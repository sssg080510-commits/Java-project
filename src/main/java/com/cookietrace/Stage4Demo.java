package com.cookietrace;

import com.cookietrace.analysis.AnomalyAnalyzer;
import com.cookietrace.data.SessionLoader;
import com.cookietrace.model.Alert;
import com.cookietrace.model.SessionEvent;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Stage 4 Demonstration: Machine Learning Anomaly Detection with Isolation Forest.
 *
 * Demonstrates:
 * 1. Feature extraction across 9 temporal, geographic, network, and cookie dimensions.
 * 2. Unsupervised anomaly scoring using Smile's Isolation Forest algorithm.
 * 3. Transparent statistical explanations via feature z-scores.
 * 4. Comparison of anomaly detector performance against ground-truth labels.
 */
public class Stage4Demo {

    public static void main(String[] args) {
        System.out.println("=== CookieTrace: Stage 4 - Isolation Forest Anomaly Detection Demo ===\n");

        // Locate data files
        Path eventsPath = Paths.get("data", "sessions_dev.csv");
        if (!Files.exists(eventsPath)) {
            eventsPath = Paths.get("cookietrace", "data", "sessions_dev.csv");
        }

        Path labelsPath = Paths.get("data", "labels_dev.csv");
        if (!Files.exists(labelsPath)) {
            labelsPath = Paths.get("cookietrace", "data", "labels_dev.csv");
        }

        // 1. Load session events
        SessionLoader loader = new SessionLoader();
        List<SessionEvent> events = loader.load(eventsPath);
        System.out.println("Loaded " + events.size() + " session events from " + eventsPath + ".");

        // 2. Load ground-truth labels
        Map<String, String> scenarioMap = new HashMap<String, String>();
        Map<String, Boolean> isAnomalyMap = new HashMap<String, Boolean>();

        try (BufferedReader reader = Files.newBufferedReader(labelsPath)) {
            String line = reader.readLine(); // Skip header
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) {
                    String[] parts = line.split(",");
                    if (parts.length >= 3) {
                        String sId = parts[0].trim();
                        boolean isAnomaly = Boolean.parseBoolean(parts[1].trim());
                        String scenario = parts[2].trim();
                        scenarioMap.put(sId, scenario);
                        isAnomalyMap.put(sId, isAnomaly);
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading labels file: " + labelsPath + " (" + e.getMessage() + ")");
        }

        // 3. Run AnomalyAnalyzer with expectedAnomalyFraction 0.20
        // The dev data has 4 attack sessions out of 20 (20%); the full 500-session run will use 0.10
        AnomalyAnalyzer analyzer = new AnomalyAnalyzer(0.20);
        List<Alert> alerts = analyzer.analyze(events);
        Map<String, Double> scoreMap = analyzer.getLastScores();

        // Track flagged sessions
        Set<String> flaggedSessions = new HashSet<String>();
        for (Alert alert : alerts) {
            flaggedSessions.add(alert.getSessionId());
        }

        // 4. Sort sessions by anomaly score descending
        List<String> sortedSessions = new ArrayList<String>(scoreMap.keySet());
        Collections.sort(sortedSessions, new Comparator<String>() {
            @Override
            public int compare(String s1, String s2) {
                return Double.compare(scoreMap.get(s2), scoreMap.get(s1));
            }
        });

        // 5. Print Score Table
        System.out.println("\n================================================================================");
        System.out.println("=== Anomaly Score Ranking (Sorted Descending) ===");
        System.out.println("================================================================================");
        System.out.printf("%-12s | %-8s | %-14s | %s%n", "Session ID", "Score", "Flagged Yes/No", "True Label");
        System.out.println("--------------------------------------------------------------------------------");

        for (String sId : sortedSessions) {
            double score = scoreMap.get(sId);
            boolean flagged = flaggedSessions.contains(sId);
            String label = scenarioMap.getOrDefault(sId, "UNKNOWN");

            System.out.printf("%-12s | %-8.3f | %-14s | %s%n",
                    sId,
                    score,
                    (flagged ? "YES" : "NO"),
                    label
            );
        }
        System.out.println("================================================================================");

        // 6. Print Alert Explanations
        System.out.println("\n=== Generated Anomaly Alerts ===");
        if (alerts.isEmpty()) {
            System.out.println("No sessions flagged as anomalies.");
        } else {
            for (Alert alert : alerts) {
                System.out.println("--------------------------------------------------------------------------------");
                System.out.println("Session ID:      " + alert.getSessionId());
                System.out.println("Analyzer:        " + alert.getAnalyzerName());
                System.out.println("Risk Score:      " + alert.getPoints() + "/30 (" + alert.getLevel() + ")");
                System.out.println("Explanation:     " + alert.getExplanation());
                System.out.println("Recommendation:  " + alert.getRecommendation());
            }
            System.out.println("--------------------------------------------------------------------------------");
        }

        // 7. Calculate and print performance metrics
        int attackSessionsCaught = 0;
        int normalSessionsFlagged = 0;

        for (String sId : flaggedSessions) {
            if (Boolean.TRUE.equals(isAnomalyMap.get(sId))) {
                attackSessionsCaught++;
            } else {
                normalSessionsFlagged++;
            }
        }

        System.out.println("\nDetection Metrics:");
        System.out.println("Attack sessions caught: " + attackSessionsCaught + " of 4");
        System.out.println("Normal sessions flagged: " + normalSessionsFlagged);
        System.out.println("\nStage 4 completed successfully!");
    }
}
