package com.cookietrace;

import com.cookietrace.analysis.ConcurrentSessionAnalyzer;
import com.cookietrace.analysis.CookieAttributeAnalyzer;
import com.cookietrace.analysis.ImpossibleTravelAnalyzer;
import com.cookietrace.analysis.IpChangeAnalyzer;
import com.cookietrace.analysis.SecurityAnalyzer;
import com.cookietrace.analysis.UserAgentAnalyzer;
import com.cookietrace.data.SessionLoader;
import com.cookietrace.model.Alert;
import com.cookietrace.model.SessionEvent;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Stage 3B Demonstration: Comprehensive Threat Analysis & Ground-Truth Verification.
 *
 * Demonstrates:
 * 1. Abstraction: All 5 analyzers share the SecurityAnalyzer abstract base class.
 * 2. Polymorphism: Iterating over a List<SecurityAnalyzer> dispatches to each specific
 *    detection algorithm dynamically at runtime.
 * 3. Validation: Comparing detection alerts against ground-truth labels from Stage 1,
 *    verifying that all attacks are caught and zero normal sessions are falsely flagged.
 */
public class Stage3Demo {

    /**
     * Helper record/class to hold ground truth labels from labels_dev.csv.
     */
    private static class SessionLabelRecord {
        String sessionId;
        boolean isAnomaly;
        String scenario;

        SessionLabelRecord(String sessionId, boolean isAnomaly, String scenario) {
            this.sessionId = sessionId;
            this.isAnomaly = isAnomaly;
            this.scenario = scenario;
        }
    }

    public static void main(String[] args) {
        System.out.println("=== CookieTrace: Stage 3B - Multi-Analyzer Threat Detection & Evaluation ===\n");

        // Locate sessions_dev.csv and labels_dev.csv
        Path eventsPath = Paths.get("data", "sessions_dev.csv");
        if (!Files.exists(eventsPath)) {
            eventsPath = Paths.get("cookietrace", "data", "sessions_dev.csv");
        }

        Path labelsPath = Paths.get("data", "labels_dev.csv");
        if (!Files.exists(labelsPath)) {
            labelsPath = Paths.get("cookietrace", "data", "labels_dev.csv");
        }

        // 1. Load session events using SessionLoader
        SessionLoader loader = new SessionLoader();
        List<SessionEvent> events = loader.load(eventsPath);
        System.out.println("Loaded " + events.size() + " session events from " + eventsPath + ".\n");

        // 2. Create the full suite of 5 security analyzers (Total max points = 150)
        List<SecurityAnalyzer> analyzers = new ArrayList<SecurityAnalyzer>();
        analyzers.add(new CookieAttributeAnalyzer());       // Max points: 30
        analyzers.add(new IpChangeAnalyzer());              // Max points: 25
        analyzers.add(new UserAgentAnalyzer());             // Max points: 20
        analyzers.add(new ConcurrentSessionAnalyzer());     // Max points: 35
        analyzers.add(new ImpossibleTravelAnalyzer());      // Max points: 40

        // Map to track which analyzers flagged which session: sessionId -> List of analyzer names
        Map<String, List<String>> flaggedBySession = new LinkedHashMap<String, List<String>>();

        // -------------------------------------------------------------
        // OOP Concept - Polymorphism:
        // Each analyzer in the list is referenced as the base abstract class
        // 'SecurityAnalyzer'. Java dynamically dispatches the .analyze() call
        // to the correct subclass at runtime.
        // -------------------------------------------------------------
        System.out.println("=== Individual Analyzer Results ===");
        for (SecurityAnalyzer analyzer : analyzers) {
            System.out.println("--------------------------------------------------------------------------------");
            System.out.println("Analyzer: " + analyzer.getName() + " (Max Points: " + analyzer.getMaxPoints() + ")");

            List<Alert> alerts = analyzer.analyze(events);
            System.out.println("Number of alerts: " + alerts.size());
            System.out.println("Alerts (sessionId | points | level | explanation):");

            for (Alert alert : alerts) {
                System.out.println(
                        alert.getSessionId() + " | " +
                        alert.getPoints() + " | " +
                        alert.getLevel() + " | " +
                        alert.getExplanation()
                );

                // Record which analyzer flagged this session
                String sId = alert.getSessionId();
                if (!flaggedBySession.containsKey(sId)) {
                    flaggedBySession.put(sId, new ArrayList<String>());
                }
                flaggedBySession.get(sId).add(analyzer.getName());
            }
            System.out.println();
        }

        // -------------------------------------------------------------
        // 3. Load labels_dev.csv and evaluate detection performance
        // -------------------------------------------------------------
        List<SessionLabelRecord> labels = new ArrayList<SessionLabelRecord>();
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
                        labels.add(new SessionLabelRecord(sId, isAnomaly, scenario));
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading labels file: " + labelsPath + " (" + e.getMessage() + ")");
        }

        // -------------------------------------------------------------
        // 4. Print Summary Table for Anomalous Sessions
        // -------------------------------------------------------------
        System.out.println("================================================================================");
        System.out.println("=== Threat Detection vs Ground Truth Summary ===");
        System.out.println("================================================================================");
        System.out.printf("%-12s | %-24s | %s%n", "Session ID", "Ground Truth Scenario", "Flagged By Analyzers");
        System.out.println("--------------------------------------------------------------------------------");

        int normalSessionsFlagged = 0;

        for (SessionLabelRecord record : labels) {
            if (record.isAnomaly) {
                List<String> analyzerList = flaggedBySession.get(record.sessionId);
                StringBuilder sb = new StringBuilder();
                if (analyzerList != null && !analyzerList.isEmpty()) {
                    for (int i = 0; i < analyzerList.size(); i++) {
                        if (i > 0) {
                            sb.append(", ");
                        }
                        sb.append(analyzerList.get(i));
                    }
                } else {
                    sb.append("[MISSED]");
                }
                System.out.printf("%-12s | %-24s | %s%n", record.sessionId, record.scenario, sb.toString());
            } else {
                // Check if any normal session was mistakenly flagged (false positive)
                if (flaggedBySession.containsKey(record.sessionId) &&
                        !flaggedBySession.get(record.sessionId).isEmpty()) {
                    normalSessionsFlagged++;
                }
            }
        }

        System.out.println("--------------------------------------------------------------------------------");
        System.out.println("Normal sessions flagged: " + normalSessionsFlagged);
        System.out.println("================================================================================");
        System.out.println("Stage 3B completed successfully!");
    }
}
