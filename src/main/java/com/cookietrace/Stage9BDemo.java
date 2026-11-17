package com.cookietrace;

import com.cookietrace.analysis.ConcurrentSessionAnalyzer;
import com.cookietrace.analysis.CookieAttributeAnalyzer;
import com.cookietrace.analysis.ImpossibleTravelAnalyzer;
import com.cookietrace.analysis.IpChangeAnalyzer;
import com.cookietrace.analysis.SecurityAnalyzer;
import com.cookietrace.analysis.UserAgentAnalyzer;
import com.cookietrace.data.EvaluationDataGenerator;
import com.cookietrace.data.SessionLoader;
import com.cookietrace.model.Alert;
import com.cookietrace.model.SessionEvent;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Stage 9B Demonstration: Benchmark Dataset Generation and Rule Analyzer Coverage.
 *
 * Demonstrates:
 * 1. Deterministic generation of 500 evaluation sessions across 7 days using seed 2026.
 *    (Same seed must give identical files across every run).
 * 2. Strict dataset validation with SessionLoader (0 rejected rows).
 * 3. Evaluation of the 5 rule-based analyzers against all 8 scenarios,
 *    highlighting rule coverage and uncovering blind spots (such as BEHAVIOR_BURST).
 */
public class Stage9BDemo {

    public static void main(String[] args) {
        System.out.println("=== CookieTrace: Stage 9B - Evaluation Dataset Generation & Rule Analysis Demo ===\n");

        // 1. Resolve output file paths (data/sessions_eval.csv and data/labels_eval.csv)
        Path dataDir = Paths.get("data");
        if (!Files.exists(dataDir) && Files.exists(Paths.get("cookietrace", "data"))) {
            dataDir = Paths.get("cookietrace", "data");
        }
        Path eventsFile = dataDir.resolve("sessions_eval.csv");
        Path labelsFile = dataDir.resolve("labels_eval.csv");

        // Determinism note: Using seed 2026 ensures repeatable, byte-for-byte identical dataset files across runs.
        long seed = 2026L;
        EvaluationDataGenerator generator = new EvaluationDataGenerator();

        try {
            System.out.println("Generating evaluation dataset with seed " + seed + "...");
            generator.generate(seed, eventsFile, labelsFile);
            System.out.println("Generated files:");
            System.out.println("  - Events: " + eventsFile.toAbsolutePath());
            System.out.println("  - Labels: " + labelsFile.toAbsolutePath());
        } catch (IOException e) {
            System.err.println("Failed to generate evaluation data: " + e.getMessage());
            return;
        }

        // 2. Read and parse labels_eval.csv for ground-truth statistics
        Map<String, String> sessionToScenario = new LinkedHashMap<String, String>();
        Map<String, Boolean> sessionToAnomaly = new LinkedHashMap<String, Boolean>();
        Map<String, Integer> scenarioCounts = new LinkedHashMap<String, Integer>();

        try (BufferedReader reader = Files.newBufferedReader(labelsFile)) {
            String header = reader.readLine(); // skip header: session_id,is_anomaly,scenario
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                String[] parts = trimmed.split(",");
                if (parts.length >= 3) {
                    String sessionId = parts[0].trim();
                    boolean isAnomaly = Boolean.parseBoolean(parts[1].trim());
                    String scenario = parts[2].trim();

                    sessionToScenario.put(sessionId, scenario);
                    sessionToAnomaly.put(sessionId, isAnomaly);
                    scenarioCounts.put(scenario, scenarioCounts.getOrDefault(scenario, 0) + 1);
                }
            }
        } catch (IOException e) {
            System.err.println("Failed to read labels file: " + e.getMessage());
            return;
        }

        // 3. Count total event rows in sessions_eval.csv
        int eventRowCount = 0;
        try (BufferedReader reader = Files.newBufferedReader(eventsFile)) {
            reader.readLine(); // skip header
            while (reader.readLine() != null) {
                eventRowCount++;
            }
        } catch (IOException e) {
            System.err.println("Failed to count events: " + e.getMessage());
            return;
        }

        int totalSessions = sessionToScenario.size();
        int anomalousCount = 0;
        for (boolean isAnomaly : sessionToAnomaly.values()) {
            if (isAnomaly) {
                anomalousCount++;
            }
        }

        System.out.println("\n=== Dataset Summary ===");
        System.out.println("Number of event rows:       " + eventRowCount);
        System.out.println("Number of sessions:         " + totalSessions);
        System.out.println("Number of anomalous sessions: " + anomalousCount + " (expected 50)");

        System.out.println("\n=== Scenario Distribution ===");
        System.out.println("------------------------------------+--------------");
        System.out.printf("%-35s | %s%n", "Scenario", "Session Count");
        System.out.println("------------------------------------+--------------");
        for (Map.Entry<String, Integer> entry : scenarioCounts.entrySet()) {
            System.out.printf("%-35s | %d%n", entry.getKey(), entry.getValue());
        }
        System.out.println("------------------------------------+--------------");

        // 4. Load the generated CSV using SessionLoader
        System.out.println("\n=== Loading Dataset with SessionLoader ===");
        SessionLoader loader = new SessionLoader();
        List<SessionEvent> loadedEvents = loader.load(eventsFile);
        System.out.println("Loaded event records:       " + loadedEvents.size());
        System.out.println("Rejected count:             " + loader.getRejectedCount() + " (expected 0)");

        // 5. Run the FIVE RULE analyzers (excluding AnomalyAnalyzer)
        List<SecurityAnalyzer> ruleAnalyzers = new ArrayList<SecurityAnalyzer>();
        ruleAnalyzers.add(new CookieAttributeAnalyzer());
        ruleAnalyzers.add(new IpChangeAnalyzer());
        ruleAnalyzers.add(new UserAgentAnalyzer());
        ruleAnalyzers.add(new ConcurrentSessionAnalyzer());
        ruleAnalyzers.add(new ImpossibleTravelAnalyzer());

        Set<String> sessionsWithRuleAlert = new HashSet<String>();
        for (SecurityAnalyzer analyzer : ruleAnalyzers) {
            List<Alert> alerts = analyzer.analyze(loadedEvents);
            for (Alert alert : alerts) {
                sessionsWithRuleAlert.add(alert.getSessionId());
            }
        }

        // 6. Print how many sessions in each scenario got at least one rule alert ("scenario: X of N")
        System.out.println("\n=== Rule Analyzers Coverage (Sessions with at least 1 rule alert) ===");
        for (String scenario : scenarioCounts.keySet()) {
            int totalInScenario = scenarioCounts.get(scenario);
            int alertedInScenario = 0;

            for (Map.Entry<String, String> entry : sessionToScenario.entrySet()) {
                if (entry.getValue().equals(scenario)) {
                    if (sessionsWithRuleAlert.contains(entry.getKey())) {
                        alertedInScenario++;
                    }
                }
            }
            System.out.println(scenario + ": " + alertedInScenario + " of " + totalInScenario);
        }

        System.out.println("\nStage 9B completed successfully!");
    }
}
