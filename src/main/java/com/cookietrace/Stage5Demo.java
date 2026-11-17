package com.cookietrace;

import com.cookietrace.analysis.AnomalyAnalyzer;
import com.cookietrace.analysis.ConcurrentSessionAnalyzer;
import com.cookietrace.analysis.CookieAttributeAnalyzer;
import com.cookietrace.analysis.ImpossibleTravelAnalyzer;
import com.cookietrace.analysis.IpChangeAnalyzer;
import com.cookietrace.analysis.SecurityAnalyzer;
import com.cookietrace.analysis.UserAgentAnalyzer;
import com.cookietrace.data.SessionLoader;
import com.cookietrace.engine.RiskEngine;
import com.cookietrace.engine.SessionRisk;
import com.cookietrace.model.Alert;
import com.cookietrace.model.RiskLevel;
import com.cookietrace.model.SessionEvent;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Stage 5 Demonstration: Polymorphic Risk Engine & Multi-Tier Threat Scoring.
 *
 * Demonstrates:
 * 1. Polymorphism: RiskEngine evaluates rule-based and machine learning analyzers
 *    uniformly through the abstract SecurityAnalyzer interface.
 * 2. Risk Aggregation: Consolidates alerts from multiple detectors and caps risk scores at 100.
 * 3. Extensibility (Open-Closed Principle): New analyzers are plugged in without modifying RiskEngine.
 */
public class Stage5Demo {

    public static void main(String[] args) {
        System.out.println("=== CookieTrace: Stage 5 - Polymorphic Risk Engine Demonstration ===\n");

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
        try (BufferedReader reader = Files.newBufferedReader(labelsPath)) {
            String line = reader.readLine(); // Skip header
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) {
                    String[] parts = line.split(",");
                    if (parts.length >= 3) {
                        scenarioMap.put(parts[0].trim(), parts[2].trim());
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading labels file: " + labelsPath + " (" + e.getMessage() + ")");
        }

        // 3. Build the full suite of 6 analyzers (5 rules + 1 ML AnomalyAnalyzer)
        List<SecurityAnalyzer> allAnalyzers = new ArrayList<SecurityAnalyzer>();
        allAnalyzers.add(new CookieAttributeAnalyzer());       // 30 max points
        allAnalyzers.add(new IpChangeAnalyzer());              // 25 max points
        allAnalyzers.add(new UserAgentAnalyzer());             // 20 max points
        allAnalyzers.add(new ConcurrentSessionAnalyzer());     // 35 max points
        allAnalyzers.add(new ImpossibleTravelAnalyzer());      // 40 max points
        allAnalyzers.add(new AnomalyAnalyzer(0.20));           // 30 max points (ML Isolation Forest)

        // Instantiate RiskEngine with all 6 analyzers
        RiskEngine fullEngine = new RiskEngine(allAnalyzers);

        System.out.println("\nRegistered Analyzers in RiskEngine:");
        List<String> analyzerNames = fullEngine.getAnalyzerNames();
        for (int i = 0; i < analyzerNames.size(); i++) {
            System.out.println("  " + (i + 1) + ". " + analyzerNames.get(i));
        }
        System.out.println();

        // 4. Evaluate all sessions through RiskEngine
        List<SessionRisk> risks = fullEngine.evaluate(events);

        // 5. Print Summary Table of all 20 sessions
        System.out.println("========================================================================================================================");
        System.out.println("=== Comprehensive Session Risk Table (Sorted by Total Points Descending) ===");
        System.out.println("========================================================================================================================");
        System.out.printf("%-11s | %-10s | %-11s | %-8s | %-42s | %s%n",
                "Session ID", "Raw Points", "TotalPoints", "Level", "Analyzers That Fired", "True Scenario");
        System.out.println("------------------------------------------------------------------------------------------------------------------------");

        for (SessionRisk risk : risks) {
            // Collect unique names of analyzers that fired for this session
            Set<String> firingAnalyzers = new LinkedHashSet<String>();
            for (Alert alert : risk.getAlerts()) {
                firingAnalyzers.add(alert.getAnalyzerName());
            }

            StringBuilder analyzerNamesStr = new StringBuilder();
            if (firingAnalyzers.isEmpty()) {
                analyzerNamesStr.append("[NONE]");
            } else {
                int count = 0;
                for (String name : firingAnalyzers) {
                    if (count > 0) {
                        analyzerNamesStr.append(", ");
                    }
                    analyzerNamesStr.append(name);
                    count++;
                }
            }

            String trueScenario = scenarioMap.getOrDefault(risk.getSessionId(), "UNKNOWN");

            System.out.printf("%-11s | %-10d | %-11d | %-8s | %-42s | %s%n",
                    risk.getSessionId(),
                    risk.getRawPoints(),
                    risk.getTotalPoints(),
                    risk.getLevel(),
                    analyzerNamesStr.toString(),
                    trueScenario
            );
        }
        System.out.println("========================================================================================================================");

        // 6. Print detailed breakdown for MEDIUM and HIGH severity sessions
        System.out.println("\n=== Detailed Threat Breakdown for Actionable Sessions (MEDIUM / HIGH) ===");
        for (SessionRisk risk : risks) {
            if (risk.getLevel() == RiskLevel.MEDIUM || risk.getLevel() == RiskLevel.HIGH) {
                System.out.println("--------------------------------------------------------------------------------");
                System.out.println("Session: " + risk.getSessionId() +
                        " | Risk Score: " + risk.getTotalPoints() + "/100 (" + risk.getLevel() + ")" +
                        " | Raw Points: " + risk.getRawPoints() +
                        " | Alerts Count: " + risk.getAlerts().size());

                for (Alert alert : risk.getAlerts()) {
                    System.out.println("  * [" + alert.getAnalyzerName() + "] (" + alert.getPoints() + " pts / " + alert.getLevel() + "):");
                    System.out.println("      Explanation:    " + alert.getExplanation());
                    System.out.println("      Recommendation: " + alert.getRecommendation());
                }
            }
        }
        System.out.println("--------------------------------------------------------------------------------");

        // 7. Print Risk Level Distribution Counts
        int lowCount = 0;
        int mediumCount = 0;
        int highCount = 0;

        for (SessionRisk risk : risks) {
            if (risk.getLevel() == RiskLevel.LOW) {
                lowCount++;
            } else if (risk.getLevel() == RiskLevel.MEDIUM) {
                mediumCount++;
            } else if (risk.getLevel() == RiskLevel.HIGH) {
                highCount++;
            }
        }

        System.out.println("\nRisk Level Distribution:");
        System.out.println("  LOW Sessions:    " + lowCount);
        System.out.println("  MEDIUM Sessions: " + mediumCount);
        System.out.println("  HIGH Sessions:   " + highCount);

        // 8. Highest Raw Points Comparison: Rule-Only Engine vs Full Engine
        // Find session with the highest raw points in the full evaluation
        SessionRisk highestRawSession = risks.get(0);
        for (SessionRisk r : risks) {
            if (r.getRawPoints() > highestRawSession.getRawPoints()) {
                highestRawSession = r;
            }
        }

        // Build a second RiskEngine using only the 5 rule analyzers (excluding AnomalyAnalyzer)
        List<SecurityAnalyzer> ruleOnlyAnalyzers = new ArrayList<SecurityAnalyzer>();
        ruleOnlyAnalyzers.add(new CookieAttributeAnalyzer());
        ruleOnlyAnalyzers.add(new IpChangeAnalyzer());
        ruleOnlyAnalyzers.add(new UserAgentAnalyzer());
        ruleOnlyAnalyzers.add(new ConcurrentSessionAnalyzer());
        ruleOnlyAnalyzers.add(new ImpossibleTravelAnalyzer());

        RiskEngine ruleOnlyEngine = new RiskEngine(ruleOnlyAnalyzers);
        List<SessionRisk> ruleOnlyRisks = ruleOnlyEngine.evaluate(events);

        SessionRisk highestInRuleOnly = null;
        for (SessionRisk r : ruleOnlyRisks) {
            if (r.getSessionId().equals(highestRawSession.getSessionId())) {
                highestInRuleOnly = r;
                break;
            }
        }

        System.out.println("\n================================================================================");
        System.out.println("=== Extensibility & Score Comparison for Session with Highest Raw Points ===");
        System.out.println("================================================================================");
        System.out.println("Target Session: " + highestRawSession.getSessionId() +
                " (Scenario: " + scenarioMap.get(highestRawSession.getSessionId()) + ")");
        System.out.println();
        if (highestInRuleOnly != null) {
            System.out.println("Using ONLY 5 Rule Analyzers:");
            System.out.println("  Raw Points:   " + highestInRuleOnly.getRawPoints());
            System.out.println("  Total Points: " + highestInRuleOnly.getTotalPoints() + "/100 (" + highestInRuleOnly.getLevel() + ")");
            System.out.println("  Alerts Count: " + highestInRuleOnly.getAlerts().size());
        }
        System.out.println();
        System.out.println("Using ALL 6 Analyzers (5 Rule Analyzers + AnomalyAnalyzer):");
        System.out.println("  Raw Points:   " + highestRawSession.getRawPoints() + " (Sum of alerts exceeds 100)");
        System.out.println("  Total Points: " + highestRawSession.getTotalPoints() + "/100 (" + highestRawSession.getLevel() + " - capped at MAX_SCORE)");
        System.out.println("  Alerts Count: " + highestRawSession.getAlerts().size());
        System.out.println();
        System.out.println("Viva Note on Extensibility (Open-Closed Principle):");
        System.out.println("  RiskEngine was NOT modified when AnomalyAnalyzer was added.");
        System.out.println("  Because RiskEngine operates on the abstract 'SecurityAnalyzer' base type,");
        System.out.println("  any new rule or machine learning analyzer can be plugged in dynamically");
        System.out.println("  via polymorphism without touching the core evaluation engine code.");
        System.out.println("================================================================================");
        System.out.println("\nStage 5 completed successfully!");
    }
}
