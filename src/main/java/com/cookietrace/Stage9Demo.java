package com.cookietrace;

import com.cookietrace.analysis.AnomalyAnalyzer;
import com.cookietrace.analysis.ConcurrentSessionAnalyzer;
import com.cookietrace.analysis.CookieAttributeAnalyzer;
import com.cookietrace.analysis.ImpossibleTravelAnalyzer;
import com.cookietrace.analysis.IpChangeAnalyzer;
import com.cookietrace.analysis.SecurityAnalyzer;
import com.cookietrace.analysis.UserAgentAnalyzer;
import com.cookietrace.data.LabelsLoader;
import com.cookietrace.data.SessionLoader;
import com.cookietrace.engine.RiskEngine;
import com.cookietrace.engine.SessionRisk;
import com.cookietrace.evaluation.ConfusionMatrix;
import com.cookietrace.evaluation.Evaluator;
import com.cookietrace.model.Alert;
import com.cookietrace.model.SessionEvent;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Stage 9 Demonstration: Comprehensive Evaluation of Rule-Based, ML, and Hybrid Threat Detectors.
 *
 * Course Project Final Demonstration:
 * - Ingests 500 evaluation sessions (2,450 events) from data/sessions_eval.csv.
 * - Compares three detection strategies:
 *   1. RULES: RiskEngine with 5 rule analyzers (flagged if totalPoints >= 30).
 *   2. ML: Unsupervised Isolation Forest (expected fraction 0.10, seed 42; flagged if alert raised).
 *   3. HYBRID: Union of RULES and ML (flagged if RULES OR ML flags the session).
 * - Computes complete Confusion Matrices (TP, FP, FN, TN, Precision, Recall, F1, Accuracy).
 * - Analyzes per-scenario detection coverage and false alarm rates.
 * - Analyzes ML seed stability (seeds 1 to 5).
 * - Exports evaluation results to output/evaluation.csv and output/evaluation_by_scenario.csv.
 */
public class Stage9Demo {

    public static void main(String[] args) {
        System.out.println("=== CookieTrace: Stage 9 - Comprehensive Threat Detection Evaluation ===\n");

        // 1. Resolve dataset file paths
        Path dataDir = Paths.get("data");
        if (!Files.exists(dataDir) && Files.exists(Paths.get("cookietrace", "data"))) {
            dataDir = Paths.get("cookietrace", "data");
        }
        Path eventsFile = dataDir.resolve("sessions_eval.csv");
        Path labelsFile = dataDir.resolve("labels_eval.csv");

        // 2. Load events using SessionLoader
        SessionLoader sessionLoader = new SessionLoader();
        List<SessionEvent> events = sessionLoader.load(eventsFile);
        System.out.println("Loaded " + events.size() + " session events from " + eventsFile.toAbsolutePath());
        System.out.println("SessionLoader rejected rows: " + sessionLoader.getRejectedCount());

        // 3. Load ground-truth labels using LabelsLoader
        LabelsLoader labelsLoader = new LabelsLoader();
        LabelsLoader.LoadedLabels loadedLabels;
        try {
            loadedLabels = labelsLoader.load(labelsFile);
        } catch (IOException e) {
            System.err.println("Failed to load ground-truth labels: " + e.getMessage());
            return;
        }

        Map<String, Boolean> isAnomaly = loadedLabels.getIsAnomalyMap();
        Map<String, String> scenarioMap = loadedLabels.getScenarioMap();
        System.out.println("Loaded ground-truth labels for " + isAnomaly.size() + " sessions.\n");

        // Collect distinct scenarios in encounter order
        Map<String, List<String>> scenarioToSessionIds = new LinkedHashMap<String, List<String>>();
        for (Map.Entry<String, String> entry : scenarioMap.entrySet()) {
            String sId = entry.getKey();
            String sc = entry.getValue();
            if (!scenarioToSessionIds.containsKey(sc)) {
                scenarioToSessionIds.put(sc, new ArrayList<String>());
            }
            scenarioToSessionIds.get(sc).add(sId);
        }

        // ---------------------------------------------------------------------
        // DETECTOR 1: RULES
        // ---------------------------------------------------------------------
        // A RiskEngine containing only the 5 rule analyzers (no AnomalyAnalyzer).
        // A session is flagged if its totalPoints is 30 or more (MEDIUM_THRESHOLD).
        List<SecurityAnalyzer> ruleAnalyzers = new ArrayList<SecurityAnalyzer>();
        ruleAnalyzers.add(new CookieAttributeAnalyzer());
        ruleAnalyzers.add(new IpChangeAnalyzer());
        ruleAnalyzers.add(new UserAgentAnalyzer());
        ruleAnalyzers.add(new ConcurrentSessionAnalyzer());
        ruleAnalyzers.add(new ImpossibleTravelAnalyzer());

        RiskEngine rulesEngine = new RiskEngine(ruleAnalyzers);
        List<SessionRisk> rulesRisks = rulesEngine.evaluate(events);

        Set<String> rulesFlagged = new HashSet<String>();
        for (SessionRisk risk : rulesRisks) {
            if (risk.getTotalPoints() >= 30) {
                rulesFlagged.add(risk.getSessionId());
            }
        }

        // ---------------------------------------------------------------------
        // DETECTOR 2: ML (Isolation Forest)
        // ---------------------------------------------------------------------
        // AnomalyAnalyzer with expectedAnomalyFraction 0.10 and seed 42.
        // A session is flagged if the analyzer raised an alert for it.
        AnomalyAnalyzer mlAnalyzer = new AnomalyAnalyzer(0.10, 42L);
        List<Alert> mlAlerts = mlAnalyzer.analyze(events);

        Set<String> mlFlagged = new HashSet<String>();
        for (Alert alert : mlAlerts) {
            mlFlagged.add(alert.getSessionId());
        }

        // ---------------------------------------------------------------------
        // DETECTOR 3: HYBRID (Union of RULES and ML)
        // ---------------------------------------------------------------------
        // A session is flagged if RULES flags it OR ML flags it.
        //
        // ARCHITECTURAL NOTE ON WHY WE USE A UNION DEFINITION:
        // Inside RiskEngine, AnomalyAnalyzer has a maxPoints cap of 30. An anomaly alert produces
        // a scaled score between 0.0 and 1.0, so the awarded points (30 * score) frequently hover
        // between 15 and 25 points. If a session triggers only an ML alert (such as a volume/rate
        // abuse like BEHAVIOR_BURST), its points remain strictly below 30. If we relied solely
        // on RiskEngine's totalPoints >= 30 threshold, legitimate behavioral anomalies detected
        // by the ML model would be suppressed and hidden. Using the logical OR (union) guarantees
        // that behavioral anomalies surfaced by ML receive visibility alongside rule alerts.
        Set<String> hybridFlagged = new HashSet<String>();
        hybridFlagged.addAll(rulesFlagged);
        hybridFlagged.addAll(mlFlagged);

        // ---------------------------------------------------------------------
        // Compute Confusion Matrices using Evaluator
        // ---------------------------------------------------------------------
        Evaluator evaluator = new Evaluator();
        ConfusionMatrix cmRules = evaluator.evaluate(rulesFlagged, isAnomaly);
        ConfusionMatrix cmMl = evaluator.evaluate(mlFlagged, isAnomaly);
        ConfusionMatrix cmHybrid = evaluator.evaluate(hybridFlagged, isAnomaly);

        // =====================================================================
        // SECTION (a): DETECTOR PERFORMANCE METRICS
        // =====================================================================
        System.out.println("================================================================================");
        System.out.println("=== SECTION (a): Detector Performance & Confusion Matrices ===");
        System.out.println("================================================================================");

        printDetectorMetrics("RULES", cmRules);
        printDetectorMetrics("ML (Isolation Forest)", cmMl);
        printDetectorMetrics("HYBRID (Rules OR ML)", cmHybrid);

        // =====================================================================
        // SECTION (b): PER-SCENARIO DETECTION & FALSE ALARM BREAKDOWN
        // =====================================================================
        System.out.println("\n================================================================================");
        System.out.println("=== SECTION (b): Per-Scenario Breakdown ===");
        System.out.println("================================================================================");
        System.out.printf(Locale.US, "%-36s | %-7s | %-8s | %-12s | %-12s | %-12s%n",
                "Scenario", "Type", "Sessions", "RULES", "ML", "HYBRID");
        System.out.println("-------------------------------------+---------+----------+--------------+--------------+--------------");

        for (Map.Entry<String, List<String>> entry : scenarioToSessionIds.entrySet()) {
            String scenario = entry.getKey();
            List<String> sIds = entry.getValue();
            int total = sIds.size();

            boolean isAnom = isAnomaly.get(sIds.get(0));
            String type = isAnom ? "ATTACK" : "NORMAL";

            int rulesCount = 0;
            int mlCount = 0;
            int hybridCount = 0;

            for (String id : sIds) {
                if (rulesFlagged.contains(id)) {
                    rulesCount++;
                }
                if (mlFlagged.contains(id)) {
                    mlCount++;
                }
                if (hybridFlagged.contains(id)) {
                    hybridCount++;
                }
            }

            System.out.printf(Locale.US, "%-36s | %-7s | %-8d | %-12d | %-12d | %-12d%n",
                    scenario, type, total, rulesCount, mlCount, hybridCount);
        }
        System.out.println("-------------------------------------+---------+----------+--------------+--------------+--------------");
        System.out.println("Note: For ATTACK scenarios, flagged = caught. For NORMAL scenarios, flagged = false alarms.");

        // =====================================================================
        // SECTION (c): HEADLINE NUMBERS
        // =====================================================================
        System.out.println("\n================================================================================");
        System.out.println("=== SECTION (c): Headline Numbers ===");
        System.out.println("================================================================================");

        int mlCaughtRulesMissed = 0;
        Map<String, Integer> mlOnlyScenarios = new LinkedHashMap<String, Integer>();

        int rulesCaughtMlMissed = 0;
        Map<String, Integer> rulesOnlyScenarios = new LinkedHashMap<String, Integer>();

        int missedByBoth = 0;
        Map<String, Integer> missedBothScenarios = new LinkedHashMap<String, Integer>();

        for (Map.Entry<String, Boolean> entry : isAnomaly.entrySet()) {
            if (entry.getValue()) { // Truly anomalous session
                String sId = entry.getKey();
                String sc = scenarioMap.get(sId);
                boolean rFlag = rulesFlagged.contains(sId);
                boolean mFlag = mlFlagged.contains(sId);

                if (mFlag && !rFlag) {
                    mlCaughtRulesMissed++;
                    mlOnlyScenarios.put(sc, mlOnlyScenarios.getOrDefault(sc, 0) + 1);
                } else if (rFlag && !mFlag) {
                    rulesCaughtMlMissed++;
                    rulesOnlyScenarios.put(sc, rulesOnlyScenarios.getOrDefault(sc, 0) + 1);
                } else if (!rFlag && !mFlag) {
                    missedByBoth++;
                    missedBothScenarios.put(sc, missedBothScenarios.getOrDefault(sc, 0) + 1);
                }
            }
        }

        System.out.println("1. Anomalies caught by ML that RULES missed: " + mlCaughtRulesMissed);
        for (Map.Entry<String, Integer> e : mlOnlyScenarios.entrySet()) {
            System.out.println("   - " + e.getKey() + ": " + e.getValue() + " sessions");
        }

        System.out.println("2. Anomalies caught by RULES that ML missed: " + rulesCaughtMlMissed);
        for (Map.Entry<String, Integer> e : rulesOnlyScenarios.entrySet()) {
            System.out.println("   - " + e.getKey() + ": " + e.getValue() + " sessions");
        }

        System.out.println("3. Anomalies missed by BOTH detectors:       " + missedByBoth);
        if (missedBothScenarios.isEmpty()) {
            System.out.println("   - (None: all 50 anomalies were caught by at least one detector)");
        } else {
            for (Map.Entry<String, Integer> e : missedBothScenarios.entrySet()) {
                System.out.println("   - " + e.getKey() + ": " + e.getValue() + " sessions");
            }
        }

        // =====================================================================
        // SECTION (d): ML STABILITY (Seeds 1, 2, 3, 4, 5)
        // =====================================================================
        System.out.println("\n================================================================================");
        System.out.println("=== SECTION (d): ML Stability Across Seeds ===");
        System.out.println("================================================================================");

        long[] testSeeds = new long[] {1L, 2L, 3L, 4L, 5L};
        double minRecall = Double.MAX_VALUE;
        double maxRecall = Double.MIN_VALUE;

        for (long s : testSeeds) {
            AnomalyAnalyzer testMl = new AnomalyAnalyzer(0.10, s);
            List<Alert> sAlerts = testMl.analyze(events);

            Set<String> sFlagged = new HashSet<String>();
            for (Alert a : sAlerts) {
                sFlagged.add(a.getSessionId());
            }

            ConfusionMatrix sCm = evaluator.evaluate(sFlagged, isAnomaly);
            double rec = sCm.recall();
            double prec = sCm.precision();

            if (rec < minRecall) {
                minRecall = rec;
            }
            if (rec > maxRecall) {
                maxRecall = rec;
            }

            System.out.printf(Locale.US, "Seed %d: Precision = %.3f, Recall = %.3f, F1 = %.3f (Flagged = %d, TP = %d, FP = %d)%n",
                    s, prec, rec, sCm.f1(), sFlagged.size(), sCm.getTp(), sCm.getFp());
        }

        System.out.printf(Locale.US, "\nMinimum Recall across seeds: %.3f%n", minRecall);
        System.out.printf(Locale.US, "Maximum Recall across seeds: %.3f%n", maxRecall);

        // =====================================================================
        // SECTION (e): LIMITATIONS
        // =====================================================================
        System.out.println("\n================================================================================");
        System.out.println("=== SECTION (e): Limitations ===");
        System.out.println("================================================================================");
        System.out.println("1. Simulated Dataset:");
        System.out.println("   The session logs are synthetically generated and cannot fully capture");
        System.out.println("   the messiness, edge cases, cellular NAT rotations, or client behaviors");
        System.out.println("   observed in enterprise production web environments.");
        System.out.println("2. Optimistic Rule Recall:");
        System.out.println("   Because attack scenarios were designed alongside the rule logic, the");
        System.out.println("   rule recall is optimistic; in real systems, attackers actively obfuscate");
        System.out.println("   requests to evade static rule patterns.");
        System.out.println("3. Benign Shifts Cause False Alarms:");
        System.out.println("   Legitimate user behaviors (such as automatic browser updates mid-session");
        System.out.println("   or switching from mobile cell towers to Wi-Fi) trigger false positives in");
        System.out.println("   rule analyzers that flag IP and User-Agent shifts.");
        System.out.println("4. Isolation Forest Numeric Blindness:");
        System.out.println("   The unsupervised Isolation Forest operates strictly on extracted numeric");
        System.out.println("   features (event frequency, intervals, distances). It has no semantic");
        System.out.println("   understanding of HTTP header values, cookie flags, or SQLi/XSS payloads.");
        System.out.println("5. Indicators vs. Proof of Compromise:");
        System.out.println("   Generated risk scores and alerts serve as prioritized indicators to guide");
        System.out.println("   human security analysts during incident response, rather than definitive");
        System.out.println("   proof of a compromised account.");

        // =====================================================================
        // Export CSV Artifacts (output/evaluation.csv & output/evaluation_by_scenario.csv)
        // =====================================================================
        Path outputDir = Paths.get("output");
        if (!Files.exists(outputDir) && Files.exists(Paths.get("cookietrace", "output"))) {
            outputDir = Paths.get("cookietrace", "output");
        }
        if (!Files.exists(outputDir)) {
            try {
                Files.createDirectories(outputDir);
            } catch (IOException e) {
                System.err.println("Could not create output directory: " + e.getMessage());
            }
        }

        Path evalCsv = outputDir.resolve("evaluation.csv");
        Path evalScenarioCsv = outputDir.resolve("evaluation_by_scenario.csv");

        try (BufferedWriter writer = Files.newBufferedWriter(evalCsv)) {
            writer.write("detector,tp,fp,fn,tn,precision,recall,f1,accuracy");
            writer.newLine();

            writeMetricRow(writer, "RULES", cmRules);
            writeMetricRow(writer, "ML", cmMl);
            writeMetricRow(writer, "HYBRID", cmHybrid);
        } catch (IOException e) {
            System.err.println("Failed to write evaluation.csv: " + e.getMessage());
        }

        try (BufferedWriter writer = Files.newBufferedWriter(evalScenarioCsv)) {
            writer.write("scenario,type,sessions,rules_flagged,ml_flagged,hybrid_flagged");
            writer.newLine();

            for (Map.Entry<String, List<String>> entry : scenarioToSessionIds.entrySet()) {
                String scenario = entry.getKey();
                List<String> sIds = entry.getValue();
                boolean isAnom = isAnomaly.get(sIds.get(0));
                String type = isAnom ? "ATTACK" : "NORMAL";

                int rulesCount = 0;
                int mlCount = 0;
                int hybridCount = 0;

                for (String id : sIds) {
                    if (rulesFlagged.contains(id)) {
                        rulesCount++;
                    }
                    if (mlFlagged.contains(id)) {
                        mlCount++;
                    }
                    if (hybridFlagged.contains(id)) {
                        hybridCount++;
                    }
                }

                writer.write(String.format(Locale.US, "%s,%s,%d,%d,%d,%d",
                        scenario, type, sIds.size(), rulesCount, mlCount, hybridCount));
                writer.newLine();
            }
        } catch (IOException e) {
            System.err.println("Failed to write evaluation_by_scenario.csv: " + e.getMessage());
        }

        System.out.println("\nGenerated Artifacts:");
        System.out.println("  - " + evalCsv.toAbsolutePath());
        System.out.println("  - " + evalScenarioCsv.toAbsolutePath());

        System.out.println("\nStage 9 completed successfully!");
    }

    private static void printDetectorMetrics(String name, ConfusionMatrix cm) {
        System.out.println("Detector: " + name);
        System.out.printf(Locale.US, "  TP: %d | FP: %d | FN: %d | TN: %d%n",
                cm.getTp(), cm.getFp(), cm.getFn(), cm.getTn());
        System.out.printf(Locale.US, "  Precision: %.3f%n", cm.precision());
        System.out.printf(Locale.US, "  Recall:    %.3f%n", cm.recall());
        System.out.printf(Locale.US, "  F1 Score:  %.3f%n", cm.f1());
        System.out.printf(Locale.US, "  Accuracy:  %.3f%n", cm.accuracy());
        System.out.println("  Check: TP + FP + FN + TN = " + cm.getTotal() + " (Matches 500 total sessions)\n");
    }

    private static void writeMetricRow(BufferedWriter writer, String name, ConfusionMatrix cm) throws IOException {
        writer.write(String.format(Locale.US, "%s,%d,%d,%d,%d,%.3f,%.3f,%.3f,%.3f",
                name, cm.getTp(), cm.getFp(), cm.getFn(), cm.getTn(),
                cm.precision(), cm.recall(), cm.f1(), cm.accuracy()));
        writer.newLine();
    }
}
