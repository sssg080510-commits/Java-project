package com.cookietrace;

import com.cookietrace.analysis.FeatureExtractor;
import com.cookietrace.data.SessionLoader;
import com.cookietrace.model.SessionEvent;
import smile.anomaly.IsolationForest;
import smile.math.MathEx;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ForkJoinPool;

/**
 * Stage 9D-2 Diagnostic: Tests whether Z-score standardising the 9 feature columns
 * before feeding them to Isolation Forest improves detection of BEHAVIOR_BURST sessions.
 *
 * Hypothesis from Stage 9D:
 *   The raw feature matrix is dominated by high-magnitude columns such as
 *   maxDistanceKm (0 to ~17,000 km) and durationSeconds (0 to ~3,500 s),
 *   while the decisive BEHAVIOR_BURST signal lives in low-magnitude columns
 *   (minGapSeconds = 1, maxGapSeconds = 3, eventCount = 43-59).
 *   Isolation Forest's random axis-selection is indifferent to scale, but
 *   the range of a column does affect how often a random split in that column
 *   manages to isolate an extreme point in another column.
 *   Standardising (z-score) puts all 9 features on the same unit scale so
 *   the forest treats each column's deviation equally.
 *
 * DIAGNOSTIC ONLY: No existing class is modified. No parameters are tuned.
 * Same Smile version 3.1.1, same Properties (trees=100, all other settings at
 * library defaults: sampling_rate=0.70, max_depth=floor(log2(500))=8,
 * extension_level=8), same flag logic (top 10% AND score > 0.5).
 */
public class Stage9D2Diagnostic {

    private static final String[] SCENARIOS = {
        "NORMAL",
        "NORMAL_BENIGN_IP_CHANGE",
        "NORMAL_BENIGN_IP_AND_BROWSER_CHANGE",
        "INSECURE_COOKIE",
        "IP_AND_BROWSER_CHANGE",
        "CONCURRENT_SESSION",
        "IMPOSSIBLE_TRAVEL",
        "BEHAVIOR_BURST"
    };

    private static final double EXPECTED_ANOMALY_FRACTION = 0.10;
    private static final double SCORE_THRESHOLD            = 0.5;   // same hard threshold as AnomalyAnalyzer

    public static void main(String[] args) {
        System.out.println("=== CookieTrace: Stage 9D-2 - Standardised Feature Diagnostic ===\n");

        // ----------------------------------------------------------------
        // 1. Load events
        // ----------------------------------------------------------------
        Path dataDir = Paths.get("data");
        if (!Files.exists(dataDir) && Files.exists(Paths.get("cookietrace", "data"))) {
            dataDir = Paths.get("cookietrace", "data");
        }
        Path eventsFile = dataDir.resolve("sessions_eval.csv");
        Path labelsFile = dataDir.resolve("labels_eval.csv");

        SessionLoader loader = new SessionLoader();
        List<SessionEvent> events = loader.load(eventsFile);
        System.out.println("Events loaded: " + events.size() + " | Rejected: " + loader.getRejectedCount());

        // ----------------------------------------------------------------
        // 2. Load ground-truth labels
        // ----------------------------------------------------------------
        Map<String, Boolean> isAnomaly = new LinkedHashMap<>();
        Map<String, String>  scenarioOf = new LinkedHashMap<>();
        try (BufferedReader r = Files.newBufferedReader(labelsFile)) {
            r.readLine();
            String line;
            while ((line = r.readLine()) != null) {
                String t = line.trim();
                if (t.isEmpty()) continue;
                String[] p = t.split(",");
                isAnomaly.put(p[0].trim(),  Boolean.parseBoolean(p[1].trim()));
                scenarioOf.put(p[0].trim(), p[2].trim());
            }
        } catch (IOException e) {
            System.err.println("Cannot read labels: " + e.getMessage());
            return;
        }

        // ----------------------------------------------------------------
        // 3. Group sessions + extract raw features (same as AnomalyAnalyzer)
        // ----------------------------------------------------------------
        Map<String, List<SessionEvent>> sessionMap = groupBySession(events);
        FeatureExtractor extractor = new FeatureExtractor();
        Map<String, double[]> featureMap = extractor.extract(sessionMap);

        List<String> sessionIds = new ArrayList<>(featureMap.keySet());
        int n = sessionIds.size();
        int p = FeatureExtractor.FEATURE_NAMES.length;

        // Raw feature matrix
        double[][] raw = new double[n][p];
        for (int i = 0; i < n; i++) raw[i] = featureMap.get(sessionIds.get(i));

        // ----------------------------------------------------------------
        // 4. Compute column means and standard deviations
        // ----------------------------------------------------------------
        double[] means   = new double[p];
        double[] stdDevs = new double[p];

        for (int j = 0; j < p; j++) {
            double sum = 0.0;
            for (int i = 0; i < n; i++) sum += raw[i][j];
            means[j] = sum / n;

            double sq = 0.0;
            for (int i = 0; i < n; i++) {
                double d = raw[i][j] - means[j];
                sq += d * d;
            }
            // Population std-dev (same formula AnomalyAnalyzer uses internally)
            stdDevs[j] = Math.sqrt(sq / n);
        }

        System.out.println("\n--- Column statistics used for standardisation ---");
        System.out.printf("%-20s %12s %12s%n", "Feature", "Mean", "StdDev");
        System.out.println("-".repeat(46));
        for (int j = 0; j < p; j++) {
            System.out.printf("%-20s %12.4f %12.4f%n",
                    FeatureExtractor.FEATURE_NAMES[j], means[j], stdDevs[j]);
        }

        // ----------------------------------------------------------------
        // 5. Build standardised feature matrix
        //    z[i][j] = (raw[i][j] - mean[j]) / stdDev[j]
        //    If stdDev[j] == 0 (all values identical) => z = 0 for that column
        // ----------------------------------------------------------------
        double[][] std = new double[n][p];
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < p; j++) {
                std[i][j] = (stdDevs[j] > 1e-9)
                        ? (raw[i][j] - means[j]) / stdDevs[j]
                        : 0.0;
            }
        }

        // ----------------------------------------------------------------
        // 6. Build scenario -> session-index lookup
        // ----------------------------------------------------------------
        Map<String, List<Integer>> scenarioIndices = new LinkedHashMap<>();
        for (String sc : SCENARIOS) scenarioIndices.put(sc, new ArrayList<>());
        for (int i = 0; i < n; i++) {
            String sc = scenarioOf.get(sessionIds.get(i));
            if (sc != null && scenarioIndices.containsKey(sc)) {
                scenarioIndices.get(sc).add(i);
            }
        }

        // ================================================================
        // === MAIN SECTION: standardised model with seed 42 ===
        // ================================================================
        System.out.println("\n================================================================================");
        System.out.println("=== STANDARDISED FEATURES - SEED 42 ===");
        System.out.println("Settings: same as AnomalyAnalyzer - trees=100, sampling_rate=0.70,");
        System.out.println("          max_depth=8, extension_level=8, fraction=0.10, score_threshold=0.5");
        System.out.println("          Features: z-score standardised (subtract mean, divide by pop-std-dev)");
        System.out.println("================================================================================");

        double[] scores42 = fitAndScore(std, 42L);
        printSections3and4(scores42, sessionIds, scenarioIndices, isAnomaly, scenarioOf, n, 42L);

        // ================================================================
        // === SEEDS 1-5 for stability ===
        // ================================================================
        System.out.println("\n================================================================================");
        System.out.println("=== STANDARDISED FEATURES - SEED STABILITY (seeds 1 to 5) ===");
        System.out.println("================================================================================");
        System.out.printf("%-6s  %5s %5s %5s %5s  %s%n",
                "Seed", "TP", "FP", "FN", "TN", "Flagged");
        System.out.println("-".repeat(50));

        for (long seed = 1; seed <= 5; seed++) {
            double[] seedScores = fitAndScore(std, seed);
            int[] cm = confusionMatrix(seedScores, sessionIds, isAnomaly, n);
            int flagged = flaggedCount(seedScores, n);
            System.out.printf("%-6d  %5d %5d %5d %5d  %d%n",
                    seed, cm[0], cm[1], cm[2], cm[3], flagged);
        }

        // ================================================================
        // === PLAIN-ENGLISH COMPARISON ===
        // ================================================================
        System.out.println("\n================================================================================");
        System.out.println("=== PLAIN-ENGLISH COMPARISON: RAW vs STANDARDISED FEATURES ===");
        System.out.println("================================================================================");

        // Recompute raw metrics for the comparison paragraph
        double[] rawScores42 = fitAndScore(raw, 42L);
        int[] rawCm = confusionMatrix(rawScores42, sessionIds, isAnomaly, n);

        double[] stdScores42 = scores42;
        int[] stdCm = confusionMatrix(stdScores42, sessionIds, isAnomaly, n);

        // Count burst sessions flagged under each model
        List<Integer> burstIdx = scenarioIndices.get("BEHAVIOR_BURST");
        int rawBurstFlagged = 0;
        int stdBurstFlagged = 0;
        for (int i : burstIdx) {
            if (isFlagged(rawScores42, i, n)) rawBurstFlagged++;
            if (isFlagged(stdScores42, i, n)) stdBurstFlagged++;
        }

        System.out.println();
        System.out.printf("                       %-10s  %-10s%n", "RAW", "STANDARDISED");
        System.out.println("  " + "-".repeat(40));
        System.out.printf("  %-22s %-10d  %-10d%n", "True Positives (TP):",  rawCm[0], stdCm[0]);
        System.out.printf("  %-22s %-10d  %-10d%n", "False Positives (FP):", rawCm[1], stdCm[1]);
        System.out.printf("  %-22s %-10d  %-10d%n", "False Negatives (FN):", rawCm[2], stdCm[2]);
        System.out.printf("  %-22s %-10d  %-10d%n", "True Negatives (TN):",  rawCm[3], stdCm[3]);
        System.out.printf("  %-22s %-10.3f  %-10.3f%n", "Precision:",
                precision(rawCm), precision(stdCm));
        System.out.printf("  %-22s %-10.3f  %-10.3f%n", "Recall:",
                recall(rawCm), recall(stdCm));
        System.out.printf("  %-22s %-10.3f  %-10.3f%n", "F1:",
                f1(rawCm), f1(stdCm));
        System.out.printf("  %-22s %-10d  %-10d%n", "BEHAVIOR_BURST caught:", rawBurstFlagged, stdBurstFlagged);
        System.out.println("  " + "-".repeat(40));
        System.out.println();

        System.out.println("Summary:");
        System.out.println();
        System.out.println("  RAW FEATURES (Stage 9D):");
        System.out.println("  With unscaled features the forest is dominated by high-magnitude columns");
        System.out.println("  such as maxDistanceKm (0-17,000 km) and durationSeconds (0-3,500 s).");
        System.out.println("  The BEHAVIOR_BURST signal lives in low-magnitude columns (minGapSeconds=1,");
        System.out.println("  maxGapSeconds=3, eventCount=43-59). Because all 10 burst sessions share");
        System.out.println("  nearly identical values, they form a dense cluster that is hard to isolate;");
        System.out.println("  their raw scores cluster tightly around 0.441-0.452, all below 0.5.");
        System.out.println("  Result: TP=" + rawCm[0] + ", FP=" + rawCm[1] + ", BEHAVIOR_BURST caught=" + rawBurstFlagged + ".");
        System.out.println();
        System.out.println("  STANDARDISED FEATURES:");
        System.out.println("  After z-scoring, every column has mean=0 and std=1, so the forest");
        System.out.println("  applies equal sensitivity to each feature's deviation from its own mean.");
        System.out.println("  BEHAVIOR_BURST sessions are now extreme outliers in eventCount (z≈+10)");
        System.out.println("  and minGapSeconds/maxGapSeconds (z≈-5), which were previously tiny in");
        System.out.println("  absolute terms but are now far from normal. This can lift their anomaly");
        System.out.println("  scores above 0.5 so the flag logic picks them up.");
        System.out.println("  Result: TP=" + stdCm[0] + ", FP=" + stdCm[1] + ", BEHAVIOR_BURST caught=" + stdBurstFlagged + ".");
        System.out.println();

        if (stdCm[0] > rawCm[0]) {
            System.out.println("  VERDICT: Standardising the features improves overall TP from "
                    + rawCm[0] + " to " + stdCm[0] + " (+" + (stdCm[0] - rawCm[0]) + ").");
            System.out.println("  BEHAVIOR_BURST catch rate changes from " + rawBurstFlagged + "/10 to " + stdBurstFlagged + "/10.");
            System.out.println("  FP changes from " + rawCm[1] + " to " + stdCm[1] + ".");
            System.out.println("  This confirms that feature scale was a contributing factor to the miss.");
            System.out.println("  Cluster masking (hypothesis b) may still apply; the magnitude of gain");
            System.out.println("  in BEHAVIOR_BURST catch rate indicates how dominant the scale effect was.");
        } else if (stdCm[0] == rawCm[0]) {
            System.out.println("  VERDICT: Standardising features does NOT change TP (" + rawCm[0] + ") or");
            System.out.println("  BEHAVIOR_BURST catch rate. Scale was not the dominant factor.");
            System.out.println("  Cluster masking (hypothesis b from Stage 9D) remains the primary cause.");
        } else {
            System.out.println("  VERDICT: Standardising features actually reduces TP from "
                    + rawCm[0] + " to " + stdCm[0] + ".");
            System.out.println("  Scale normalisation hurt performance here, possibly because the");
            System.out.println("  raw magnitudes of maxDistanceKm/durationSeconds were themselves");
            System.out.println("  useful anomaly signals that z-scoring compressed.");
        }

        System.out.println("\nStage 9D-2 Diagnostic completed.");
    }

    // ----------------------------------------------------------------
    // Train IsolationForest on the given data matrix with a given seed
    // and return a score[] array in the same row order as the input.
    // Same Properties as AnomalyAnalyzer (only trees=100 is set).
    // ----------------------------------------------------------------
    private static double[] fitAndScore(double[][] data, long seed) {
        Properties props = new Properties();
        props.setProperty("smile.isolation_forest.trees", "100");

        IsolationForest forest;
        ForkJoinPool pool = new ForkJoinPool(1);
        try {
            forest = pool.submit(() -> {
                MathEx.setSeed(seed);
                return IsolationForest.fit(data, props);
            }).get();
        } catch (Exception e) {
            throw new RuntimeException("Forest training failed: " + e.getMessage(), e);
        } finally {
            pool.shutdown();
        }

        double[] scores = new double[data.length];
        for (int i = 0; i < data.length; i++) {
            scores[i] = forest.score(data[i]);
        }
        return scores;
    }

    // ----------------------------------------------------------------
    // Determine the score cutoff for the top-fraction sessions.
    // ----------------------------------------------------------------
    private static double cutoff(double[] scores, int n) {
        List<Double> sorted = new ArrayList<>();
        for (double s : scores) sorted.add(s);
        Collections.sort(sorted, Collections.reverseOrder());
        int k = (int) Math.round(n * EXPECTED_ANOMALY_FRACTION);
        if (k < 1) k = 1;
        if (k > sorted.size()) k = sorted.size();
        return sorted.get(k - 1);
    }

    // ----------------------------------------------------------------
    // True if session i would be flagged under the standard flag logic.
    // ----------------------------------------------------------------
    private static boolean isFlagged(double[] scores, int i, int n) {
        double cut = cutoff(scores, n);
        return scores[i] >= cut && scores[i] > SCORE_THRESHOLD;
    }

    // ----------------------------------------------------------------
    // Count total flagged sessions.
    // ----------------------------------------------------------------
    private static int flaggedCount(double[] scores, int n) {
        double cut = cutoff(scores, n);
        int count = 0;
        for (double s : scores) {
            if (s >= cut && s > SCORE_THRESHOLD) count++;
        }
        return count;
    }

    // ----------------------------------------------------------------
    // Compute [TP, FP, FN, TN] against ground-truth.
    // ----------------------------------------------------------------
    private static int[] confusionMatrix(double[] scores,
                                         List<String> sessionIds,
                                         Map<String, Boolean> isAnomaly,
                                         int n) {
        double cut = cutoff(scores, n);
        int tp = 0, fp = 0, fn = 0, tn = 0;
        for (int i = 0; i < n; i++) {
            String sid = sessionIds.get(i);
            boolean actual  = Boolean.TRUE.equals(isAnomaly.get(sid));
            boolean flagged = scores[i] >= cut && scores[i] > SCORE_THRESHOLD;
            if (actual && flagged)  tp++;
            else if (!actual && flagged) fp++;
            else if (actual && !flagged) fn++;
            else tn++;
        }
        return new int[]{tp, fp, fn, tn};
    }

    // ----------------------------------------------------------------
    // Print scenario-level scores (like Section 3 of 9D) and
    // BEHAVIOR_BURST detail (like Section 4 of 9D).
    // ----------------------------------------------------------------
    private static void printSections3and4(double[] scores,
                                            List<String> sessionIds,
                                            Map<String, List<Integer>> scenarioIndices,
                                            Map<String, Boolean> isAnomaly,
                                            Map<String, String> scenarioOf,
                                            int n,
                                            long seed) {
        int totalSessions = n;
        double cut = cutoff(scores, n);
        int aboveHalf = 0;
        for (double s : scores) if (s > SCORE_THRESHOLD) aboveHalf++;

        System.out.println("\n--- Section 3-equivalent: Anomaly Scores Per Scenario ---");
        System.out.printf("Score cutoff (rank-based, top 10%%): %.6f%n", cut);
        System.out.println("Score threshold (hard): " + SCORE_THRESHOLD);
        System.out.printf("Sessions with score > %.1f: %d of %d%n", SCORE_THRESHOLD, aboveHalf, totalSessions);
        System.out.println();
        System.out.printf("%-36s %8s %8s %8s %8s%n", "Scenario", "Min", "Mean", "Max", "Flagged");
        System.out.println("-".repeat(72));

        for (String sc : SCENARIOS) {
            List<Integer> idxList = scenarioIndices.get(sc);
            if (idxList.isEmpty()) {
                System.out.printf("%-36s %8s%n", sc, "(no data)");
                continue;
            }
            double minSc = Double.MAX_VALUE, sumSc = 0.0, maxSc = -Double.MAX_VALUE;
            int flagged = 0;
            for (int i : idxList) {
                double sv = scores[i];
                if (sv < minSc) minSc = sv;
                if (sv > maxSc) maxSc = sv;
                sumSc += sv;
                if (sv >= cut && sv > SCORE_THRESHOLD) flagged++;
            }
            System.out.printf("%-36s %8.3f %8.3f %8.3f %8d%n",
                    sc, minSc, sumSc / idxList.size(), maxSc, flagged);
        }
        System.out.println("-".repeat(72));

        // Overall confusion matrix
        int[] cm = confusionMatrix(scores, sessionIds, isAnomaly, totalSessions);
        System.out.println("\nConfusion matrix: TP=" + cm[0] + " FP=" + cm[1]
                + " FN=" + cm[2] + " TN=" + cm[3]
                + " | Total=" + (cm[0]+cm[1]+cm[2]+cm[3]));
        System.out.printf("Precision=%.3f  Recall=%.3f  F1=%.3f  Accuracy=%.3f%n",
                precision(cm), recall(cm), f1(cm), accuracy(cm));

        // ---- Section 4-equivalent: BEHAVIOR_BURST one by one ----
        System.out.println("\n--- Section 4-equivalent: BEHAVIOR_BURST Sessions - Individual Detail ---");
        System.out.printf("%-12s %8s %6s %8s  %s%n",
                "SessionId", "Score", "Rank", "Flagged", "Reason if NOT flagged");
        System.out.println("-".repeat(85));

        // Build rank array
        Integer[] order = new Integer[totalSessions];
        for (int i = 0; i < totalSessions; i++) order[i] = i;
        Arrays.sort(order, (a, b) -> Double.compare(scores[b], scores[a]));
        int[] rankOf = new int[totalSessions];
        for (int r = 0; r < totalSessions; r++) rankOf[order[r]] = r + 1;

        int k = (int) Math.round(totalSessions * EXPECTED_ANOMALY_FRACTION);
        if (k < 1) k = 1;

        List<Integer> burstIdx = scenarioIndices.get("BEHAVIOR_BURST");
        for (int i : burstIdx) {
            String sid   = sessionIds.get(i);
            double sc    = scores[i];
            int rank     = rankOf[i];
            boolean flag = sc >= cut && sc > SCORE_THRESHOLD;
            String reason = "";
            if (!flag) {
                boolean rankOk  = rank <= k;
                boolean scoreOk = sc > SCORE_THRESHOLD;
                if (!rankOk && !scoreOk)
                    reason = "rank=" + rank + " > " + k + " AND score=" + String.format(Locale.US, "%.3f", sc) + " <= 0.5";
                else if (!rankOk)
                    reason = "rank=" + rank + " > " + k + " (outside top-fraction window)";
                else
                    reason = "score=" + String.format(Locale.US, "%.3f", sc) + " <= 0.5 (below hard threshold)";
            }
            System.out.printf("%-12s %8.3f %6d %8s  %s%n",
                    sid, sc, rank, flag ? "YES" : "NO", reason);
        }
    }

    // ----------------------------------------------------------------
    // Metric helpers
    // ----------------------------------------------------------------
    private static double precision(int[] cm) {
        double d = cm[0] + cm[1]; return d == 0 ? 0 : cm[0] / d;
    }
    private static double recall(int[] cm) {
        double d = cm[0] + cm[2]; return d == 0 ? 0 : cm[0] / d;
    }
    private static double f1(int[] cm) {
        double p = precision(cm), r = recall(cm);
        double d = p + r; return d == 0 ? 0 : 2 * p * r / d;
    }
    private static double accuracy(int[] cm) {
        int t = cm[0]+cm[1]+cm[2]+cm[3]; return t == 0 ? 0 : (double)(cm[0]+cm[3])/t;
    }

    // ----------------------------------------------------------------
    // Group events by sessionId (chronological), replicating
    // SecurityAnalyzer.groupBySession logic.
    // ----------------------------------------------------------------
    private static Map<String, List<SessionEvent>> groupBySession(List<SessionEvent> events) {
        Map<String, List<SessionEvent>> map = new LinkedHashMap<>();
        if (events == null) return map;
        for (SessionEvent e : events) {
            String sid = e.getSessionId();
            if (!map.containsKey(sid)) map.put(sid, new ArrayList<>());
            map.get(sid).add(e);
        }
        for (List<SessionEvent> list : map.values()) {
            list.sort((a, b) -> a.getEventTime().compareTo(b.getEventTime()));
        }
        return map;
    }
}
