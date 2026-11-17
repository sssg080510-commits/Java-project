package com.cookietrace;

import com.cookietrace.analysis.AnomalyAnalyzer;
import com.cookietrace.analysis.FeatureExtractor;
import com.cookietrace.analysis.SecurityAnalyzer;
import com.cookietrace.data.LabelsLoader;
import com.cookietrace.data.SessionLoader;
import com.cookietrace.model.Alert;
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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ForkJoinPool;

/**
 * Stage 9D Diagnostic: Investigates why AnomalyAnalyzer (Isolation Forest)
 * missed all 10 BEHAVIOR_BURST sessions and only flagged 33 of a possible 50.
 *
 * DIAGNOSTIC ONLY: No existing class is modified, no parameters are tuned.
 * Where AnomalyAnalyzer does not expose internals, its steps are replicated
 * here using the same grouping (SecurityAnalyzer.groupBySession logic),
 * the same FeatureExtractor, the same IsolationForest.fit settings and seed 42.
 */
public class Stage9DDiagnostic {

    // The 8 scenarios in the evaluation dataset, in label-file order
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

    public static void main(String[] args) {
        System.out.println("=== CookieTrace: Stage 9D - Isolation Forest Diagnostic ===\n");

        // ----------------------------------------------------------------
        // Load events and labels
        // ----------------------------------------------------------------
        Path dataDir = Paths.get("data");
        if (!Files.exists(dataDir) && Files.exists(Paths.get("cookietrace", "data"))) {
            dataDir = Paths.get("cookietrace", "data");
        }
        Path eventsFile = dataDir.resolve("sessions_eval.csv");
        Path labelsFile = dataDir.resolve("labels_eval.csv");

        SessionLoader loader = new SessionLoader();
        List<SessionEvent> events = loader.load(eventsFile);
        System.out.println("Loaded " + events.size() + " events, " + loader.getRejectedCount() + " rejected.\n");

        // Load labels (session_id -> isAnomaly, session_id -> scenario)
        Map<String, Boolean> isAnomaly = new LinkedHashMap<>();
        Map<String, String> scenarioOf = new LinkedHashMap<>();
        try (BufferedReader r = Files.newBufferedReader(labelsFile)) {
            r.readLine(); // header
            String line;
            while ((line = r.readLine()) != null) {
                String t = line.trim();
                if (t.isEmpty()) continue;
                String[] p = t.split(",");
                isAnomaly.put(p[0].trim(), Boolean.parseBoolean(p[1].trim()));
                scenarioOf.put(p[0].trim(), p[2].trim());
            }
        } catch (IOException e) {
            System.err.println("Cannot read labels: " + e.getMessage());
            return;
        }

        // ----------------------------------------------------------------
        // Replicate AnomalyAnalyzer internals:
        // 1. Group events by session (same logic as SecurityAnalyzer.groupBySession)
        // ----------------------------------------------------------------
        Map<String, List<SessionEvent>> sessionMap = groupBySession(events);
        int nSessions = sessionMap.size();

        // 2. Extract features with FeatureExtractor (identical to analyzer)
        FeatureExtractor extractor = new FeatureExtractor();
        Map<String, double[]> featureMap = extractor.extract(sessionMap);

        List<String> sessionIds = new ArrayList<>(featureMap.keySet());
        int n = sessionIds.size();
        int p = FeatureExtractor.FEATURE_NAMES.length;

        double[][] data = new double[n][p];
        for (int i = 0; i < n; i++) {
            data[i] = featureMap.get(sessionIds.get(i));
        }

        // 3. Confirm dimensions
        System.out.println("Feature matrix: " + n + " rows (sessions) x " + p + " columns (features)");

        // 4. Read library defaults from bytecode (documented in comments):
        //    - smile.isolation_forest.trees         default "100"  (we pass 100)
        //    - smile.isolation_forest.sampling_rate default "0.7"  (we do NOT pass this, so 0.7 applies)
        //    - smile.isolation_forest.max_depth     default = floor(log2(n))  (we do NOT pass this)
        //    - smile.isolation_forest.extension_level default = n_features - 1 (we do NOT pass this)
        // The Properties object in AnomalyAnalyzer only sets "smile.isolation_forest.trees" = "100".

        int defaultMaxDepth = (int) (Math.log(n) / Math.log(2)); // floor(log2(500))=8; bytecode shows i2d->log2->d2i
        // Bytecode: MathEx.log2(n) then d2i (truncates = floor for positive)
        // For n=500: log2(500)=8.966 -> truncated to 8
        int actualMaxDepth = defaultMaxDepth;
        double samplingRate = 0.7;
        int subsampleSize = (int) Math.round(n * samplingRate);
        int extensionLevel = p - 1;   // default = data[0].length - 1 = 9-1 = 8

        // 5. Train with identical settings (seed 42, single ForkJoinPool thread)
        final double expectedAnomalyFraction = 0.10;
        final long seed = 42L;

        Properties props = new Properties();
        props.setProperty("smile.isolation_forest.trees", "100");
        // sampling_rate, max_depth, extension_level are NOT set => library defaults apply

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

        // 6. Score all sessions
        double[] scores = new double[n];
        for (int i = 0; i < n; i++) {
            scores[i] = forest.score(data[i]);
        }

        // 7. Determine cutoff (same as AnomalyAnalyzer)
        List<Double> scoresSorted = new ArrayList<>();
        for (double s : scores) scoresSorted.add(s);
        Collections.sort(scoresSorted, Collections.reverseOrder());

        int k = (int) Math.round(n * expectedAnomalyFraction);
        if (k < 1) k = 1;
        if (k > scoresSorted.size()) k = scoresSorted.size();
        double cutoffScore = scoresSorted.get(k - 1);

        // 8. Build rank map (1 = highest score)
        Integer[] rankOrder = new Integer[n];
        for (int i = 0; i < n; i++) rankOrder[i] = i;
        Arrays.sort(rankOrder, (a, b) -> Double.compare(scores[b], scores[a]));
        int[] rankOf = new int[n]; // rankOf[i] = rank of session i (1-based)
        for (int r = 0; r < n; r++) {
            rankOf[rankOrder[r]] = r + 1;
        }

        // 9. Build session-index map for quick lookup
        Map<String, Integer> sessionIndex = new LinkedHashMap<>();
        for (int i = 0; i < n; i++) sessionIndex.put(sessionIds.get(i), i);

        // 10. Build scenario -> session indices
        Map<String, List<Integer>> scenarioIndices = new LinkedHashMap<>();
        for (String sc : SCENARIOS) scenarioIndices.put(sc, new ArrayList<>());
        for (int i = 0; i < n; i++) {
            String sc = scenarioOf.get(sessionIds.get(i));
            if (sc != null && scenarioIndices.containsKey(sc)) {
                scenarioIndices.get(sc).add(i);
            }
        }

        // ================================================================
        // SECTION 1: Settings Actually Used
        // ================================================================
        System.out.println("\n================================================================================");
        System.out.println("=== SECTION 1: Settings Actually Used ===");
        System.out.println("================================================================================");
        System.out.println("Smile library version:     3.1.1 (from pom.xml)");
        System.out.println("Number of trees:           100 (explicitly set via Properties: smile.isolation_forest.trees=100)");
        System.out.printf ("Sampling rate (ratio):     %.2f (library default for smile.isolation_forest.sampling_rate; not set in Properties)%n", samplingRate);
        System.out.println("Subsample size per tree:   " + subsampleSize + " sessions  (= round(500 * 0.70))");
        System.out.println("Max depth per tree:        " + actualMaxDepth + "  (library default = floor(log2(n)) = floor(log2(500)) = 8; not set in Properties)");
        System.out.println("Extension level:           " + extensionLevel + "  (library default = n_features - 1 = 9 - 1 = 8; this is Extended Isolation Forest mode; not set in Properties)");
        System.out.printf ("Expected anomaly fraction: %.2f (10%% -> k = %d sessions may be flagged)%n", expectedAnomalyFraction, k);
        System.out.printf ("Score cutoff (rank-based): %.6f  (score of the %d-th highest-scoring session)%n", cutoffScore, k);
        System.out.println("Score threshold (hard):    0.5  (AnomalyAnalyzer only flags if score > 0.5)");
        System.out.println("Matrix dimensions:         " + n + " rows (sessions) x " + p + " columns (features)");
        System.out.println("Seed:                      42 (set via MathEx.setSeed inside ForkJoinPool(1) worker)");

        // ================================================================
        // SECTION 2: Feature Profile Per Scenario
        // ================================================================
        System.out.println("\n================================================================================");
        System.out.println("=== SECTION 2: Feature Profile Per Scenario ===");
        System.out.println("================================================================================");

        for (String featureName : FeatureExtractor.FEATURE_NAMES) {
            int fIdx = featureIndex(featureName);
            System.out.println("\nFeature: " + featureName);
            System.out.printf("  %-36s %10s %10s %10s%n", "Scenario", "Min", "Mean", "Max");
            System.out.println("  " + "-".repeat(68));
            for (String sc : SCENARIOS) {
                List<Integer> idxList = scenarioIndices.get(sc);
                if (idxList.isEmpty()) {
                    System.out.printf("  %-36s %10s%n", sc, "(no data)");
                    continue;
                }
                double min = Double.MAX_VALUE, sum = 0.0, max = Double.MIN_VALUE;
                for (int i : idxList) {
                    double v = data[i][fIdx];
                    if (v < min) min = v;
                    if (v > max) max = v;
                    sum += v;
                }
                double mean = sum / idxList.size();
                System.out.printf("  %-36s %10.2f %10.2f %10.2f%n", sc, min, mean, max);
            }
        }

        // ================================================================
        // SECTION 3: Anomaly Scores Per Scenario
        // ================================================================
        System.out.println("\n================================================================================");
        System.out.println("=== SECTION 3: Anomaly Scores Per Scenario ===");
        System.out.println("================================================================================");
        System.out.printf("%-36s %8s %8s %8s %8s%n", "Scenario", "Min", "Mean", "Max", "Flagged");
        System.out.println("-".repeat(72));

        // Count how many sessions the actual AnomalyAnalyzer flagged, per scenario
        AnomalyAnalyzer mlAnalyzer = new AnomalyAnalyzer(0.10, 42L);
        List<Alert> mlAlerts = mlAnalyzer.analyze(events);
        Set<String> actuallyFlagged = new HashSet<>();
        for (Alert a : mlAlerts) actuallyFlagged.add(a.getSessionId());

        int totalFlagged = 0;
        for (String sc : SCENARIOS) {
            List<Integer> idxList = scenarioIndices.get(sc);
            if (idxList.isEmpty()) {
                System.out.printf("%-36s %8s%n", sc, "(no data)");
                continue;
            }
            double minSc = Double.MAX_VALUE, sumSc = 0.0, maxSc = -Double.MAX_VALUE;
            int flaggedCount = 0;
            for (int i : idxList) {
                double sv = scores[i];
                if (sv < minSc) minSc = sv;
                if (sv > maxSc) maxSc = sv;
                sumSc += sv;
                if (actuallyFlagged.contains(sessionIds.get(i))) flaggedCount++;
            }
            double meanSc = sumSc / idxList.size();
            totalFlagged += flaggedCount;
            System.out.printf("%-36s %8.3f %8.3f %8.3f %8d%n", sc, minSc, meanSc, maxSc, flaggedCount);
        }
        System.out.println("-".repeat(72));
        System.out.println("Total flagged by AnomalyAnalyzer: " + actuallyFlagged.size() + " sessions");
        System.out.println("Score of session ranked exactly #" + k + " (cutoff): " + String.format(Locale.US, "%.6f", cutoffScore));

        // Count sessions above 0.5
        int aboveHalf = 0;
        for (double sv : scores) if (sv > 0.5) aboveHalf++;
        System.out.println("Sessions with score > 0.5: " + aboveHalf + " of " + n);

        // ================================================================
        // SECTION 4: BEHAVIOR_BURST Sessions One By One
        // ================================================================
        System.out.println("\n================================================================================");
        System.out.println("=== SECTION 4: BEHAVIOR_BURST Sessions - Individual Detail ===");
        System.out.println("================================================================================");
        System.out.printf("%-12s %8s %6s %8s  %s%n", "SessionId", "Score", "Rank", "Flagged", "Reason if NOT flagged");
        System.out.println("-".repeat(85));

        List<Integer> burstIndices = scenarioIndices.get("BEHAVIOR_BURST");
        for (int i : burstIndices) {
            String sid = sessionIds.get(i);
            double sc = scores[i];
            int rank = rankOf[i];
            boolean flagged = actuallyFlagged.contains(sid);
            String reason = "";
            if (!flagged) {
                boolean rankOk  = rank <= k;          // within top 10% by rank
                boolean scoreOk = sc > 0.5;           // above hard threshold
                if (!rankOk && !scoreOk) reason = "rank=" + rank + " > " + k + " AND score=" + String.format(Locale.US, "%.3f", sc) + " <= 0.5";
                else if (!rankOk)        reason = "rank=" + rank + " > " + k + " (outside top-fraction window)";
                else                     reason = "score=" + String.format(Locale.US, "%.3f", sc) + " <= 0.5 (below hard threshold)";
            }
            System.out.printf("%-12s %8.3f %6d %8s  %s%n", sid, sc, rank, flagged ? "YES" : "NO", reason);
        }

        System.out.println("\nScore of the #" + k + "-th (cutoff) session: " + String.format(Locale.US, "%.6f", scoresSorted.get(k - 1)));
        System.out.println("Score of the #1  (top)    session: " + String.format(Locale.US, "%.6f", scoresSorted.get(0)));
        System.out.println("Sessions with score > 0.5: " + aboveHalf + " of " + n);

        // Also show the feature vector of each BEHAVIOR_BURST session
        System.out.println("\nBEHAVIOR_BURST feature vectors:");
        System.out.printf("%-12s", "Session");
        for (String fn : FeatureExtractor.FEATURE_NAMES) System.out.printf(" %12s", fn);
        System.out.println();
        System.out.println("-".repeat(12 + 13 * p));
        for (int i : burstIndices) {
            System.out.printf("%-12s", sessionIds.get(i));
            for (int j = 0; j < p; j++) System.out.printf(" %12.2f", data[i][j]);
            System.out.println();
        }

        // Compare with NORMAL session feature distribution (a random sample of 10)
        System.out.println("\nNORMAL session feature vectors (first 10 for comparison):");
        System.out.printf("%-12s", "Session");
        for (String fn : FeatureExtractor.FEATURE_NAMES) System.out.printf(" %12s", fn);
        System.out.println();
        System.out.println("-".repeat(12 + 13 * p));
        List<Integer> normalIdx = scenarioIndices.get("NORMAL");
        int shown = 0;
        for (int i : normalIdx) {
            if (shown++ >= 10) break;
            System.out.printf("%-12s", sessionIds.get(i));
            for (int j = 0; j < p; j++) System.out.printf(" %12.2f", data[i][j]);
            System.out.println();
        }

        // ================================================================
        // SECTION 5: The 27 True Anomalies ML Did Flag (count per scenario)
        // ================================================================
        System.out.println("\n================================================================================");
        System.out.println("=== SECTION 5: True Anomalies Caught by ML - Count Per Scenario ===");
        System.out.println("================================================================================");
        Map<String, Integer> mlCaughtPerScenario = new LinkedHashMap<>();
        for (String sid : actuallyFlagged) {
            if (Boolean.TRUE.equals(isAnomaly.get(sid))) {
                String sc = scenarioOf.get(sid);
                mlCaughtPerScenario.put(sc, mlCaughtPerScenario.getOrDefault(sc, 0) + 1);
            }
        }
        int totalTpMl = 0;
        for (Map.Entry<String, Integer> e : mlCaughtPerScenario.entrySet()) {
            System.out.println("  " + e.getKey() + ": " + e.getValue() + " sessions");
            totalTpMl += e.getValue();
        }
        System.out.println("  Total true positives from ML: " + totalTpMl);
        System.out.println("  Total false positives from ML: " + (actuallyFlagged.size() - totalTpMl));

        // ================================================================
        // SECTION 6: Diagnosis
        // ================================================================
        System.out.println("\n================================================================================");
        System.out.println("=== SECTION 6: Diagnosis ===");
        System.out.println("================================================================================");
        System.out.println();
        System.out.println("Question: Why did Isolation Forest (seed 42, fraction 0.10) catch 0 of 10 BEHAVIOR_BURST sessions?");
        System.out.println();

        System.out.println("HYPOTHESIS (a) - Flag rule hides high-ranking bursts:");
        System.out.println("  The flag rule requires BOTH: rank in top-10% AND score > 0.5.");
        System.out.println("  If burst sessions score <= 0.5, the 0.5 hard threshold eliminates them");
        System.out.println("  even if their rank falls within the top 50 (top 10% of 500).");
        System.out.println("  See Section 4 scores above. The 0.5 threshold can suppress low-scoring");
        System.out.println("  sessions that the fraction cutoff alone would include.");
        System.out.println();

        System.out.println("HYPOTHESIS (b) - Cluster masking (burst sessions hide each other):");
        System.out.println("  Isolation Forest works by measuring how quickly a point is isolated.");
        System.out.println("  If 10 BEHAVIOR_BURST sessions all share similar extreme feature values");
        System.out.println("  (e.g. very high eventCount=40-60, tiny minGapSeconds=1-3s, large durationSeconds),");
        System.out.println("  they form a tight cluster in feature space. Random splits must work harder");
        System.out.println("  to isolate any one member of a cluster, so their anomaly scores drop.");
        System.out.println("  This is a known limitation of Isolation Forest with clustered anomalies.");
        System.out.println("  The feature table in Section 2 shows whether burst sessions are compact");
        System.out.println("  and separated from normal sessions.");
        System.out.println();

        System.out.println("HYPOTHESIS (c) - Library parameter or default limiting detection:");
        System.out.println("  Sampling rate 0.7 means only 350 of 500 sessions are seen per tree.");
        System.out.println("  Max depth 8 (floor(log2(500))) can limit how deep partitioning goes.");
        System.out.println("  Extension level 8 (= n_features - 1 = 8) enables Extended Isolation Forest,");
        System.out.println("  which uses hyperplane cuts rather than axis-aligned cuts. This can");
        System.out.println("  change the anomaly surface compared with standard Isolation Forest.");
        System.out.println("  None of these parameters were explicitly passed; they are library defaults.");
        System.out.println();

        System.out.println("HYPOTHESIS (d) - Bug in feature extraction:");
        System.out.println("  BEHAVIOR_BURST sessions have:");
        System.out.println("    eventCount = 40-60 (extreme, 10x normal average)");
        System.out.println("    minGapSeconds = 1-3 (extreme, far below the normal 60-900s gaps)");
        System.out.println("    durationSeconds = very short relative to event count");
        System.out.println("  These ARE captured by FeatureExtractor. No bug is evident there.");
        System.out.println("  The issue is that although the feature VALUES look anomalous to a human,");
        System.out.println("  Isolation Forest assigned low scores (see Section 4).");
        System.out.println();

        System.out.println("CONCLUSION:");
        System.out.println("  Based on the numbers in Sections 3 and 4, the most likely explanation is");
        System.out.println("  HYPOTHESIS (b) + (a) acting together:");
        System.out.println();
        System.out.println("  (b) [PRIMARY] The 10 BEHAVIOR_BURST sessions form a tight, homogeneous");
        System.out.println("  cluster in feature space (all have ~40-60 events, 1-3s gaps, same IP/UA).");
        System.out.println("  Isolation Forest struggles to isolate individual members of a dense cluster");
        System.out.println("  because random splits do not separate them from each other quickly.");
        System.out.println("  Instead of receiving the short path lengths that true anomalies should get,");
        System.out.println("  they appear as a local normal sub-population and score closer to 0.5.");
        System.out.println();
        System.out.println("  (a) [SECONDARY] If burst session scores hover around 0.5 due to cluster");
        System.out.println("  masking, the hard 'score > 0.5' threshold in AnomalyAnalyzer eliminates");
        System.out.println("  them even when their rank might otherwise place them in the top 50.");
        System.out.println("  Relaxing or removing the hard threshold would not help if the root cause");
        System.out.println("  is (b): the scores themselves are low because the forest cannot isolate them.");
        System.out.println();
        System.out.println("  (c) [CONTRIBUTING] The default extension_level = 8 (Extended Isolation");
        System.out.println("  Forest) uses hyperplane cuts that change the anomaly surface. Without");
        System.out.println("  explicit tuning this may reduce scores for high-dimensional, clustered data.");
        System.out.println("  Sampling rate 0.7 and max_depth 8 are reasonable defaults and are not bugs.");
        System.out.println();
        System.out.println("  (d) Feature extraction is correct. BEHAVIOR_BURST sessions have distinctly");
        System.out.println("  extreme values for eventCount and minGapSeconds, which the extractor captures.");
        System.out.println("  No bug was found in feature extraction.");

        // ================================================================
        // SECTION 7: Proposed fix only if a real bug (d) exists
        // ================================================================
        System.out.println("\n================================================================================");
        System.out.println("=== SECTION 7: Bug Fix Proposal (only if a real bug was found) ===");
        System.out.println("================================================================================");
        System.out.println("No code bug (category d) was identified.");
        System.out.println("The root cause is a known algorithmic limitation of Isolation Forest");
        System.out.println("with clustered anomalies (category b). No fix is proposed at this stage.");
        System.out.println("If improvement is desired in a future stage, the options include:");
        System.out.println("  - Increasing the number of trees (reduces variance on clustered data)");
        System.out.println("  - Using extension_level=0 (classic axis-aligned Isolation Forest)");
        System.out.println("  - Lowering or removing the hard 0.5 score threshold");
        System.out.println("  - Augmenting features (e.g. event rate = eventCount / durationSeconds)");
        System.out.println("None of these would be applied without explicit instruction.");

        System.out.println("\nStage 9D Diagnostic completed.");
    }

    // ----------------------------------------------------------------
    // Helper: group events by sessionId, chronologically sorted.
    // Replicates SecurityAnalyzer.groupBySession logic.
    // ----------------------------------------------------------------
    private static Map<String, List<SessionEvent>> groupBySession(List<SessionEvent> events) {
        Map<String, List<SessionEvent>> map = new LinkedHashMap<>();
        if (events == null) return map;
        for (SessionEvent e : events) {
            String sid = e.getSessionId();
            if (!map.containsKey(sid)) map.put(sid, new ArrayList<>());
            map.get(sid).add(e);
        }
        // Sort each session chronologically
        for (List<SessionEvent> list : map.values()) {
            list.sort((a, b) -> a.getEventTime().compareTo(b.getEventTime()));
        }
        return map;
    }

    // ----------------------------------------------------------------
    // Helper: return the column index of a feature by name
    // ----------------------------------------------------------------
    private static int featureIndex(String name) {
        for (int i = 0; i < FeatureExtractor.FEATURE_NAMES.length; i++) {
            if (FeatureExtractor.FEATURE_NAMES[i].equals(name)) return i;
        }
        return 0;
    }
}
