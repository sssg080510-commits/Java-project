package com.cookietrace.analysis;

import com.cookietrace.exception.InvalidSessionDataException;
import com.cookietrace.model.Alert;
import com.cookietrace.model.SessionEvent;
import smile.anomaly.IsolationForest;
import smile.math.MathEx;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ForkJoinPool;

/**
 * AnomalyAnalyzer applies unsupervised machine learning (Isolation Forest) to detect unusual sessions.
 *
 * How Isolation Forest Works:
 * - Isolation Forest isolates data points by randomly partitioning features.
 * - Anomalous sessions have rare or extreme values, so they become isolated in fewer random splits
 *   (i.e., closer to the root of the tree) and therefore receive higher anomaly scores (approaching 1.0).
 * - Because it is an unsupervised learning model, it needs the whole dataset to learn what constitutes
 *   "normal" behavior; that is why analyze() trains on all events it receives.
 */
public class AnomalyAnalyzer extends SecurityAnalyzer {

    private final double expectedAnomalyFraction;
    private final long seed;
    private final Map<String, Double> lastScores;

    /**
     * Inner helper class representing feature deviation (z-score) for viva explanation.
     */
    private static class FeatureZScore {
        String name;
        double value;
        double mean;
        double zScore;
        double absZ;

        FeatureZScore(String name, double value, double mean, double zScore) {
            this.name = name;
            this.value = value;
            this.mean = mean;
            this.zScore = zScore;
            this.absZ = Math.abs(zScore);
        }
    }

    /**
     * Constructs an AnomalyAnalyzer with custom expected anomaly fraction and custom random seed.
     *
     * @param expectedAnomalyFraction Expected ratio of anomalies in the dataset (0 < fraction < 1)
     * @param seed                    Random seed for deterministic tree generation
     * @throws InvalidSessionDataException If fraction is <= 0 or >= 1
     */
    public AnomalyAnalyzer(double expectedAnomalyFraction, long seed) {
        super("AnomalyAnalyzer", 30);

        if (expectedAnomalyFraction <= 0.0 || expectedAnomalyFraction >= 1.0) {
            throw new InvalidSessionDataException(
                "expectedAnomalyFraction must be strictly between 0 and 1. Received: " + expectedAnomalyFraction
            );
        }

        this.expectedAnomalyFraction = expectedAnomalyFraction;
        this.seed = seed;
        this.lastScores = new LinkedHashMap<String, Double>();
    }

    /**
     * Constructs an AnomalyAnalyzer with custom expected anomaly fraction and default seed (42).
     *
     * @param expectedAnomalyFraction Expected ratio of anomalies in the dataset (0 < fraction < 1)
     * @throws InvalidSessionDataException If fraction is <= 0 or >= 1
     */
    public AnomalyAnalyzer(double expectedAnomalyFraction) {
        this(expectedAnomalyFraction, 42L);
    }

    /**
     * No-argument constructor defaulting expected anomaly fraction to 0.10 (10%) and seed to 42.
     */
    public AnomalyAnalyzer() {
        this(0.10, 42L);
    }

    public long getSeed() {
        return seed;
    }

    /**
     * Returns the anomaly scores computed for each session during the most recent analyze() call.
     *
     * @return Map of sessionId to anomaly score (0 to 1)
     */
    public Map<String, Double> getLastScores() {
        return lastScores;
    }

    @Override
    public List<Alert> analyze(List<SessionEvent> events) {
        List<Alert> alerts = new ArrayList<Alert>();
        lastScores.clear();

        // 1. Group events by session (chronologically sorted)
        Map<String, List<SessionEvent>> sessionMap = groupBySession(events);
        if (sessionMap.isEmpty()) {
            return alerts;
        }

        // 2. Extract numerical features (9 metrics per session)
        FeatureExtractor extractor = new FeatureExtractor();
        Map<String, double[]> featureMap = extractor.extract(sessionMap);

        List<String> sessionIds = new ArrayList<String>(featureMap.keySet());
        int n = sessionIds.size();
        int p = FeatureExtractor.FEATURE_NAMES.length;

        double[][] data = new double[n][p];
        for (int i = 0; i < n; i++) {
            data[i] = featureMap.get(sessionIds.get(i));
        }

        // 3. Compute column means and standard deviations for z-score explanations
        double[] means = new double[p];
        double[] stdDevs = new double[p];

        for (int j = 0; j < p; j++) {
            double sum = 0.0;
            for (int i = 0; i < n; i++) {
                sum += data[i][j];
            }
            means[j] = sum / n;

            double sumSqDiff = 0.0;
            for (int i = 0; i < n; i++) {
                double diff = data[i][j] - means[j];
                sumSqDiff += diff * diff;
            }
            stdDevs[j] = Math.sqrt(sumSqDiff / n);
        }

        // 4. Train Isolation Forest deterministically
        // Smile's IsolationForest.fit uses a parallel stream (IntStream.range(0, trees).parallel()),
        // which by default distributes tree training across ForkJoinPool.commonPool() worker threads.
        // Because MathEx's random number generator is stored in a ThreadLocal, calling MathEx.setSeed on
        // the caller thread does not seed the ForkJoinPool worker threads, causing non-deterministic scores.
        // By executing IsolationForest.fit inside a dedicated ForkJoinPool with parallelism 1, all
        // 100 trees are trained sequentially on a single worker thread whose ThreadLocal RNG is explicitly seeded.
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
            throw new RuntimeException("Failed to train Isolation Forest model deterministically: " + e.getMessage(), e);
        } finally {
            pool.shutdown();
        }

        // 6. Compute anomaly score for each session
        List<Double> scoreList = new ArrayList<Double>();
        for (int i = 0; i < n; i++) {
            double score = forest.score(data[i]);
            lastScores.put(sessionIds.get(i), score);
            scoreList.add(score);
        }

        // 7. Determine threshold for top expectedAnomalyFraction
        List<Double> sortedScores = new ArrayList<Double>(scoreList);
        Collections.sort(sortedScores, Collections.reverseOrder());

        int k = (int) Math.round(n * expectedAnomalyFraction);
        if (k < 1) {
            k = 1;
        }
        if (k > sortedScores.size()) {
            k = sortedScores.size();
        }
        double cutoffScore = sortedScores.get(k - 1);

        // 8. Flag sessions and generate alerts
        for (int i = 0; i < n; i++) {
            String sessionId = sessionIds.get(i);
            double score = lastScores.get(sessionId);

            // A session is flagged if in top expectedAnomalyFraction AND score > 0.5
            if (score >= cutoffScore && score > 0.5) {
                int points = (int) Math.round(30.0 * score);

                // Compute z-scores for this session's features
                List<FeatureZScore> zScores = new ArrayList<FeatureZScore>();
                for (int j = 0; j < p; j++) {
                    if (stdDevs[j] > 1e-9) {
                        double z = (data[i][j] - means[j]) / stdDevs[j];
                        if (Math.abs(z) >= 1.5) {
                            zScores.add(new FeatureZScore(
                                    FeatureExtractor.FEATURE_NAMES[j],
                                    data[i][j],
                                    means[j],
                                    z
                            ));
                        }
                    }
                }

                // Sort by absolute z-score descending
                Collections.sort(zScores, new Comparator<FeatureZScore>() {
                    @Override
                    public int compare(FeatureZScore f1, FeatureZScore f2) {
                        return Double.compare(f2.absZ, f1.absZ);
                    }
                });

                // Pick up to 3 features with largest deviation
                int limit = Math.min(3, zScores.size());
                StringBuilder featureList = new StringBuilder();
                for (int zIdx = 0; zIdx < limit; zIdx++) {
                    if (zIdx > 0) {
                        featureList.append(", ");
                    }
                    FeatureZScore f = zScores.get(zIdx);
                    String valStr = (f.value == Math.floor(f.value))
                            ? String.valueOf((long) f.value)
                            : String.format(Locale.US, "%.1f", f.value);
                    featureList.append(f.name)
                               .append(" = ")
                               .append(valStr)
                               .append(" (typical about ")
                               .append(String.format(Locale.US, "%.1f", f.mean))
                               .append(")");
                }

                String explanation;
                if (featureList.length() > 0) {
                    explanation = "Session behaved unusually compared with other sessions: " + featureList.toString();
                } else {
                    explanation = "Session behaved unusually compared with other sessions across multiple combined dimensions.";
                }

                String recommendation = "Investigate manually; this is a statistical indicator and not proof.";

                alerts.add(buildAlert(sessionId, points, explanation, recommendation));
            }
        }

        return alerts;
    }
}
