package com.cookietrace.evaluation;

import java.util.Map;
import java.util.Set;

/**
 * Evaluator computes classification metrics by comparing a detector's flagged session IDs
 * against the ground-truth anomaly labels.
 *
 * Soundness Guarantee:
 * - Every session present in the ground-truth labels map is counted exactly once.
 * - Therefore, tp + fp + fn + tn is guaranteed to equal the total size of the labels map (500 sessions).
 */
public class Evaluator {

    /**
     * Evaluates a detector against the ground-truth labels.
     *
     * @param flaggedSessionIds Set of session IDs flagged by the detector
     * @param isAnomalyMap       Map of session ID to boolean indicating whether it is truly anomalous
     * @return Fully calculated, immutable ConfusionMatrix
     */
    public ConfusionMatrix evaluate(Set<String> flaggedSessionIds, Map<String, Boolean> isAnomalyMap) {
        int tp = 0;
        int fp = 0;
        int fn = 0;
        int tn = 0;

        if (isAnomalyMap != null) {
            for (Map.Entry<String, Boolean> entry : isAnomalyMap.entrySet()) {
                String sessionId = entry.getKey();
                boolean actualAnomaly = entry.getValue() != null && entry.getValue();
                boolean flagged = flaggedSessionIds != null && flaggedSessionIds.contains(sessionId);

                if (actualAnomaly) {
                    if (flagged) {
                        tp++; // Correctly caught anomaly
                    } else {
                        fn++; // Missed anomaly
                    }
                } else {
                    if (flagged) {
                        fp++; // False alarm on normal session
                    } else {
                        tn++; // Correctly ignored normal session
                    }
                }
            }
        }

        return new ConfusionMatrix(tp, fp, fn, tn);
    }
}
