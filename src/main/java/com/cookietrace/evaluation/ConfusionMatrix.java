package com.cookietrace.evaluation;

import com.cookietrace.exception.InvalidSessionDataException;

/**
 * ConfusionMatrix represents the evaluation outcomes of a binary classification detector
 * for web session threat detection.
 *
 * Immutability & Encapsulation:
 * - All counts (tp, fp, fn, tn) are private final integers.
 * - Constructor validates that counts cannot be negative, preventing corrupted metric states.
 * - Read-only getters provide safe access.
 *
 * Positive vs. Negative Definition:
 * - In this evaluation, POSITIVE means an ANOMALOUS (compromised or attack-simulating) session.
 * - NEGATIVE means a NORMAL (benign browsing) session.
 */
public class ConfusionMatrix {

    // Private final fields to enforce immutability
    private final int tp; // True Positives: Anomalous sessions correctly flagged as anomalies
    private final int fp; // False Positives: Normal sessions incorrectly flagged as anomalies (false alarms)
    private final int fn; // False Negatives: Anomalous sessions missed by the detector
    private final int tn; // True Negatives: Normal sessions correctly left unflagged

    /**
     * Constructs and validates an immutable ConfusionMatrix.
     *
     * @param tp True positives count (>= 0)
     * @param fp False positives count (>= 0)
     * @param fn False negatives count (>= 0)
     * @param tn True negatives count (>= 0)
     * @throws InvalidSessionDataException If any count is negative
     */
    public ConfusionMatrix(int tp, int fp, int fn, int tn) {
        if (tp < 0 || fp < 0 || fn < 0 || tn < 0) {
            throw new InvalidSessionDataException(
                "Confusion matrix counts cannot be negative: tp=" + tp + ", fp=" + fp + ", fn=" + fn + ", tn=" + tn
            );
        }
        this.tp = tp;
        this.fp = fp;
        this.fn = fn;
        this.tn = tn;
    }

    public int getTp() {
        return tp;
    }

    public int getFp() {
        return fp;
    }

    public int getFn() {
        return fn;
    }

    public int getTn() {
        return tn;
    }

    /**
     * Total number of evaluated sessions (TP + FP + FN + TN).
     *
     * @return Sum of all matrix quadrants
     */
    public int getTotal() {
        return tp + fp + fn + tn;
    }

    /**
     * Precision: tp / (tp + fp)
     *
     * Plain-English meaning:
     * When the detector raises an alarm and flags a session, how often is it actually an anomaly?
     * A precision of 1.0 means zero false alarms (every alert was a real threat).
     * Returns 0.0 when denominator (tp + fp) is zero.
     *
     * @return Precision score between 0.0 and 1.0
     */
    public double precision() {
        double denom = tp + fp;
        if (denom == 0.0) {
            return 0.0;
        }
        return tp / denom;
    }

    /**
     * Recall (True Positive Rate / Sensitivity): tp / (tp + fn)
     *
     * Plain-English meaning:
     * Of all the true anomalous sessions that existed in the dataset, what fraction did the detector catch?
     * A recall of 1.0 means zero missed threats (every real attack was caught).
     * Returns 0.0 when denominator (tp + fn) is zero.
     *
     * @return Recall score between 0.0 and 1.0
     */
    public double recall() {
        double denom = tp + fn;
        if (denom == 0.0) {
            return 0.0;
        }
        return tp / denom;
    }

    /**
     * F1 Score: 2 * precision * recall / (precision + recall)
     *
     * Plain-English meaning:
     * Harmonic mean of precision and recall. It balances the cost of false alarms against the cost
     * of missed attacks into a single performance number.
     * Returns 0.0 when denominator (precision + recall) is zero.
     *
     * @return F1 score between 0.0 and 1.0
     */
    public double f1() {
        double p = precision();
        double r = recall();
        double denom = p + r;
        if (denom == 0.0) {
            return 0.0;
        }
        return (2.0 * p * r) / denom;
    }

    /**
     * Accuracy: (tp + tn) / total
     *
     * Plain-English meaning:
     * The overall fraction of all evaluated sessions where the detector made the correct judgment
     * (either flagging a true anomaly or leaving a normal session alone).
     * Returns 0.0 when total is zero.
     *
     * @return Accuracy score between 0.0 and 1.0
     */
    public double accuracy() {
        int total = getTotal();
        if (total == 0) {
            return 0.0;
        }
        return (double) (tp + tn) / (double) total;
    }

    @Override
    public String toString() {
        return String.format("ConfusionMatrix[TP=%d, FP=%d, FN=%d, TN=%d, Total=%d]",
                tp, fp, fn, tn, getTotal());
    }
}
