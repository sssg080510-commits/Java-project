package com.cookietrace.storage;

/**
 * Immutable data transfer model representing a single historical analysis run.
 *
 * Encapsulation Design:
 * - All fields are private final.
 * - Getters only, no setters to ensure historical audit integrity.
 */
public class RunSummary {

    private final long runId;
    private final String runTime;
    private final String dataset;
    private final int eventCount;
    private final int sessionCount;
    private final int lowCount;
    private final int mediumCount;
    private final int highCount;

    /**
     * Constructs a RunSummary record.
     *
     * @param runId        Database primary key
     * @param runTime      ISO timestamp when the run occurred
     * @param dataset      Name of the analyzed dataset (e.g. sessions_dev.csv)
     * @param eventCount   Total number of session events analyzed
     * @param sessionCount Total number of unique sessions evaluated
     * @param lowCount     Number of sessions categorized as LOW risk
     * @param mediumCount  Number of sessions categorized as MEDIUM risk
     * @param highCount    Number of sessions categorized as HIGH risk
     */
    public RunSummary(long runId, String runTime, String dataset, int eventCount,
                      int sessionCount, int lowCount, int mediumCount, int highCount) {
        this.runId = runId;
        this.runTime = runTime;
        this.dataset = dataset;
        this.eventCount = eventCount;
        this.sessionCount = sessionCount;
        this.lowCount = lowCount;
        this.mediumCount = mediumCount;
        this.highCount = highCount;
    }

    public long getRunId() {
        return runId;
    }

    public String getRunTime() {
        return runTime;
    }

    public String getDataset() {
        return dataset;
    }

    public int getEventCount() {
        return eventCount;
    }

    public int getSessionCount() {
        return sessionCount;
    }

    public int getLowCount() {
        return lowCount;
    }

    public int getMediumCount() {
        return mediumCount;
    }

    public int getHighCount() {
        return highCount;
    }

    @Override
    public String toString() {
        return String.format("Run #%d [%s | %s] events=%d sessions=%d (LOW=%d, MED=%d, HIGH=%d)",
                runId, runTime, dataset, eventCount, sessionCount, lowCount, mediumCount, highCount);
    }
}
