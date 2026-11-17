package com.cookietrace.dashboard;

import com.cookietrace.model.RiskLevel;

/**
 * Immutable value object representing a risk level escalation observed during live event streaming.
 */
public class TimelineEntry {

    private final int eventIndex;
    private final String sessionId;
    private final RiskLevel oldLevel;
    private final RiskLevel newLevel;
    private final int score;

    /**
     * Constructs a TimelineEntry.
     *
     * @param eventIndex 1-based sequential event index when escalation occurred
     * @param sessionId  Session identifier
     * @param oldLevel   Previous risk level
     * @param newLevel   Escalated new risk level
     * @param score      New cumulative score at the time of escalation
     */
    public TimelineEntry(int eventIndex, String sessionId, RiskLevel oldLevel, RiskLevel newLevel, int score) {
        this.eventIndex = eventIndex;
        this.sessionId = sessionId;
        this.oldLevel = oldLevel;
        this.newLevel = newLevel;
        this.score = score;
    }

    public int getEventIndex() {
        return eventIndex;
    }

    public String getSessionId() {
        return sessionId;
    }

    public RiskLevel getOldLevel() {
        return oldLevel;
    }

    public RiskLevel getNewLevel() {
        return newLevel;
    }

    public int getScore() {
        return score;
    }

    @Override
    public String toString() {
        return String.format("Event #%d: %s %s -> %s (score %d)",
                eventIndex, sessionId, oldLevel, newLevel, score);
    }
}
