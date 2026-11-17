package com.cookietrace.model;

import com.cookietrace.exception.InvalidSessionDataException;

/**
 * Represents a security threat alert raised when anomalous session behavior is detected.
 *
 * Encapsulation Design:
 * - All fields are 'private final' so an alert's details cannot be altered after creation.
 * - No setters are provided, guaranteeing that severity points, analyzer names, and explanations
 *   cannot be tampered with or accidentally wiped out.
 * - The constructor enforces strict validation rules so an invalid Alert instance can never exist.
 */
public class Alert {

    // Private final fields to enforce encapsulation
    private final String sessionId;
    private final String analyzerName;
    private final RiskLevel level;
    private final int points;
    private final String explanation;
    private final String recommendation;

    /**
     * Constructs and validates a threat Alert.
     *
     * @param sessionId      ID of the session triggering the alert
     * @param analyzerName   Name of the analyzer that detected the issue
     * @param level          Risk severity level (LOW, MEDIUM, HIGH)
     * @param points         Risk points between 0 and 100
     * @param explanation    Human-readable explanation of the threat
     * @param recommendation Recommended response action
     * @throws InvalidSessionDataException If any validation check fails
     */
    public Alert(String sessionId, String analyzerName, RiskLevel level, int points,
                 String explanation, String recommendation) {

        if (sessionId == null || sessionId.trim().isEmpty()) {
            throw new InvalidSessionDataException("sessionId cannot be null or blank.");
        }
        if (analyzerName == null || analyzerName.trim().isEmpty()) {
            throw new InvalidSessionDataException("analyzerName cannot be null or blank.");
        }
        if (level == null) {
            throw new InvalidSessionDataException("RiskLevel cannot be null.");
        }
        if (points < 0 || points > 100) {
            throw new InvalidSessionDataException(
                "Risk points must be between 0 and 100 inclusive. Received: " + points
            );
        }
        if (explanation == null || explanation.trim().isEmpty()) {
            throw new InvalidSessionDataException("explanation cannot be null or blank.");
        }
        if (recommendation == null || recommendation.trim().isEmpty()) {
            throw new InvalidSessionDataException("recommendation cannot be null or blank.");
        }

        this.sessionId = sessionId.trim();
        this.analyzerName = analyzerName.trim();
        this.level = level;
        this.points = points;
        this.explanation = explanation.trim();
        this.recommendation = recommendation.trim();
    }

    // Read-only getters

    public String getSessionId() {
        return sessionId;
    }

    public String getAnalyzerName() {
        return analyzerName;
    }

    public RiskLevel getLevel() {
        return level;
    }

    public int getPoints() {
        return points;
    }

    public String getExplanation() {
        return explanation;
    }

    public String getRecommendation() {
        return recommendation;
    }

    @Override
    public String toString() {
        return "Alert{" +
                "session='" + sessionId + '\'' +
                ", analyzer='" + analyzerName + '\'' +
                ", level=" + level +
                ", points=" + points +
                ", explanation='" + explanation + '\'' +
                ", recommendation='" + recommendation + '\'' +
                '}';
    }
}
