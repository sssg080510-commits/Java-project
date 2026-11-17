package com.cookietrace.engine;

import com.cookietrace.exception.InvalidSessionDataException;
import com.cookietrace.model.Alert;
import com.cookietrace.model.RiskLevel;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Immutable data model representing the consolidated risk assessment for a web session.
 *
 * Encapsulation & Immutability Design:
 * - All fields are marked 'private final'.
 * - No setters are provided.
 * - The alerts list is defensive-copied and wrapped in Collections.unmodifiableList
 *   so external code cannot add or remove alerts after instantiation.
 */
public class SessionRisk {

    private final String sessionId;
    private final int rawPoints;
    private final int totalPoints;
    private final RiskLevel level;
    private final List<Alert> alerts;

    /**
     * Constructs and validates a SessionRisk instance.
     *
     * @param sessionId   Unique session ID
     * @param rawPoints   Sum of all alert risk points (can exceed 100)
     * @param totalPoints Consolidated risk score capped at 100 (0-100)
     * @param level       Risk severity classification (LOW, MEDIUM, HIGH)
     * @param alerts      List of alerts raised for this session
     * @throws InvalidSessionDataException If any validation constraint fails
     */
    public SessionRisk(String sessionId, int rawPoints, int totalPoints,
                       RiskLevel level, List<Alert> alerts) {

        if (sessionId == null || sessionId.trim().isEmpty()) {
            throw new InvalidSessionDataException("sessionId cannot be null or blank.");
        }
        if (rawPoints < 0) {
            throw new InvalidSessionDataException("rawPoints cannot be negative. Received: " + rawPoints);
        }
        if (totalPoints < 0) {
            throw new InvalidSessionDataException("totalPoints cannot be negative. Received: " + totalPoints);
        }
        if (level == null) {
            throw new InvalidSessionDataException("RiskLevel cannot be null.");
        }
        if (alerts == null) {
            throw new InvalidSessionDataException("Alerts list cannot be null.");
        }

        this.sessionId = sessionId.trim();
        this.rawPoints = rawPoints;
        this.totalPoints = totalPoints;
        this.level = level;
        // Defensive unmodifiable copy to guarantee immutability
        this.alerts = Collections.unmodifiableList(new ArrayList<Alert>(alerts));
    }

    public String getSessionId() {
        return sessionId;
    }

    public int getRawPoints() {
        return rawPoints;
    }

    public int getTotalPoints() {
        return totalPoints;
    }

    public RiskLevel getLevel() {
        return level;
    }

    public List<Alert> getAlerts() {
        return alerts;
    }

    @Override
    public String toString() {
        return "SessionRisk{" +
                "sessionId='" + sessionId + '\'' +
                ", rawPoints=" + rawPoints +
                ", totalPoints=" + totalPoints +
                ", level=" + level +
                ", alertsCount=" + alerts.size() +
                '}';
    }
}
