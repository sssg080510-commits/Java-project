package com.cookietrace.analysis;

import com.cookietrace.exception.InvalidSessionDataException;
import com.cookietrace.model.Alert;
import com.cookietrace.model.RiskLevel;
import com.cookietrace.model.SessionEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Abstract base class for all security threat analyzers in CookieTrace.
 *
 * OOP Concept - Abstraction:
 * - This class defines the common contract (analyze method) and shared utility logic
 *   (groupBySession, buildAlert) that every concrete analyzer needs.
 * - Callers interact with this abstract type without needing to know specific detection algorithms.
 *
 * OOP Concept - Inheritance:
 * - Subclasses (CookieAttributeAnalyzer, IpChangeAnalyzer) inherit common fields (name, maxPoints)
 *   and helper methods, eliminating repetitive boilerplate code across analyzers.
 */
public abstract class SecurityAnalyzer {

    // Common properties shared by all analyzers (encapsulated)
    private final String name;
    private final int maxPoints;

    /**
     * Constructs and validates a SecurityAnalyzer.
     *
     * @param name      Descriptive name of the analyzer
     * @param maxPoints Maximum risk score this analyzer can assign (1 to 100)
     * @throws InvalidSessionDataException If name is blank or maxPoints is outside 1-100
     */
    public SecurityAnalyzer(String name, int maxPoints) {
        if (name == null || name.trim().isEmpty()) {
            throw new InvalidSessionDataException("Analyzer name cannot be null or blank.");
        }
        if (maxPoints < 1 || maxPoints > 100) {
            throw new InvalidSessionDataException(
                "maxPoints must be between 1 and 100 inclusive. Received: " + maxPoints
            );
        }

        this.name = name.trim();
        this.maxPoints = maxPoints;
    }

    public String getName() {
        return name;
    }

    public int getMaxPoints() {
        return maxPoints;
    }

    /**
     * Analyzes session events and produces threat alerts.
     * Overridden by each specialized subclass (Polymorphism).
     *
     * @param events List of raw session events to analyze
     * @return List of generated threat alerts
     */
    public abstract List<Alert> analyze(List<SessionEvent> events);

    /**
     * Helper method to partition events by sessionId while preserving first-seen order.
     * Each session's events are sorted chronologically by eventTime.
     *
     * @param events All session events
     * @return Map where key is sessionId and value is chronologically sorted events
     */
    protected Map<String, List<SessionEvent>> groupBySession(List<SessionEvent> events) {
        // LinkedHashMap preserves the insertion (first-seen) order of sessions
        Map<String, List<SessionEvent>> sessionMap = new LinkedHashMap<String, List<SessionEvent>>();

        if (events == null) {
            return sessionMap;
        }

        for (SessionEvent event : events) {
            String sId = event.getSessionId();
            if (!sessionMap.containsKey(sId)) {
                sessionMap.put(sId, new ArrayList<SessionEvent>());
            }
            sessionMap.get(sId).add(event);
        }

        // Sort each session's event list chronologically
        for (List<SessionEvent> sessionEvents : sessionMap.values()) {
            Collections.sort(sessionEvents, new Comparator<SessionEvent>() {
                @Override
                public int compare(SessionEvent e1, SessionEvent e2) {
                    return e1.getEventTime().compareTo(e2.getEventTime());
                }
            });
        }

        return sessionMap;
    }

    /**
     * Helper method to construct a validated Alert object.
     * Automatically caps points at maxPoints and computes the appropriate RiskLevel.
     *
     * @param sessionId      ID of the offending session
     * @param points         Raw risk points calculated by the analyzer
     * @param explanation    Human-readable explanation of why the threat was flagged
     * @param recommendation Actionable security advice
     * @return A fully populated Alert instance
     */
    protected Alert buildAlert(String sessionId, int points, String explanation, String recommendation) {
        // Cap points at maxPoints (and ensure not negative)
        int cappedPoints = Math.min(points, this.maxPoints);
        if (cappedPoints < 0) {
            cappedPoints = 0;
        }

        // Calculate severity ratio: points / maxPoints
        double ratio = (double) cappedPoints / (double) this.maxPoints;
        RiskLevel level;
        if (ratio < 0.4) {
            level = RiskLevel.LOW;
        } else if (ratio < 0.7) {
            level = RiskLevel.MEDIUM;
        } else {
            level = RiskLevel.HIGH;
        }

        return new Alert(sessionId, this.name, level, cappedPoints, explanation, recommendation);
    }
}
