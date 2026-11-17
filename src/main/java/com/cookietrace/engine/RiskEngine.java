package com.cookietrace.engine;

import com.cookietrace.analysis.SecurityAnalyzer;
import com.cookietrace.exception.InvalidSessionDataException;
import com.cookietrace.model.Alert;
import com.cookietrace.model.RiskLevel;
import com.cookietrace.model.SessionEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * RiskEngine consolidates threat detection results across multiple analyzers into unified session risk profiles.
 *
 * OOP Concept - Polymorphism in Action:
 * - RiskEngine is completely decoupled from concrete analyzer classes.
 * - It stores and interacts with all analyzers exclusively through the abstract base class reference 'SecurityAnalyzer'.
 * - It does not check types (no 'instanceof') and does not use type casting.
 * - Whether an analyzer uses deterministic rules (e.g. CookieAttributeAnalyzer) or statistical machine
 *   learning (e.g. AnomalyAnalyzer), RiskEngine calls analyzer.analyze(events) identically!
 * - This adheres to the Open-Closed Principle: new analyzers can be introduced without modifying a single line of RiskEngine.
 */
public class RiskEngine {

    // Threshold constants for risk scoring and tier categorization
    public static final int MAX_SCORE = 100;
    public static final int MEDIUM_THRESHOLD = 30;
    public static final int HIGH_THRESHOLD = 60;

    private final List<SecurityAnalyzer> analyzers;

    /**
     * Constructs a RiskEngine configured with a list of security analyzers.
     *
     * @param analyzers List of SecurityAnalyzer instances to run
     * @throws InvalidSessionDataException If the analyzers list is null or empty
     */
    public RiskEngine(List<SecurityAnalyzer> analyzers) {
        if (analyzers == null || analyzers.isEmpty()) {
            throw new InvalidSessionDataException("Analyzers list cannot be null or empty.");
        }
        // Defensive copy of the analyzer list
        this.analyzers = new ArrayList<SecurityAnalyzer>(analyzers);
    }

    /**
     * Returns the descriptive names of all configured analyzers in registration order.
     *
     * @return List of analyzer names
     */
    public List<String> getAnalyzerNames() {
        List<String> names = new ArrayList<String>();
        for (SecurityAnalyzer analyzer : analyzers) {
            names.add(analyzer.getName());
        }
        return names;
    }

    /**
     * Evaluates all sessions found in the event stream across every configured analyzer.
     *
     * @param events List of raw session events
     * @return List of SessionRisk assessments sorted by totalPoints descending (ties broken by sessionId)
     */
    public List<SessionRisk> evaluate(List<SessionEvent> events) {
        // 1. Identify all unique session IDs across the dataset
        // Using LinkedHashSet ensures we preserve the first-seen session order
        Set<String> allSessionIds = new LinkedHashSet<String>();
        if (events != null) {
            for (SessionEvent event : events) {
                allSessionIds.add(event.getSessionId());
            }
        }

        // Initialize empty alert buckets for EVERY session (including sessions that generate 0 alerts)
        Map<String, List<Alert>> alertsBySession = new LinkedHashMap<String, List<Alert>>();
        for (String sId : allSessionIds) {
            alertsBySession.put(sId, new ArrayList<Alert>());
        }

        // -------------------------------------------------------------
        // Polymorphism:
        // We invoke .analyze(events) on each element of List<SecurityAnalyzer>.
        // Java's virtual method dispatch routes each call to the appropriate
        // concrete implementation at runtime without any instanceof checks.
        // -------------------------------------------------------------
        for (SecurityAnalyzer analyzer : analyzers) {
            List<Alert> generatedAlerts = analyzer.analyze(events);
            if (generatedAlerts != null) {
                for (Alert alert : generatedAlerts) {
                    String sId = alert.getSessionId();
                    if (!alertsBySession.containsKey(sId)) {
                        alertsBySession.put(sId, new ArrayList<Alert>());
                    }
                    alertsBySession.get(sId).add(alert);
                }
            }
        }

        // 2. Compute risk scores and risk level tiers for each session
        List<SessionRisk> results = new ArrayList<SessionRisk>();

        for (String sId : allSessionIds) {
            List<Alert> sessionAlerts = alertsBySession.get(sId);

            int rawPoints = 0;
            for (Alert alert : sessionAlerts) {
                rawPoints += alert.getPoints();
            }

            // Cap risk score at 100 points
            int totalPoints = Math.min(rawPoints, MAX_SCORE);

            // Determine RiskLevel tier
            RiskLevel level;
            if (totalPoints < MEDIUM_THRESHOLD) {
                level = RiskLevel.LOW;
            } else if (totalPoints < HIGH_THRESHOLD) {
                level = RiskLevel.MEDIUM;
            } else {
                level = RiskLevel.HIGH;
            }

            results.add(new SessionRisk(sId, rawPoints, totalPoints, level, sessionAlerts));
        }

        // 3. Sort results: totalPoints descending, ties by sessionId ascending
        Collections.sort(results, new Comparator<SessionRisk>() {
            @Override
            public int compare(SessionRisk r1, SessionRisk r2) {
                int cmp = Integer.compare(r2.getTotalPoints(), r1.getTotalPoints());
                if (cmp != 0) {
                    return cmp;
                }
                return r1.getSessionId().compareTo(r2.getSessionId());
            }
        });

        return results;
    }
}
