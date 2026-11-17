package com.cookietrace.simulation;

import com.cookietrace.engine.RiskEngine;
import com.cookietrace.engine.SessionRisk;
import com.cookietrace.exception.InvalidSessionDataException;
import com.cookietrace.model.Alert;
import com.cookietrace.model.RiskLevel;
import com.cookietrace.model.SessionEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * live mode uses rule analyzers only, because Isolation Forest needs the whole dataset
 * to learn what normal is; time is compressed (one event per delayMillis) but analyzers
 * use the events' own timestamps.
 *
 * LiveSimulator streams session events sequentially in chronological order, simulating
 * a real-time Security Operations Center (SOC) monitoring feed. As each event arrives,
 * it dynamically updates the session's historical timeline, re-evaluates risk, emits newly
 * detected alerts, and notifies listeners of risk level escalations.
 */
public class LiveSimulator {

    private final RiskEngine engine;
    private final SimulationListener listener;
    private final long delayMillis;

    // Stores per-session state (events seen so far, alerts already emitted, current risk level, and latest risk)
    private final Map<String, SessionState> sessionStates = new LinkedHashMap<String, SessionState>();

    /**
     * Constructs a LiveSimulator instance.
     *
     * @param engine      RiskEngine instance configured with rule-based analyzers
     * @param listener    Observer listening to simulation events, alerts, and escalations
     * @param delayMillis Delay between successive events in milliseconds (0 to 5000)
     * @throws InvalidSessionDataException If engine or listener is null, or delayMillis is outside [0, 5000]
     */
    public LiveSimulator(RiskEngine engine, SimulationListener listener, long delayMillis) {
        if (engine == null) {
            throw new InvalidSessionDataException("RiskEngine cannot be null.");
        }
        if (listener == null) {
            throw new InvalidSessionDataException("SimulationListener cannot be null.");
        }
        if (delayMillis < 0 || delayMillis > 5000) {
            throw new InvalidSessionDataException("delayMillis must be between 0 and 5000 ms, got: " + delayMillis);
        }

        this.engine = engine;
        this.listener = listener;
        this.delayMillis = delayMillis;
    }

    /**
     * Streams events one by one in chronological order, evaluating risk progressively.
     *
     * @param events List of raw session events to stream
     */
    public void run(List<SessionEvent> events) {
        sessionStates.clear();

        if (events == null || events.isEmpty()) {
            return;
        }

        // 1. Sort a defensive copy of the events chronologically by eventTime
        List<SessionEvent> sortedEvents = new ArrayList<SessionEvent>(events);
        Collections.sort(sortedEvents, new Comparator<SessionEvent>() {
            @Override
            public int compare(SessionEvent e1, SessionEvent e2) {
                return e1.getEventTime().compareTo(e2.getEventTime());
            }
        });

        int total = sortedEvents.size();

        // 2. Process events sequentially
        for (int i = 0; i < total; i++) {
            int index = i + 1;
            SessionEvent event = sortedEvents.get(i);
            String sessionId = event.getSessionId();

            // Locate or initialize the session's cumulative state
            SessionState state = sessionStates.get(sessionId);
            if (state == null) {
                state = new SessionState(sessionId);
                sessionStates.put(sessionId, state);
            }

            // (a) Add event to that session's own list
            state.events.add(event);

            // (b) Notify listener of the newly arrived event
            listener.onEvent(event, index, total);

            // (c) Evaluate risk with ONLY that session's events seen so far
            List<SessionRisk> risks = engine.evaluate(state.events);
            if (risks == null || risks.isEmpty()) {
                continue;
            }
            SessionRisk currentRisk = risks.get(0);

            // (d) Emit alerts not reported before for this session (same analyzer name and same points)
            for (Alert alert : currentRisk.getAlerts()) {
                String alertKey = alert.getAnalyzerName() + "#" + alert.getPoints();
                if (!state.reportedAlertKeys.contains(alertKey)) {
                    state.reportedAlertKeys.add(alertKey);
                    listener.onNewAlert(alert, index);
                }
            }

            // (e) Check for risk tier escalation: new sessions start as LOW
            RiskLevel newLevel = currentRisk.getLevel();
            int newScore = currentRisk.getTotalPoints();
            if (newLevel.ordinal() > state.currentLevel.ordinal()) {
                RiskLevel oldLevel = state.currentLevel;
                state.currentLevel = newLevel;
                listener.onEscalation(sessionId, oldLevel, newLevel, newScore, index);
            }

            // (f) Remember the latest SessionRisk state
            state.lastRisk = currentRisk;

            // (g) Pause for the configured delay to simulate real-time arrival
            if (delayMillis > 0) {
                try {
                    Thread.sleep(delayMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt(); // Restore interrupted status
                    break;                              // Terminate streaming loop cleanly
                }
            }
        }
    }

    /**
     * Returns an unmodifiable map containing the final evaluated SessionRisk for each session.
     *
     * @return Map of sessionId to its final SessionRisk
     */
    public Map<String, SessionRisk> getFinalRisks() {
        Map<String, SessionRisk> finalRisks = new LinkedHashMap<String, SessionRisk>();
        for (Map.Entry<String, SessionState> entry : sessionStates.entrySet()) {
            finalRisks.put(entry.getKey(), entry.getValue().lastRisk);
        }
        return Collections.unmodifiableMap(finalRisks);
    }

    /**
     * Private inner class maintaining state for each session across streaming events.
     */
    private static class SessionState {
        private final String sessionId;
        private final List<SessionEvent> events = new ArrayList<SessionEvent>();
        private final Set<String> reportedAlertKeys = new HashSet<String>();
        private RiskLevel currentLevel = RiskLevel.LOW; // All sessions start at LOW
        private SessionRisk lastRisk;

        public SessionState(String sessionId) {
            this.sessionId = sessionId;
        }
    }
}
