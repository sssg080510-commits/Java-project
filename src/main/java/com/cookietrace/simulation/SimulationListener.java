package com.cookietrace.simulation;

import com.cookietrace.model.Alert;
import com.cookietrace.model.RiskLevel;
import com.cookietrace.model.SessionEvent;

/**
 * Listener interface for streaming event simulation.
 *
 * Implements the Observer pattern:
 * Decouples the live event simulation loop from output presentation (console, logs, dashboard).
 */
public interface SimulationListener {

    /**
     * Called when a new session event is ingested into the simulation.
     *
     * @param event The session event observed
     * @param index 1-based sequential index of the event
     * @param total Total number of events in the simulation
     */
    void onEvent(SessionEvent event, int index, int total);

    /**
     * Called when an analyzer detects a new, previously unreported threat alert for a session.
     *
     * @param alert The newly raised alert
     * @param index 1-based sequential index of the current event
     */
    void onNewAlert(Alert alert, int index);

    /**
     * Called when a session's cumulative risk level escalates to a higher tier (e.g. LOW to MEDIUM, MEDIUM to HIGH).
     *
     * @param sessionId The session identifier
     * @param oldLevel  The previous risk level
     * @param newLevel  The escalated risk level
     * @param newScore  The updated cumulative risk score (capped at 100)
     * @param index     1-based sequential index of the current event
     */
    void onEscalation(String sessionId, RiskLevel oldLevel, RiskLevel newLevel, int newScore, int index);
}
