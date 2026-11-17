package com.cookietrace.simulation;

import com.cookietrace.model.Alert;
import com.cookietrace.model.RiskLevel;
import com.cookietrace.model.SessionEvent;

/**
 * Standard console-based listener rendering live simulation events, alerts, and escalations.
 *
 * Uses plain text formatting without ANSI colour codes for broad compatibility with Windows terminals.
 */
public class ConsoleSimulationListener implements SimulationListener {

    private int escalationCount = 0;

    @Override
    public void onEvent(SessionEvent event, int index, int total) {
        // One short line: [index/total] sessionId | city | ip (no extra detail)
        System.out.printf("[%d/%d] %s | %s | %s%n",
                index, total, event.getSessionId(), event.getCity(), event.getIpAddress());
    }

    @Override
    public void onNewAlert(Alert alert, int index) {
        // Indented line starting with "   ALERT" showing analyzer, points and plain-language explanation
        System.out.println("   ALERT [" + alert.getAnalyzerName() + "] (" + alert.getPoints() + " pts): " + alert.getExplanation());
    }

    @Override
    public void onEscalation(String sessionId, RiskLevel oldLevel, RiskLevel newLevel, int newScore, int index) {
        escalationCount++;
        // Clearly marked escalation notification
        System.out.printf("*** ESCALATION: %s %s -> %s (score %d) at event %d ***%n",
                sessionId, oldLevel, newLevel, newScore, index);
    }

    /**
     * Returns the total number of risk level escalations observed during the simulation.
     *
     * @return Count of escalation notifications emitted
     */
    public int getEscalationCount() {
        return escalationCount;
    }
}
