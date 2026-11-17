package com.cookietrace.dashboard;

import com.cookietrace.model.Alert;
import com.cookietrace.model.RiskLevel;
import com.cookietrace.model.SessionEvent;
import com.cookietrace.simulation.SimulationListener;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Implementation of SimulationListener that silently captures escalation events into a timeline list.
 *
 * It performs no console output, making it ideal for automated tests, programmatic simulation,
 * and populating visual dashboard timelines.
 */
public class RecordingSimulationListener implements SimulationListener {

    private final List<TimelineEntry> timeline = new ArrayList<TimelineEntry>();

    @Override
    public void onEvent(SessionEvent event, int index, int total) {
        // Silent observer: no-op
    }

    @Override
    public void onNewAlert(Alert alert, int index) {
        // Silent observer: no-op
    }

    @Override
    public void onEscalation(String sessionId, RiskLevel oldLevel, RiskLevel newLevel, int newScore, int index) {
        // Records the escalation into the timeline
        timeline.add(new TimelineEntry(index, sessionId, oldLevel, newLevel, newScore));
    }

    /**
     * Returns an unmodifiable copy of the captured escalation timeline.
     *
     * @return List of recorded TimelineEntry objects
     */
    public List<TimelineEntry> getTimeline() {
        return Collections.unmodifiableList(new ArrayList<TimelineEntry>(timeline));
    }
}
