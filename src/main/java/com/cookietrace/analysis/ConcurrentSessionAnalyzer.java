package com.cookietrace.analysis;

import com.cookietrace.model.Alert;
import com.cookietrace.model.SessionEvent;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * ConcurrentSessionAnalyzer detects simultaneous or near-simultaneous usage of the same
 * session token from two distinct IP addresses within a tight time window (<= 60 seconds).
 *
 * Attack Vectors Targeted:
 * - Active Session Cloning / Cookie Replay: An active session is simultaneously used
 *   by both the legitimate user and an attacker on different network connections.
 * - Man-in-the-Middle (MitM) session duplication: The legitimate user continues browsing
 *   while the attacker sends concurrent automated or manual requests.
 */
public class ConcurrentSessionAnalyzer extends SecurityAnalyzer {

    /**
     * Constructs a ConcurrentSessionAnalyzer with a maximum risk score of 35.
     */
    public ConcurrentSessionAnalyzer() {
        super("ConcurrentSessionAnalyzer", 35);
    }

    @Override
    public List<Alert> analyze(List<SessionEvent> events) {
        List<Alert> alerts = new ArrayList<Alert>();
        Map<String, List<SessionEvent>> sessionMap = groupBySession(events);

        for (Map.Entry<String, List<SessionEvent>> entry : sessionMap.entrySet()) {
            String sessionId = entry.getKey();
            List<SessionEvent> sessionEvents = entry.getValue();

            // Need at least 2 events to detect concurrent usage
            if (sessionEvents.size() < 2) {
                continue;
            }

            boolean concurrentFound = false;
            String ip1 = "";
            String ip2 = "";
            long gapSeconds = 0;

            // Events are sorted chronologically. Check all pairs within the session.
            for (int i = 0; i < sessionEvents.size(); i++) {
                for (int j = i + 1; j < sessionEvents.size(); j++) {
                    SessionEvent e1 = sessionEvents.get(i);
                    SessionEvent e2 = sessionEvents.get(j);

                    long diff = Math.abs(Duration.between(e1.getEventTime(), e2.getEventTime()).getSeconds());

                    // Flag if different IPs appear within 60 seconds of each other
                    if (diff <= 60 && !e1.getIpAddress().equalsIgnoreCase(e2.getIpAddress())) {
                        concurrentFound = true;
                        ip1 = e1.getIpAddress();
                        ip2 = e2.getIpAddress();
                        gapSeconds = diff;
                        break;
                    }
                }
                if (concurrentFound) {
                    break;
                }
            }

            // Emit at most one Alert per flagged session
            if (concurrentFound) {
                String explanation = "The same session appeared from two different IP addresses (" + ip1 + " and " + ip2 +
                        ") within " + gapSeconds + " seconds. One session cannot normally be used from two networks " +
                        "at nearly the same time, so the session ID may have been copied.";
                String recommendation = "Invalidate the session and force login.";

                alerts.add(buildAlert(sessionId, 35, explanation, recommendation));
            }
        }

        return alerts;
    }
}
