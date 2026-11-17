package com.cookietrace.analysis;

import com.cookietrace.model.Alert;
import com.cookietrace.model.SessionEvent;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * UserAgentAnalyzer checks whether the client's browser identity changes within a session.
 *
 * Attack Vectors Targeted:
 * - Session Hijacking / Cookie Theft: An attacker steals a session cookie from a victim
 *   (e.g., using Chrome on Windows) and uses it from their own device (e.g., Firefox on Linux).
 * - Multi-Device Token Sharing: Unauthorized sharing of session tokens between different browsers.
 *
 * Innocent Causes:
 * - A browser automatic update mid-session or mobile browser desktop-mode toggle can alter
 *   the User-Agent string.
 */
public class UserAgentAnalyzer extends SecurityAnalyzer {

    /**
     * Constructs a UserAgentAnalyzer with a maximum risk score of 20.
     */
    public UserAgentAnalyzer() {
        super("UserAgentAnalyzer", 20);
    }

    @Override
    public List<Alert> analyze(List<SessionEvent> events) {
        List<Alert> alerts = new ArrayList<Alert>();
        Map<String, List<SessionEvent>> sessionMap = groupBySession(events);

        for (Map.Entry<String, List<SessionEvent>> entry : sessionMap.entrySet()) {
            String sessionId = entry.getKey();
            List<SessionEvent> sessionEvents = entry.getValue();

            // Need at least 2 events to compare user agents
            if (sessionEvents.size() < 2) {
                continue;
            }

            boolean uaChanged = false;
            String oldUa = "";
            String newUa = "";

            for (int i = 0; i < sessionEvents.size() - 1; i++) {
                SessionEvent current = sessionEvents.get(i);
                SessionEvent next = sessionEvents.get(i + 1);

                if (!current.getUserAgent().equals(next.getUserAgent())) {
                    uaChanged = true;
                    oldUa = current.getUserAgent();
                    newUa = next.getUserAgent();
                    break;
                }
            }

            // If user agent changed, emit exactly one Alert for this session
            if (uaChanged) {
                String explanation = "The browser identity changed mid-session from '" + oldUa + "' to '" + newUa +
                        "', which may mean the cookie is being used from another device; can also be an innocent browser update.";
                String recommendation = "Re-authenticate the session.";

                alerts.add(buildAlert(sessionId, 20, explanation, recommendation));
            }
        }

        return alerts;
    }
}
