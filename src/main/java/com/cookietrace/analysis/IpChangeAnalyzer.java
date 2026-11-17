package com.cookietrace.analysis;

import com.cookietrace.model.Alert;
import com.cookietrace.model.SessionEvent;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * IpChangeAnalyzer monitors sessions for IP address shifts between consecutive requests.
 *
 * Attack Vectors Targeted:
 * - Session Hijacking / Man-in-the-Middle: An attacker steals an active session cookie
 *   and sends requests from a different machine or geographic location.
 * - Credential / Cookie Replay: A stolen session token is used concurrently or sequentially
 *   from an unauthorized network.
 *
 * Note on False Positives:
 * - IP changes are not always malicious; mobile devices frequently rotate IP addresses
 *   when moving between cellular towers or switching to Wi-Fi, and users may toggle VPNs.
 */
public class IpChangeAnalyzer extends SecurityAnalyzer {

    /**
     * Constructs an IpChangeAnalyzer with a max risk score of 25.
     */
    public IpChangeAnalyzer() {
        super("IpChangeAnalyzer", 25);
    }

    @Override
    public List<Alert> analyze(List<SessionEvent> events) {
        List<Alert> alerts = new ArrayList<Alert>();
        Map<String, List<SessionEvent>> sessionMap = groupBySession(events);

        for (Map.Entry<String, List<SessionEvent>> entry : sessionMap.entrySet()) {
            String sessionId = entry.getKey();
            List<SessionEvent> sessionEvents = entry.getValue();

            // Need at least 2 events to compare consecutive requests
            if (sessionEvents.size() < 2) {
                continue;
            }

            boolean ipChanged = false;
            boolean countryChanged = false;
            String oldIp = "";
            String newIp = "";
            String oldCountry = "";
            String newCountry = "";

            for (int i = 0; i < sessionEvents.size() - 1; i++) {
                SessionEvent current = sessionEvents.get(i);
                SessionEvent next = sessionEvents.get(i + 1);

                if (!current.getIpAddress().equalsIgnoreCase(next.getIpAddress())) {
                    ipChanged = true;
                    oldIp = current.getIpAddress();
                    newIp = next.getIpAddress();
                    oldCountry = current.getCountry();
                    newCountry = next.getCountry();

                    // Check if country also changed
                    if (!current.getCountry().equalsIgnoreCase(next.getCountry())) {
                        countryChanged = true;
                        // Prioritize reporting the country-level jump
                        break;
                    }
                }
            }

            // If an IP change was detected in this session, build exactly one Alert
            if (ipChanged) {
                int points = countryChanged ? 25 : 15;

                String explanation = "IP change detected: previous IP " + oldIp + " (" + oldCountry + ") " +
                        "changed to new IP " + newIp + " (" + newCountry + "). " +
                        "Note: IP changes can have innocent causes (mobile network, VPN).";

                String recommendation = "Verify with the user or require re-authentication.";

                alerts.add(buildAlert(sessionId, points, explanation, recommendation));
            }
        }

        return alerts;
    }
}
