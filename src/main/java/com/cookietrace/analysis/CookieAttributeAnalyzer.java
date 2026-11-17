package com.cookietrace.analysis;

import com.cookietrace.model.Alert;
import com.cookietrace.model.CookieInfo;
import com.cookietrace.model.SessionEvent;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * CookieAttributeAnalyzer checks for missing or misconfigured cookie security flags.
 *
 * Attacks Detected:
 * 1. Missing Secure flag: Allows session cookies to be transmitted over unencrypted HTTP,
 *    enabling network sniffers and Man-in-the-Middle (MitM) attackers to capture session tokens.
 * 2. Missing HttpOnly flag: Allows client-side JavaScript (e.g. document.cookie) to access
 *    the cookie, meaning any Cross-Site Scripting (XSS) vulnerability can hijack the session.
 * 3. SameSite=None: Cookies are sent along with third-party cross-site requests, leaving the
 *    application exposed to Cross-Site Request Forgery (CSRF).
 */
public class CookieAttributeAnalyzer extends SecurityAnalyzer {

    /**
     * Constructs a CookieAttributeAnalyzer with a max risk score of 30.
     */
    public CookieAttributeAnalyzer() {
        super("CookieAttributeAnalyzer", 30);
    }

    @Override
    public List<Alert> analyze(List<SessionEvent> events) {
        List<Alert> alerts = new ArrayList<Alert>();
        Map<String, List<SessionEvent>> sessionMap = groupBySession(events);

        for (Map.Entry<String, List<SessionEvent>> entry : sessionMap.entrySet()) {
            String sessionId = entry.getKey();
            List<SessionEvent> sessionEvents = entry.getValue();

            boolean missingSecure = false;
            boolean missingHttpOnly = false;
            boolean sameSiteNone = false;

            // Check cookie attributes across all events in this session
            for (SessionEvent event : sessionEvents) {
                CookieInfo cookie = event.getCookie();
                if (!cookie.isSecure()) {
                    missingSecure = true;
                }
                if (!cookie.isHttpOnly()) {
                    missingHttpOnly = true;
                }
                if ("None".equalsIgnoreCase(cookie.getSameSite())) {
                    sameSiteNone = true;
                }
            }

            int points = 0;
            List<String> issues = new ArrayList<String>();
            List<String> recommendations = new ArrayList<String>();

            if (missingSecure) {
                points += 10;
                issues.add("Secure flag missing: cookie can be sent over unencrypted connections and sniffed");
                recommendations.add("Secure=true");
            }
            if (missingHttpOnly) {
                points += 10;
                issues.add("HttpOnly missing: JavaScript can read the cookie, so cross-site scripting could steal it");
                recommendations.add("HttpOnly=true");
            }
            if (sameSiteNone) {
                points += 10;
                issues.add("SameSite None: cookie is sent on cross-site requests, which helps cross-site request forgery");
                recommendations.add("SameSite=Strict or Lax");
            }

            // If any cookie security issue was found, emit exactly one Alert for this session
            if (points > 0) {
                StringBuilder explanation = new StringBuilder("Cookie security vulnerability: ");
                for (int i = 0; i < issues.size(); i++) {
                    if (i > 0) {
                        explanation.append("; ");
                    }
                    explanation.append(issues.get(i));
                }

                StringBuilder rec = new StringBuilder("Configure session cookies with: ");
                for (int i = 0; i < recommendations.size(); i++) {
                    if (i > 0) {
                        rec.append(", ");
                    }
                    rec.append(recommendations.get(i));
                }

                alerts.add(buildAlert(sessionId, points, explanation.toString(), rec.toString()));
            }
        }

        return alerts;
    }
}
