package com.cookietrace.report;

import com.cookietrace.model.CookieInfo;
import com.cookietrace.model.SessionEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * CookieGrader evaluates the security attributes of HTTP session cookies and assigns letter grades.
 *
 * Scoring Rubric (Max 100 points):
 * - Secure flag present:    +40 points
 * - HttpOnly flag present:  +30 points
 * - SameSite attribute:     +30 (Strict), +20 (Lax), +0 (None)
 */
public class CookieGrader {

    /**
     * Calculates the numerical security score of a cookie (0 to 100).
     *
     * @param cookie The cookie to score
     * @return Score between 0 and 100
     */
    public int score(CookieInfo cookie) {
        if (cookie == null) {
            return 0;
        }

        int score = 0;
        if (cookie.isSecure()) {
            score += 40;
        }
        if (cookie.isHttpOnly()) {
            score += 30;
        }

        String sameSite = cookie.getSameSite();
        if ("Strict".equalsIgnoreCase(sameSite)) {
            score += 30;
        } else if ("Lax".equalsIgnoreCase(sameSite)) {
            score += 20;
        }
        // "None" gives 0 points

        return score;
    }

    /**
     * Assigns a CookieGrade letter grade based on the calculated security score.
     *
     * @param cookie The cookie to grade
     * @return A (>=90), B (>=70), C (>=50), D (>=30), or F (<30)
     */
    public CookieGrade grade(CookieInfo cookie) {
        int s = score(cookie);
        if (s >= 90) {
            return CookieGrade.A;
        } else if (s >= 70) {
            return CookieGrade.B;
        } else if (s >= 50) {
            return CookieGrade.C;
        } else if (s >= 30) {
            return CookieGrade.D;
        } else {
            return CookieGrade.F;
        }
    }

    /**
     * Produces plain-English remediation advice for any missing cookie security flags.
     *
     * @param cookie The cookie to inspect
     * @return List of actionable recommendation sentences (empty if fully secure)
     */
    public List<String> recommendations(CookieInfo cookie) {
        List<String> recs = new ArrayList<String>();
        if (cookie == null) {
            return recs;
        }

        if (!cookie.isSecure()) {
            recs.add("Enable the Secure flag so the cookie only travels over HTTPS and cannot be sniffed.");
        }
        if (!cookie.isHttpOnly()) {
            recs.add("Enable the HttpOnly flag so JavaScript cannot read the cookie, which limits theft by cross-site scripting.");
        }
        if ("None".equalsIgnoreCase(cookie.getSameSite())) {
            recs.add("Set SameSite to Strict or Lax so other sites cannot trigger requests with the cookie.");
        }

        return recs;
    }

    /**
     * Determines the WORST cookie security grade observed across all events in each session.
     * (e.g., if a session has events with Grade A and Grade F, the session receives Grade F).
     *
     * @param events List of raw session events
     * @return Map of sessionId to worst CookieGrade
     */
    public Map<String, CookieGrade> gradeSessions(List<SessionEvent> events) {
        Map<String, CookieGrade> sessionGrades = new LinkedHashMap<String, CookieGrade>();
        if (events == null) {
            return sessionGrades;
        }

        for (SessionEvent event : events) {
            String sId = event.getSessionId();
            CookieGrade eventGrade = grade(event.getCookie());

            if (!sessionGrades.containsKey(sId)) {
                sessionGrades.put(sId, eventGrade);
            } else {
                CookieGrade currentWorst = sessionGrades.get(sId);
                // In CookieGrade enum: A=0, B=1, C=2, D=3, F=4 (higher ordinal = worse grade)
                if (eventGrade.ordinal() > currentWorst.ordinal()) {
                    sessionGrades.put(sId, eventGrade);
                }
            }
        }

        return sessionGrades;
    }

    /**
     * Determines the cookie remediation advice for the WORST cookie of each session, removing duplicates.
     *
     * @param events List of raw session events
     * @return Map of sessionId to unique recommendations list
     */
    public Map<String, List<String>> fixesBySession(List<SessionEvent> events) {
        Map<String, List<String>> sessionFixes = new LinkedHashMap<String, List<String>>();
        if (events == null) {
            return sessionFixes;
        }

        // Track the lowest score cookie for each session
        Map<String, Integer> lowestScores = new LinkedHashMap<String, Integer>();
        Map<String, Set<String>> fixesSets = new LinkedHashMap<String, Set<String>>();

        for (SessionEvent event : events) {
            String sId = event.getSessionId();
            CookieInfo cookie = event.getCookie();
            int currentScore = score(cookie);

            if (!lowestScores.containsKey(sId) || currentScore < lowestScores.get(sId)) {
                lowestScores.put(sId, currentScore);
                Set<String> recSet = new LinkedHashSet<String>(recommendations(cookie));
                fixesSets.put(sId, recSet);
            } else if (currentScore == lowestScores.get(sId)) {
                // Same worst score: merge recommendations without duplicates
                fixesSets.get(sId).addAll(recommendations(cookie));
            }
        }

        for (Map.Entry<String, Set<String>> entry : fixesSets.entrySet()) {
            sessionFixes.put(entry.getKey(), new ArrayList<String>(entry.getValue()));
        }

        return sessionFixes;
    }
}
