package com.cookietrace.report;

import com.cookietrace.engine.SessionRisk;
import com.cookietrace.exception.InvalidSessionDataException;
import com.cookietrace.model.SessionEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Immutable report model combining behavioral risk assessment with cookie hygiene grading.
 *
 * Encapsulation Design:
 * - All fields are private final.
 * - cookieFixes is wrapped in Collections.unmodifiableList.
 * - Constructor validates that all components are non-null.
 */
public class SessionReport {

    private final SessionRisk risk;
    private final CookieGrade cookieGrade;
    private final List<String> cookieFixes;

    /**
     * Constructs a validated, immutable SessionReport.
     *
     * @param risk        Consolidated SessionRisk from RiskEngine
     * @param cookieGrade Letter grade assigned by CookieGrader
     * @param cookieFixes Remediation recommendations for cookie vulnerabilities
     * @throws InvalidSessionDataException If any parameter is null
     */
    public SessionReport(SessionRisk risk, CookieGrade cookieGrade, List<String> cookieFixes) {
        if (risk == null) {
            throw new InvalidSessionDataException("SessionRisk cannot be null.");
        }
        if (cookieGrade == null) {
            throw new InvalidSessionDataException("CookieGrade cannot be null.");
        }
        if (cookieFixes == null) {
            throw new InvalidSessionDataException("cookieFixes list cannot be null.");
        }

        this.risk = risk;
        this.cookieGrade = cookieGrade;
        this.cookieFixes = Collections.unmodifiableList(new ArrayList<String>(cookieFixes));
    }

    public SessionRisk getRisk() {
        return risk;
    }

    public CookieGrade getCookieGrade() {
        return cookieGrade;
    }

    public List<String> getCookieFixes() {
        return cookieFixes;
    }

    /**
     * Static factory method combining engine risk evaluation with cookie grading results.
     *
     * @param risks  List of evaluated SessionRisk instances
     * @param events List of raw session events
     * @return List of consolidated SessionReport instances in the same order as risks
     * @throws InvalidSessionDataException If risks or events is null
     */
    public static List<SessionReport> build(List<SessionRisk> risks, List<SessionEvent> events) {
        if (risks == null || events == null) {
            throw new InvalidSessionDataException("risks and events lists cannot be null.");
        }

        CookieGrader grader = new CookieGrader();
        Map<String, CookieGrade> gradeMap = grader.gradeSessions(events);
        Map<String, List<String>> fixesMap = grader.fixesBySession(events);

        List<SessionReport> reports = new ArrayList<SessionReport>();
        for (SessionRisk risk : risks) {
            String sId = risk.getSessionId();
            CookieGrade grade = gradeMap.getOrDefault(sId, CookieGrade.A);
            List<String> fixes = fixesMap.getOrDefault(sId, Collections.emptyList());

            reports.add(new SessionReport(risk, grade, fixes));
        }

        return reports;
    }

    @Override
    public String toString() {
        return "SessionReport{" +
                "session='" + risk.getSessionId() + '\'' +
                ", totalPoints=" + risk.getTotalPoints() +
                ", level=" + risk.getLevel() +
                ", cookieGrade=" + cookieGrade +
                ", fixesCount=" + cookieFixes.size() +
                '}';
    }
}
