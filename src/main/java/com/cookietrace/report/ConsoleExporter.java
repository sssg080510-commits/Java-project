package com.cookietrace.report;

import com.cookietrace.engine.SessionRisk;
import com.cookietrace.model.Alert;
import com.cookietrace.model.RiskLevel;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Formats and renders session threat reports directly to standard terminal / console output.
 */
public class ConsoleExporter implements AlertExporter {

    @Override
    public String getFormatName() {
        return "Console";
    }

    @Override
    public String getFileExtension() {
        return null; // Signals direct terminal output
    }

    @Override
    public void export(List<SessionReport> reports, Writer out) throws IOException {
        PrintWriter pw = new PrintWriter(out);

        pw.println("================================================================================");
        pw.println("=== CookieTrace Security Report: Console Summary ===");
        pw.println("================================================================================");
        pw.printf("%-12s | %-12s | %-12s | %s%n", "Session ID", "Total Points", "Risk Level", "Cookie Grade");
        pw.println("--------------------------------------------------------------------------------");

        Map<RiskLevel, Integer> riskCounts = new EnumMap<RiskLevel, Integer>(RiskLevel.class);
        for (RiskLevel rl : RiskLevel.values()) {
            riskCounts.put(rl, 0);
        }

        Map<CookieGrade, Integer> gradeCounts = new EnumMap<CookieGrade, Integer>(CookieGrade.class);
        for (CookieGrade cg : CookieGrade.values()) {
            gradeCounts.put(cg, 0);
        }

        // 1. One-line summary for EVERY session
        for (SessionReport report : reports) {
            SessionRisk risk = report.getRisk();
            CookieGrade grade = report.getCookieGrade();

            pw.printf("%-12s | %-12d | %-12s | %s%n",
                    risk.getSessionId(),
                    risk.getTotalPoints(),
                    risk.getLevel(),
                    grade
            );

            riskCounts.put(risk.getLevel(), riskCounts.get(risk.getLevel()) + 1);
            gradeCounts.put(grade, gradeCounts.get(grade) + 1);
        }
        pw.println("================================================================================");

        // 2. Actionable threats breakdown for MEDIUM or HIGH sessions
        pw.println("\n=== Actionable Threat & Cookie Breakdown (MEDIUM / HIGH Sessions) ===");
        for (SessionReport report : reports) {
            SessionRisk risk = report.getRisk();
            if (risk.getLevel() == RiskLevel.MEDIUM || risk.getLevel() == RiskLevel.HIGH) {
                pw.println("--------------------------------------------------------------------------------");
                pw.println("Session: " + risk.getSessionId() +
                        " | Risk Score: " + risk.getTotalPoints() + "/100 (" + risk.getLevel() + ")" +
                        " | Cookie Grade: " + report.getCookieGrade());

                // Print Alerts
                if (!risk.getAlerts().isEmpty()) {
                    pw.println("  Alerts:");
                    for (Alert alert : risk.getAlerts()) {
                        pw.println("    * [" + alert.getAnalyzerName() + "] (" + alert.getPoints() + " pts): " + alert.getExplanation());
                        pw.println("        Recommendation: " + alert.getRecommendation());
                    }
                }

                // Print Cookie Fixes if grade is not A
                if (report.getCookieGrade() != CookieGrade.A) {
                    pw.println("  Cookie Remediation (Grade " + report.getCookieGrade() + "):");
                    if (report.getCookieFixes().isEmpty()) {
                        pw.println("    * None reported.");
                    } else {
                        for (String fix : report.getCookieFixes()) {
                            pw.println("    * " + fix);
                        }
                    }
                }
            }
        }
        pw.println("--------------------------------------------------------------------------------");

        // 3. Counts per Risk Level and Cookie Grade
        pw.println("\n=== Distribution Totals ===");
        pw.println("Risk Level Counts:");
        for (RiskLevel rl : RiskLevel.values()) {
            pw.println("  " + rl + ": " + riskCounts.get(rl));
        }

        pw.println("\nCookie Grade Counts:");
        for (CookieGrade cg : CookieGrade.values()) {
            pw.println("  Grade " + cg + ": " + gradeCounts.get(cg));
        }
        pw.println("================================================================================");

        pw.flush();
    }
}
