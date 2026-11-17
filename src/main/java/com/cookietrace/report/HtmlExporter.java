package com.cookietrace.report;

import com.cookietrace.engine.SessionRisk;
import com.cookietrace.model.Alert;
import com.cookietrace.model.RiskLevel;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Exports session threat and cookie security reports in standalone HTML format.
 *
 * Implements HTML generation with inline CSS, risk-based color coding,
 * and strict context-aware escaping for defensive security against XSS.
 */
public class HtmlExporter implements AlertExporter {

    @Override
    public String getFormatName() {
        return "HTML";
    }

    @Override
    public String getFileExtension() {
        return "html";
    }

    @Override
    public void export(List<SessionReport> reports, Writer out) throws IOException {
        PrintWriter pw = new PrintWriter(out);

        // Count totals per RiskLevel and CookieGrade
        Map<RiskLevel, Integer> riskCounts = new EnumMap<RiskLevel, Integer>(RiskLevel.class);
        for (RiskLevel rl : RiskLevel.values()) {
            riskCounts.put(rl, 0);
        }

        Map<CookieGrade, Integer> gradeCounts = new EnumMap<CookieGrade, Integer>(CookieGrade.class);
        for (CookieGrade cg : CookieGrade.values()) {
            gradeCounts.put(cg, 0);
        }

        if (reports != null) {
            for (SessionReport report : reports) {
                riskCounts.put(report.getRisk().getLevel(), riskCounts.get(report.getRisk().getLevel()) + 1);
                gradeCounts.put(report.getCookieGrade(), gradeCounts.get(report.getCookieGrade()) + 1);
            }
        }

        pw.println("<!DOCTYPE html>");
        pw.println("<html lang=\"en\">");
        pw.println("<head>");
        pw.println("  <meta charset=\"UTF-8\">");
        pw.println("  <title>CookieTrace Report</title>");
        pw.println("</head>");
        pw.println("<body style=\"font-family: Arial, sans-serif; margin: 24px; color: #333;\">");

        // Page Header
        pw.println("  <h1 style=\"color: #1a237e; border-bottom: 2px solid #1a237e; padding-bottom: 8px;\">CookieTrace Report</h1>");

        // Summary Line with counts per risk level and per cookie grade
        pw.println("  <p style=\"font-size: 15px; background-color: #f5f5f5; padding: 10px 14px; border-left: 4px solid #1a237e;\">");
        pw.print("    <strong>Summary:</strong> Risk Levels: ");
        pw.print("HIGH: " + riskCounts.get(RiskLevel.HIGH) + ", ");
        pw.print("MEDIUM: " + riskCounts.get(RiskLevel.MEDIUM) + ", ");
        pw.print("LOW: " + riskCounts.get(RiskLevel.LOW));
        pw.print(" &bull; Cookie Grades: ");
        pw.print("A: " + gradeCounts.get(CookieGrade.A) + ", ");
        pw.print("B: " + gradeCounts.get(CookieGrade.B) + ", ");
        pw.print("C: " + gradeCounts.get(CookieGrade.C) + ", ");
        pw.print("D: " + gradeCounts.get(CookieGrade.D) + ", ");
        pw.print("F: " + gradeCounts.get(CookieGrade.F));
        pw.println();
        pw.println("  </p>");

        // Table of all sessions
        pw.println("  <h2 style=\"color: #283593; margin-top: 24px;\">All Sessions</h2>");
        pw.println("  <table style=\"border-collapse: collapse; width: 100%; font-size: 14px;\">");
        pw.println("    <thead>");
        pw.println("      <tr style=\"background-color: #eeeeee; text-align: left;\">");
        pw.println("        <th style=\"border: 1px solid #ccc; padding: 8px;\">Session ID</th>");
        pw.println("        <th style=\"border: 1px solid #ccc; padding: 8px;\">Score</th>");
        pw.println("        <th style=\"border: 1px solid #ccc; padding: 8px;\">Level</th>");
        pw.println("        <th style=\"border: 1px solid #ccc; padding: 8px;\">Cookie Grade</th>");
        pw.println("        <th style=\"border: 1px solid #ccc; padding: 8px;\">Analyzers</th>");
        pw.println("      </tr>");
        pw.println("    </thead>");
        pw.println("    <tbody>");

        if (reports != null) {
            for (SessionReport report : reports) {
                SessionRisk risk = report.getRisk();
                RiskLevel level = risk.getLevel();

                // Determine row background color:
                // light red for HIGH, light orange for MEDIUM, light green for LOW
                String bgColor;
                if (level == RiskLevel.HIGH) {
                    bgColor = "#ffcccc"; // light red
                } else if (level == RiskLevel.MEDIUM) {
                    bgColor = "#ffe0b2"; // light orange
                } else {
                    bgColor = "#d4edda"; // light green
                }

                // Collect unique analyzer names
                Set<String> uniqueAnalyzers = new LinkedHashSet<String>();
                for (Alert alert : risk.getAlerts()) {
                    uniqueAnalyzers.add(alert.getAnalyzerName());
                }

                StringBuilder analyzersBuilder = new StringBuilder();
                int aCount = 0;
                for (String aName : uniqueAnalyzers) {
                    if (aCount > 0) {
                        analyzersBuilder.append("; ");
                    }
                    analyzersBuilder.append(escapeHtml(aName));
                    aCount++;
                }
                String analyzersStr = (aCount == 0) ? "None" : analyzersBuilder.toString();

                pw.println("      <tr style=\"background-color: " + bgColor + ";\">");
                pw.println("        <td style=\"border: 1px solid #ccc; padding: 8px;\">" + escapeHtml(risk.getSessionId()) + "</td>");
                pw.println("        <td style=\"border: 1px solid #ccc; padding: 8px;\">" + risk.getTotalPoints() + "</td>");
                pw.println("        <td style=\"border: 1px solid #ccc; padding: 8px;\">" + escapeHtml(level.name()) + "</td>");
                pw.println("        <td style=\"border: 1px solid #ccc; padding: 8px;\">" + escapeHtml(report.getCookieGrade().name()) + "</td>");
                pw.println("        <td style=\"border: 1px solid #ccc; padding: 8px;\">" + analyzersStr + "</td>");
                pw.println("      </tr>");
            }
        }

        pw.println("    </tbody>");
        pw.println("  </table>");

        // Section for each MEDIUM or HIGH session
        pw.println("  <h2 style=\"color: #283593; margin-top: 32px;\">Threat & Cookie Remediation Details (MEDIUM / HIGH Sessions)</h2>");

        if (reports != null) {
            for (SessionReport report : reports) {
                SessionRisk risk = report.getRisk();
                RiskLevel level = risk.getLevel();

                if (level == RiskLevel.MEDIUM || level == RiskLevel.HIGH) {
                    String borderColor = (level == RiskLevel.HIGH) ? "#d32f2f" : "#f57c00";
                    pw.println("  <div style=\"border: 1px solid " + borderColor + "; border-left: 6px solid " + borderColor + "; padding: 14px; margin-bottom: 18px; background-color: #fafafa;\">");
                    pw.println("    <h3 style=\"margin-top: 0; color: #111;\">Session: " + escapeHtml(risk.getSessionId())
                            + " &mdash; Risk Level: " + escapeHtml(level.name())
                            + " (Score: " + risk.getTotalPoints() + "/100)"
                            + " &mdash; Cookie Grade: " + escapeHtml(report.getCookieGrade().name()) + "</h3>");

                    // Alerts
                    pw.println("    <h4 style=\"margin-bottom: 6px;\">Security Alerts:</h4>");
                    if (risk.getAlerts().isEmpty()) {
                        pw.println("    <p style=\"margin-left: 16px; color: #666;\">No security alerts triggered.</p>");
                    } else {
                        pw.println("    <ul style=\"margin-top: 4px; padding-left: 24px;\">");
                        for (Alert alert : risk.getAlerts()) {
                            pw.println("      <li style=\"margin-bottom: 8px;\">");
                            pw.println("        <strong>[" + escapeHtml(alert.getAnalyzerName()) + "]</strong> ("
                                    + alert.getPoints() + " pts, " + escapeHtml(alert.getLevel().name()) + "): "
                                    + escapeHtml(alert.getExplanation()) + "<br>");
                            pw.println("        <em>Recommendation:</em> " + escapeHtml(alert.getRecommendation()));
                            pw.println("      </li>");
                        }
                        pw.println("    </ul>");
                    }

                    // Cookie Fixes
                    pw.println("    <h4 style=\"margin-bottom: 6px;\">Cookie Remediation Fixes:</h4>");
                    if (report.getCookieFixes().isEmpty()) {
                        pw.println("    <p style=\"margin-left: 16px; color: #666;\">No cookie configuration issues found.</p>");
                    } else {
                        pw.println("    <ul style=\"margin-top: 4px; padding-left: 24px;\">");
                        for (String fix : report.getCookieFixes()) {
                            pw.println("      <li style=\"margin-bottom: 4px;\">" + escapeHtml(fix) + "</li>");
                        }
                        pw.println("    </ul>");
                    }

                    pw.println("  </div>");
                }
            }
        }

        pw.println("</body>");
        pw.println("</html>");
        pw.flush();
    }

    /**
     * Replaces special HTML characters with corresponding HTML character entities.
     *
     * SECURITY COMMENT:
     * Escaping stops text in the data from being interpreted as HTML or script.
     * Web session logs often contain untrusted user-controlled input (e.g. crafted
     * User-Agent headers, session IDs, URLs, or parameter values). Without escaping,
     * an attacker could inject malicious markup or JavaScript (<script> tags), resulting
     * in a Cross-Site Scripting (XSS) attack when an analyst opens this report in a browser.
     *
     * @param input Raw text to escape
     * @return HTML-safe escaped text
     */
    private String escapeHtml(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '&':
                    sb.append("&amp;");
                    break;
                case '<':
                    sb.append("&lt;");
                    break;
                case '>':
                    sb.append("&gt;");
                    break;
                case '"':
                    sb.append("&quot;");
                    break;
                default:
                    sb.append(c);
                    break;
            }
        }
        return sb.toString();
    }
}
