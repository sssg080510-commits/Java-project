package com.cookietrace.dashboard;

import com.cookietrace.engine.SessionRisk;
import com.cookietrace.model.Alert;
import com.cookietrace.model.RiskLevel;
import com.cookietrace.report.CookieGrade;
import com.cookietrace.report.SessionReport;
import com.cookietrace.storage.RunSummary;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Generates a self-contained, standalone HTML dashboard summarizing session security analysis,
 * audit history, and live simulation timeline.
 *
 * Design constraints:
 * - Pure HTML5 and inline CSS only.
 * - Zero JavaScript, no external fonts, no external network images.
 * - Strict context-aware HTML escaping to prevent Cross-Site Scripting (XSS).
 */
public class DashboardGenerator {

    /**
     * Renders and exports the dashboard HTML document to the specified destination.
     *
     * @param reports    Current evaluated session reports
     * @param history    Historical run summaries from SQLite database
     * @param timeline   Recorded live escalation events
     * @param outputFile Destination file path
     * @throws IOException If file creation or writing fails
     */
    public void generate(List<SessionReport> reports, List<RunSummary> history,
                         List<TimelineEntry> timeline, Path outputFile) throws IOException {

        if (outputFile.getParent() != null) {
            Files.createDirectories(outputFile.getParent());
        }

        // 1. Calculate aggregated summary metrics
        int totalSessions = (reports == null) ? 0 : reports.size();
        int highCount = 0;
        int medCount = 0;
        int lowCount = 0;
        int weakCookiesCount = 0;

        if (reports != null) {
            for (SessionReport r : reports) {
                RiskLevel lvl = r.getRisk().getLevel();
                if (lvl == RiskLevel.HIGH) {
                    highCount++;
                } else if (lvl == RiskLevel.MEDIUM) {
                    medCount++;
                } else if (lvl == RiskLevel.LOW) {
                    lowCount++;
                }

                CookieGrade g = r.getCookieGrade();
                if (g == CookieGrade.F || g == CookieGrade.D || g == CookieGrade.C) {
                    weakCookiesCount++;
                }
            }
        }

        String lastRunTime = (history != null && !history.isEmpty()) ? history.get(0).getRunTime() : "N/A";

        // 2. Sort reports by totalPoints descending (ties broken by sessionId ascending)
        List<SessionReport> sortedReports = new ArrayList<SessionReport>();
        if (reports != null) {
            sortedReports.addAll(reports);
            Collections.sort(sortedReports, new Comparator<SessionReport>() {
                @Override
                public int compare(SessionReport r1, SessionReport r2) {
                    int cmp = Integer.compare(r2.getRisk().getTotalPoints(), r1.getRisk().getTotalPoints());
                    if (cmp != 0) {
                        return cmp;
                    }
                    return r1.getRisk().getSessionId().compareTo(r2.getRisk().getSessionId());
                }
            });
        }

        // 3. Write HTML document using try-with-resources
        try (BufferedWriter bw = Files.newBufferedWriter(outputFile);
             PrintWriter pw = new PrintWriter(bw)) {

            pw.println("<!DOCTYPE html>");
            pw.println("<html lang=\"en\">");
            pw.println("<head>");
            pw.println("  <meta charset=\"UTF-8\">");
            pw.println("  <title>CookieTrace Dashboard</title>");
            pw.println("</head>");
            pw.println("<body style=\"background-color: #f4f6f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 28px; color: #212529;\">");

            // Header
            pw.println("  <div style=\"margin-bottom: 24px;\">");
            pw.println("    <h1 style=\"margin: 0; color: #1a237e; font-size: 28px;\">CookieTrace Dashboard</h1>");
            pw.println("    <p style=\"margin: 6px 0 0 0; color: #6c757d; font-size: 14px;\">Session Threat Detection & Cookie Hygiene Monitoring</p>");
            pw.println("  </div>");

            // (a) Summary cards in a row
            pw.println("  <!-- Section A: Summary Cards -->");
            pw.println("  <div style=\"display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 28px;\">");

            renderCard(pw, "Total Sessions", String.valueOf(totalSessions), "#1a237e", "Analyzed web sessions");
            renderCard(pw, "HIGH Risk", String.valueOf(highCount), "#d32f2f", "Critical threat score >= 60");
            renderCard(pw, "MEDIUM Risk", String.valueOf(medCount), "#f57c00", "Elevated threat score 30-59");
            renderCard(pw, "LOW Risk", String.valueOf(lowCount), "#2e7d32", "Normal score < 30");
            renderCard(pw, "Weak Cookies", String.valueOf(weakCookiesCount), "#c2185b", "Grades F, D, or C");
            renderCard(pw, "Last Run Time", escapeHtml(lastRunTime), "#455a64", "Most recent audit timestamp");

            pw.println("  </div>");

            // (b) Sessions table sorted by score descending
            pw.println("  <!-- Section B: Sessions Table -->");
            pw.println("  <div style=\"background-color: #ffffff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); padding: 20px; margin-bottom: 28px;\">");
            pw.println("    <h2 style=\"margin-top: 0; color: #1a237e; font-size: 18px; border-bottom: 1px solid #e9ecef; padding-bottom: 10px;\">All Sessions (Ranked by Risk Score)</h2>");
            pw.println("    <table style=\"border-collapse: collapse; width: 100%; font-size: 14px;\">");
            pw.println("      <thead>");
            pw.println("        <tr style=\"background-color: #f8f9fa; text-align: left;\">");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">Session ID</th>");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">Score</th>");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">Level</th>");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">Cookie Grade</th>");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">Analyzers That Fired</th>");
            pw.println("        </tr>");
            pw.println("      </thead>");
            pw.println("      <tbody>");

            for (SessionReport report : sortedReports) {
                SessionRisk risk = report.getRisk();
                RiskLevel lvl = risk.getLevel();

                // Build badge style
                String badgeStyle;
                if (lvl == RiskLevel.HIGH) {
                    badgeStyle = "background-color: #ffebee; color: #c62828;";
                } else if (lvl == RiskLevel.MEDIUM) {
                    badgeStyle = "background-color: #fff3e0; color: #ef6c00;";
                } else {
                    badgeStyle = "background-color: #e8f5e9; color: #2e7d32;";
                }

                Set<String> uniqueAnalyzers = new LinkedHashSet<String>();
                for (Alert a : risk.getAlerts()) {
                    uniqueAnalyzers.add(a.getAnalyzerName());
                }

                StringBuilder analyzersSb = new StringBuilder();
                int aCount = 0;
                for (String aName : uniqueAnalyzers) {
                    if (aCount > 0) {
                        analyzersSb.append("; ");
                    }
                    analyzersSb.append(escapeHtml(aName));
                    aCount++;
                }
                String analyzersStr = (aCount == 0) ? "None" : analyzersSb.toString();

                pw.println("        <tr>");
                pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef; font-family: monospace; font-weight: 600;\">" + escapeHtml(risk.getSessionId()) + "</td>");
                pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef; font-weight: bold;\">" + risk.getTotalPoints() + "</td>");
                pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef;\"><span style=\"" + badgeStyle + " padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;\">" + escapeHtml(lvl.name()) + "</span></td>");
                pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef; font-weight: bold;\">" + escapeHtml(report.getCookieGrade().name()) + "</td>");
                pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef; color: #495057;\">" + analyzersStr + "</td>");
                pw.println("        </tr>");
            }

            pw.println("      </tbody>");
            pw.println("    </table>");
            pw.println("  </div>");

            // (c) "Alert details": collapsible <details> for each MEDIUM or HIGH session
            pw.println("  <!-- Section C: Alert Details -->");
            pw.println("  <div style=\"background-color: #ffffff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); padding: 20px; margin-bottom: 28px;\">");
            pw.println("    <h2 style=\"margin-top: 0; color: #1a237e; font-size: 18px; border-bottom: 1px solid #e9ecef; padding-bottom: 10px;\">Alert Details (Actionable Threats & Cookie Remediations)</h2>");

            boolean foundElevated = false;
            for (SessionReport report : sortedReports) {
                SessionRisk risk = report.getRisk();
                RiskLevel lvl = risk.getLevel();

                if (lvl == RiskLevel.MEDIUM || lvl == RiskLevel.HIGH) {
                    foundElevated = true;
                    String borderAccent = (lvl == RiskLevel.HIGH) ? "#d32f2f" : "#f57c00";

                    pw.println("    <details style=\"margin-bottom: 14px; background-color: #fafbfc; border: 1px solid #e1e4e8; border-left: 4px solid " + borderAccent + "; border-radius: 6px; padding: 12px;\">");
                    pw.println("      <summary style=\"font-weight: bold; cursor: pointer; color: #1a237e; font-size: 15px;\">");
                    pw.println("        Session: " + escapeHtml(risk.getSessionId())
                            + " &bull; Score: " + risk.getTotalPoints()
                            + "/100 &bull; Level: " + escapeHtml(lvl.name())
                            + " &bull; Cookie Grade: " + escapeHtml(report.getCookieGrade().name()));
                    pw.println("      </summary>");

                    pw.println("      <div style=\"margin-top: 12px; font-size: 14px;\">");

                    // Alerts breakdown
                    pw.println("        <h4 style=\"margin: 10px 0 6px 0; color: #24292e;\">Security Alerts:</h4>");
                    if (risk.getAlerts().isEmpty()) {
                        pw.println("        <p style=\"color: #6a737d; margin: 4px 0 8px 16px;\">No security alerts triggered.</p>");
                    } else {
                        pw.println("        <ul style=\"margin: 4px 0 10px 0; padding-left: 20px;\">");
                        for (Alert a : risk.getAlerts()) {
                            pw.println("          <li style=\"margin-bottom: 8px;\">");
                            pw.println("            <strong>[" + escapeHtml(a.getAnalyzerName()) + "]</strong> (" + a.getPoints() + " pts, " + escapeHtml(a.getLevel().name()) + "): " + escapeHtml(a.getExplanation()) + "<br>");
                            pw.println("            <em style=\"color: #495057;\">Recommendation:</em> " + escapeHtml(a.getRecommendation()));
                            pw.println("          </li>");
                        }
                        pw.println("        </ul>");
                    }

                    // Cookie Fixes breakdown
                    pw.println("        <h4 style=\"margin: 10px 0 6px 0; color: #24292e;\">Cookie Remediation Fixes:</h4>");
                    if (report.getCookieFixes().isEmpty()) {
                        pw.println("        <p style=\"color: #6a737d; margin: 4px 0 8px 16px;\">No cookie configuration issues found.</p>");
                    } else {
                        pw.println("        <ul style=\"margin: 4px 0 8px 0; padding-left: 20px;\">");
                        for (String fix : report.getCookieFixes()) {
                            pw.println("          <li style=\"margin-bottom: 4px;\">" + escapeHtml(fix) + "</li>");
                        }
                        pw.println("        </ul>");
                    }

                    pw.println("      </div>");
                    pw.println("    </details>");
                }
            }

            if (!foundElevated) {
                pw.println("    <p style=\"color: #6c757d;\">No MEDIUM or HIGH risk sessions observed.</p>");
            }

            pw.println("  </div>");

            // (d) "Run history" table from SQLite history
            pw.println("  <!-- Section D: Run History -->");
            pw.println("  <div style=\"background-color: #ffffff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); padding: 20px; margin-bottom: 28px;\">");
            pw.println("    <h2 style=\"margin-top: 0; color: #1a237e; font-size: 18px; border-bottom: 1px solid #e9ecef; padding-bottom: 10px;\">Run History (Audit Trail from SQLite)</h2>");
            pw.println("    <table style=\"border-collapse: collapse; width: 100%; font-size: 14px;\">");
            pw.println("      <thead>");
            pw.println("        <tr style=\"background-color: #f8f9fa; text-align: left;\">");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">Run ID</th>");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">Run Time</th>");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">Dataset</th>");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">Sessions</th>");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">LOW</th>");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">MEDIUM</th>");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">HIGH</th>");
            pw.println("        </tr>");
            pw.println("      </thead>");
            pw.println("      <tbody>");

            if (history != null && !history.isEmpty()) {
                for (RunSummary run : history) {
                    pw.println("        <tr>");
                    pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef; font-weight: bold;\">" + run.getRunId() + "</td>");
                    pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef; font-family: monospace; font-size: 12px;\">" + escapeHtml(run.getRunTime()) + "</td>");
                    pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef;\">" + escapeHtml(run.getDataset()) + "</td>");
                    pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef;\">" + run.getSessionCount() + "</td>");
                    pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef; color: #2e7d32;\">" + run.getLowCount() + "</td>");
                    pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef; color: #ef6c00;\">" + run.getMediumCount() + "</td>");
                    pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef; color: #c62828;\">" + run.getHighCount() + "</td>");
                    pw.println("        </tr>");
                }
            } else {
                pw.println("        <tr><td colspan=\"7\" style=\"padding: 12px; text-align: center; color: #6c757d;\">No historical runs recorded.</td></tr>");
            }

            pw.println("      </tbody>");
            pw.println("    </table>");
            pw.println("  </div>");

            // (e) "Live simulation timeline": table of escalations
            pw.println("  <!-- Section E: Live Simulation Timeline -->");
            pw.println("  <div style=\"background-color: #ffffff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); padding: 20px; margin-bottom: 28px;\">");
            pw.println("    <h2 style=\"margin-top: 0; color: #1a237e; font-size: 18px; border-bottom: 1px solid #e9ecef; padding-bottom: 10px;\">Live Simulation Timeline (Escalation Stream)</h2>");
            pw.println("    <table style=\"border-collapse: collapse; width: 100%; font-size: 14px;\">");
            pw.println("      <thead>");
            pw.println("        <tr style=\"background-color: #f8f9fa; text-align: left;\">");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">Event #</th>");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">Session</th>");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">Old Level</th>");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">New Level</th>");
            pw.println("          <th style=\"padding: 10px 12px; border-bottom: 2px solid #dee2e6;\">Score at Escalation</th>");
            pw.println("        </tr>");
            pw.println("      </thead>");
            pw.println("      <tbody>");

            if (timeline != null && !timeline.isEmpty()) {
                for (TimelineEntry entry : timeline) {
                    pw.println("        <tr>");
                    pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef; font-weight: bold;\">" + entry.getEventIndex() + "</td>");
                    pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef; font-family: monospace;\">" + escapeHtml(entry.getSessionId()) + "</td>");
                    pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef; color: #6c757d;\">" + escapeHtml(entry.getOldLevel().name()) + "</td>");
                    pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef; font-weight: bold; color: " + (entry.getNewLevel() == RiskLevel.HIGH ? "#c62828" : "#ef6c00") + ";\">" + escapeHtml(entry.getNewLevel().name()) + "</td>");
                    pw.println("          <td style=\"padding: 10px 12px; border-bottom: 1px solid #e9ecef; font-weight: bold;\">" + entry.getScore() + "</td>");
                    pw.println("        </tr>");
                }
            } else {
                pw.println("        <tr><td colspan=\"5\" style=\"padding: 12px; text-align: center; color: #6c757d;\">No risk escalations recorded during simulation.</td></tr>");
            }

            pw.println("      </tbody>");
            pw.println("    </table>");
            pw.println("  </div>");

            // (f) Footer
            pw.println("  <!-- Section F: Footer -->");
            pw.println("  <footer style=\"margin-top: 32px; padding: 18px; text-align: center; color: #6c757d; font-size: 13px; border-top: 1px solid #dee2e6;\">");
            pw.println("    Simulated data. Alerts are indicators for human investigation, not proof of compromise.");
            pw.println("  </footer>");

            pw.println("</body>");
            pw.println("</html>");
            pw.flush();
        }
    }

    /**
     * Renders a clean summary metric card in HTML.
     */
    private void renderCard(PrintWriter pw, String title, String value, String accentColor, String subtitle) {
        pw.println("    <div style=\"flex: 1; min-width: 140px; background-color: #ffffff; padding: 16px; border-radius: 8px; border-left: 4px solid " + accentColor + "; box-shadow: 0 1px 3px rgba(0,0,0,0.08);\">");
        pw.println("      <div style=\"font-size: 12px; color: #6c757d; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;\">" + escapeHtml(title) + "</div>");
        pw.println("      <div style=\"font-size: 22px; font-weight: bold; margin-top: 6px; color: #212529; word-break: break-all;\">" + value + "</div>");
        pw.println("      <div style=\"font-size: 11px; color: #adb5bd; margin-top: 4px;\">" + escapeHtml(subtitle) + "</div>");
        pw.println("    </div>");
    }

    /**
     * Escapes special HTML characters (&, <, >, ") to prevent injection vulnerabilities.
     *
     * SECURITY COMMENT:
     * Web session logs may contain untrusted user inputs (such as arbitrary User-Agent
     * headers, crafted session IDs, URL parameters, or attack payloads). If dynamic text
     * were injected directly into HTML without escaping, an attacker could inject malicious
     * JavaScript or HTML tags, leading to a Stored Cross-Site Scripting (XSS) vulnerability
     * when a security analyst views this dashboard.
     *
     * @param input Raw text from session data
     * @return HTML-safe escaped string
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
