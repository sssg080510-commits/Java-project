package com.cookietrace.report;

import com.cookietrace.engine.SessionRisk;
import com.cookietrace.model.Alert;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;
import java.time.Instant;
import java.util.List;

/**
 * Exports session threat and cookie security reports in JSON format.
 *
 * Implements manual JSON serialization without external libraries:
 * - Generates clean, 2-space indented, human-readable JSON.
 * - Handles proper escaping of strings (backslash, quotes, newlines, carriage returns, tabs).
 */
public class JsonExporter implements AlertExporter {

    @Override
    public String getFormatName() {
        return "JSON";
    }

    @Override
    public String getFileExtension() {
        return "json";
    }

    @Override
    public void export(List<SessionReport> reports, Writer out) throws IOException {
        PrintWriter pw = new PrintWriter(out);

        int sessionCount = (reports == null) ? 0 : reports.size();

        pw.println("{");
        pw.println("  \"generatedAt\": \"" + Instant.now().toString() + "\",");
        pw.println("  \"sessionCount\": " + sessionCount + ",");
        pw.println("  \"sessions\": [");

        if (reports != null) {
            for (int i = 0; i < reports.size(); i++) {
                SessionReport report = reports.get(i);
                SessionRisk risk = report.getRisk();
                List<String> cookieFixes = report.getCookieFixes();
                List<Alert> alerts = risk.getAlerts();

                pw.println("    {");
                pw.println("      \"sessionId\": \"" + escapeJson(risk.getSessionId()) + "\",");
                pw.println("      \"rawPoints\": " + risk.getRawPoints() + ",");
                pw.println("      \"totalPoints\": " + risk.getTotalPoints() + ",");
                pw.println("      \"level\": \"" + escapeJson(risk.getLevel().name()) + "\",");
                pw.println("      \"cookieGrade\": \"" + escapeJson(report.getCookieGrade().name()) + "\",");

                // cookieFixes array
                pw.println("      \"cookieFixes\": [");
                for (int j = 0; j < cookieFixes.size(); j++) {
                    String fix = cookieFixes.get(j);
                    pw.print("        \"" + escapeJson(fix) + "\"");
                    if (j < cookieFixes.size() - 1) {
                        pw.print(",");
                    }
                    pw.println();
                }
                pw.println("      ],");

                // alerts array
                pw.println("      \"alerts\": [");
                for (int k = 0; k < alerts.size(); k++) {
                    Alert alert = alerts.get(k);
                    pw.println("        {");
                    pw.println("          \"analyzer\": \"" + escapeJson(alert.getAnalyzerName()) + "\",");
                    pw.println("          \"points\": " + alert.getPoints() + ",");
                    pw.println("          \"level\": \"" + escapeJson(alert.getLevel().name()) + "\",");
                    pw.println("          \"explanation\": \"" + escapeJson(alert.getExplanation()) + "\",");
                    pw.println("          \"recommendation\": \"" + escapeJson(alert.getRecommendation()) + "\"");
                    pw.print("        }");
                    if (k < alerts.size() - 1) {
                        pw.print(",");
                    }
                    pw.println();
                }
                pw.println("      ]");

                pw.print("    }");
                if (i < reports.size() - 1) {
                    pw.print(",");
                }
                pw.println();
            }
        }

        pw.println("  ]");
        pw.println("}");
        pw.flush();
    }

    /**
     * Escapes special characters for safe inclusion in JSON string literals.
     * Escapes backslash, double quote, newline, carriage return, and tab.
     *
     * @param input Raw text to escape
     * @return Escaped string safe for JSON string literal
     */
    private String escapeJson(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\\\");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    sb.append(c);
                    break;
            }
        }
        return sb.toString();
    }
}
