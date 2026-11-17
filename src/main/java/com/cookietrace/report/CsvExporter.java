package com.cookietrace.report;

import com.cookietrace.engine.SessionRisk;
import com.cookietrace.model.Alert;

import java.io.IOException;
import java.io.Writer;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Exports session threat and cookie security reports in CSV format.
 */
public class CsvExporter implements AlertExporter {

    @Override
    public String getFormatName() {
        return "CSV";
    }

    @Override
    public String getFileExtension() {
        return "csv";
    }

    @Override
    public void export(List<SessionReport> reports, Writer out) throws IOException {
        // Header row
        out.write("session_id,raw_points,total_points,level,cookie_grade,alert_count,analyzers");
        out.write(System.lineSeparator());

        if (reports == null) {
            return;
        }

        for (SessionReport report : reports) {
            SessionRisk risk = report.getRisk();

            // Collect unique analyzer names separated by semicolon
            Set<String> uniqueAnalyzers = new LinkedHashSet<String>();
            for (Alert alert : risk.getAlerts()) {
                uniqueAnalyzers.add(alert.getAnalyzerName());
            }

            StringBuilder analyzerNames = new StringBuilder();
            int count = 0;
            for (String name : uniqueAnalyzers) {
                if (count > 0) {
                    analyzerNames.append(";");
                }
                analyzerNames.append(name);
                count++;
            }

            String row = escapeCsv(risk.getSessionId()) + ","
                    + risk.getRawPoints() + ","
                    + risk.getTotalPoints() + ","
                    + risk.getLevel().name() + ","
                    + report.getCookieGrade().name() + ","
                    + risk.getAlerts().size() + ","
                    + escapeCsv(analyzerNames.toString());

            out.write(row);
            out.write(System.lineSeparator());
        }

        out.flush();
    }

    /**
     * Helper method to escape and quote a CSV field if it contains commas, double quotes, or newlines.
     * Any internal double quotes are escaped by doubling them ("").
     *
     * @param value The raw string to escape
     * @return Escaped and quoted string if needed, or original string
     */
    private String escapeCsv(String value) {
        if (value == null) {
            return "";
        }
        if (value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}
