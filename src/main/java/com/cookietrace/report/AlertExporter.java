package com.cookietrace.report;

import java.io.IOException;
import java.io.Writer;
import java.util.List;

/**
 * Common interface defining the export capabilities for session security reports.
 *
 * OOP Concept - Why use an Interface?
 * 1. Separation of Concerns:
 *    The core threat detection logic (analyzers and RiskEngine) produces domain data (SessionReport).
 *    AlertExporter decouples HOW that data is presented (Console, CSV, JSON, HTML) from how it is generated.
 * 2. Interchangeability & Polymorphism:
 *    Any caller can iterate over a List<AlertExporter> and call exporter.export(...) without
 *    needing to know whether the output goes to a terminal, a CSV file, or a network socket.
 * 3. Extensibility:
 *    Adding a new report format requires creating a new implementing class without altering
 *    any existing analysis, engine, or exporter code.
 */
public interface AlertExporter {

    /**
     * Returns a human-friendly name for this export format (e.g. "Console", "CSV").
     *
     * @return Format name
     */
    String getFormatName();

    /**
     * Returns the file extension for file-based exports (e.g. "csv"), or null for console output.
     *
     * @return File extension string, or null if direct console output
     */
    String getFileExtension();

    /**
     * Exports a list of session reports to the given Writer destination.
     *
     * @param reports List of session reports to export
     * @param out     Destination Writer (e.g. FileWriter, PrintWriter, StringWriter)
     * @throws IOException If writing fails
     */
    void export(List<SessionReport> reports, Writer out) throws IOException;
}
