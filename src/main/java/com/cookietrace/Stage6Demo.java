package com.cookietrace;

import com.cookietrace.analysis.AnomalyAnalyzer;
import com.cookietrace.analysis.ConcurrentSessionAnalyzer;
import com.cookietrace.analysis.CookieAttributeAnalyzer;
import com.cookietrace.analysis.ImpossibleTravelAnalyzer;
import com.cookietrace.analysis.IpChangeAnalyzer;
import com.cookietrace.analysis.SecurityAnalyzer;
import com.cookietrace.analysis.UserAgentAnalyzer;
import com.cookietrace.data.SessionLoader;
import com.cookietrace.engine.RiskEngine;
import com.cookietrace.engine.SessionRisk;
import com.cookietrace.model.SessionEvent;
import com.cookietrace.report.AlertExporter;
import com.cookietrace.report.ConsoleExporter;
import com.cookietrace.report.CookieGrade;
import com.cookietrace.report.CsvExporter;
import com.cookietrace.report.HtmlExporter;
import com.cookietrace.report.JsonExporter;
import com.cookietrace.report.SessionReport;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Stage 6A Demonstration: Interface-Driven Report Generation & Export Pipeline.
 *
 * Demonstrates:
 * 1. Interface Polymorphism: AlertExporter standardizes the contract across different formats (Console, CSV).
 * 2. Multi-Dimensional Auditing: Combines dynamic threat detection (RiskEngine) with static hygiene grading (CookieGrader).
 * 3. File I/O: Generates and exports structured CSV reports to the output/ directory using try-with-resources.
 */
public class Stage6Demo {

    public static void main(String[] args) {
        System.out.println("=== CookieTrace: Stage 6A - Report Generation & Export Pipeline Demo ===\n");

        // Locate data/sessions_dev.csv
        Path eventsPath = Paths.get("data", "sessions_dev.csv");
        if (!Files.exists(eventsPath)) {
            eventsPath = Paths.get("cookietrace", "data", "sessions_dev.csv");
        }

        // 1. Load session events
        SessionLoader loader = new SessionLoader();
        List<SessionEvent> events = loader.load(eventsPath);
        System.out.println("Loaded " + events.size() + " session events from " + eventsPath + ".\n");

        // 2. Build RiskEngine with all 6 analyzers (5 rules + 1 ML AnomalyAnalyzer)
        List<SecurityAnalyzer> analyzers = new ArrayList<SecurityAnalyzer>();
        analyzers.add(new CookieAttributeAnalyzer());
        analyzers.add(new IpChangeAnalyzer());
        analyzers.add(new UserAgentAnalyzer());
        analyzers.add(new ConcurrentSessionAnalyzer());
        analyzers.add(new ImpossibleTravelAnalyzer());
        analyzers.add(new AnomalyAnalyzer(0.20));

        RiskEngine engine = new RiskEngine(analyzers);

        // 3. Evaluate risks
        List<SessionRisk> risks = engine.evaluate(events);

        // 4. Build unified SessionReports combining risk assessments and cookie grades
        List<SessionReport> reports = SessionReport.build(risks, events);

        // 5. Build exporters list using the AlertExporter interface
        List<AlertExporter> exporters = new ArrayList<AlertExporter>();
        exporters.add(new ConsoleExporter());
        exporters.add(new CsvExporter());
        exporters.add(new JsonExporter());
        exporters.add(new HtmlExporter());

        // Ensure output/ directory exists
        Path outputDir = Paths.get("output");
        if (!Files.exists(outputDir)) {
            try {
                Files.createDirectories(outputDir);
            } catch (IOException e) {
                System.err.println("Could not create output directory: " + e.getMessage());
            }
        }

        // -------------------------------------------------------------
        // OOP Concept - Interface Polymorphism:
        // We iterate over List<AlertExporter>. The caller does not need to know
        // whether an exporter outputs to the console or writes a file on disk.
        // -------------------------------------------------------------
        System.out.println("=== Executing Exporters Polymorphically ===");
        for (AlertExporter exporter : exporters) {
            String ext = exporter.getFileExtension();

            if (ext == null) {
                // Console output writes to System.out via PrintWriter
                PrintWriter consoleWriter = new PrintWriter(System.out);
                try {
                    exporter.export(reports, consoleWriter);
                    consoleWriter.flush();
                } catch (IOException e) {
                    System.err.println("Console export error: " + e.getMessage());
                }
            } else {
                // File-based output written to output/report.<extension> using try-with-resources
                Path targetFile = outputDir.resolve("report." + ext);
                try (BufferedWriter writer = Files.newBufferedWriter(targetFile)) {
                    exporter.export(reports, writer);
                    System.out.println("\n[File Export Succeeded]");
                    System.out.println("  Format: " + exporter.getFormatName());
                    System.out.println("  Saved to: " + targetFile.toAbsolutePath());
                } catch (IOException e) {
                    System.err.println("File export error for " + targetFile + ": " + e.getMessage());
                }
            }
        }

        // 6. Print summary count of sessions per cookie grade
        Map<CookieGrade, Integer> gradeTotals = new EnumMap<CookieGrade, Integer>(CookieGrade.class);
        for (CookieGrade cg : CookieGrade.values()) {
            gradeTotals.put(cg, 0);
        }
        for (SessionReport report : reports) {
            gradeTotals.put(report.getCookieGrade(), gradeTotals.get(report.getCookieGrade()) + 1);
        }

        System.out.println("\n================================================================================");
        System.out.println("=== Final Session Count per Cookie Grade ===");
        System.out.println("================================================================================");
        for (CookieGrade cg : CookieGrade.values()) {
            System.out.printf("  Cookie Grade %s : %2d session(s)%n", cg, gradeTotals.get(cg));
        }
        System.out.println("================================================================================");

        System.out.println("\nStage 6A completed successfully!");
    }
}
