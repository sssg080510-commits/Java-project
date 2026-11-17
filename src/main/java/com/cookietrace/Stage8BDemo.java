package com.cookietrace;

import com.cookietrace.analysis.AnomalyAnalyzer;
import com.cookietrace.analysis.ConcurrentSessionAnalyzer;
import com.cookietrace.analysis.CookieAttributeAnalyzer;
import com.cookietrace.analysis.ImpossibleTravelAnalyzer;
import com.cookietrace.analysis.IpChangeAnalyzer;
import com.cookietrace.analysis.SecurityAnalyzer;
import com.cookietrace.analysis.UserAgentAnalyzer;
import com.cookietrace.dashboard.DashboardGenerator;
import com.cookietrace.dashboard.RecordingSimulationListener;
import com.cookietrace.dashboard.TimelineEntry;
import com.cookietrace.data.SessionLoader;
import com.cookietrace.engine.RiskEngine;
import com.cookietrace.engine.SessionRisk;
import com.cookietrace.model.SessionEvent;
import com.cookietrace.report.SessionReport;
import com.cookietrace.simulation.LiveSimulator;
import com.cookietrace.storage.RunHistoryStore;
import com.cookietrace.storage.RunSummary;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Stage 8B Demonstration: Comprehensive Security Dashboard Generation.
 *
 * Demonstrates:
 * 1. End-to-End Threat Pipeline: Ingests session events, evaluates rule and ML anomalies, and stores runs in SQLite.
 * 2. Silent Streaming Simulation: Executes LiveSimulator with delay 0 using RecordingSimulationListener.
 * 3. Self-Contained Visual Dashboard: DashboardGenerator produces an interactive, styled, pure-HTML dashboard.
 */
public class Stage8BDemo {

    public static void main(String[] args) {
        System.out.println("=== CookieTrace: Stage 8B - HTML Dashboard Generation Demo ===\n");

        // 1. Locate and load session events from data/sessions_dev.csv
        Path eventsPath = Paths.get("data", "sessions_dev.csv");
        if (!Files.exists(eventsPath)) {
            eventsPath = Paths.get("cookietrace", "data", "sessions_dev.csv");
        }

        SessionLoader loader = new SessionLoader();
        List<SessionEvent> events = loader.load(eventsPath);
        System.out.println("1. Loaded " + events.size() + " session events from " + eventsPath + ".");

        // 2. Build full RiskEngine with five rules + AnomalyAnalyzer(0.20)
        List<SecurityAnalyzer> fullAnalyzers = new ArrayList<SecurityAnalyzer>();
        fullAnalyzers.add(new CookieAttributeAnalyzer());
        fullAnalyzers.add(new IpChangeAnalyzer());
        fullAnalyzers.add(new UserAgentAnalyzer());
        fullAnalyzers.add(new ConcurrentSessionAnalyzer());
        fullAnalyzers.add(new ImpossibleTravelAnalyzer());
        fullAnalyzers.add(new AnomalyAnalyzer(0.20));

        RiskEngine fullEngine = new RiskEngine(fullAnalyzers);

        // 3. Evaluate risks and build consolidated SessionReports
        List<SessionRisk> risks = fullEngine.evaluate(events);
        List<SessionReport> reports = SessionReport.build(risks, events);
        System.out.println("2. Evaluated " + reports.size() + " sessions with full RiskEngine (rules + ML anomaly detection).");

        // 4. Save run to SQLite database and retrieve newest 10 runs
        Path dbPath = Paths.get("data", "cookietrace.db");
        if (!Files.exists(Paths.get("data")) && Files.exists(Paths.get("cookietrace", "data"))) {
            dbPath = Paths.get("cookietrace", "data", "cookietrace.db");
        }

        List<RunSummary> history;
        try (RunHistoryStore store = new RunHistoryStore(dbPath)) {
            long runId = store.saveRun("sessions_dev.csv", events.size(), reports);
            System.out.println("3. Stored analysis run #" + runId + " into " + dbPath + ".");
            history = store.listRuns(10);
            System.out.println("   Retrieved " + history.size() + " historical runs from database.");
        }

        // 5. Run fast streaming simulation (delay 0) with rule analyzers and RecordingSimulationListener
        List<SecurityAnalyzer> ruleAnalyzers = new ArrayList<SecurityAnalyzer>();
        ruleAnalyzers.add(new CookieAttributeAnalyzer());
        ruleAnalyzers.add(new IpChangeAnalyzer());
        ruleAnalyzers.add(new UserAgentAnalyzer());
        ruleAnalyzers.add(new ConcurrentSessionAnalyzer());
        ruleAnalyzers.add(new ImpossibleTravelAnalyzer());

        RiskEngine ruleEngine = new RiskEngine(ruleAnalyzers);
        RecordingSimulationListener recordingListener = new RecordingSimulationListener();
        LiveSimulator simulator = new LiveSimulator(ruleEngine, recordingListener, 0L);
        simulator.run(events);

        List<TimelineEntry> timeline = recordingListener.getTimeline();
        System.out.println("4. Fast simulation completed (delay 0 ms). Recorded " + timeline.size() + " escalation events.");

        // 6. Generate self-contained HTML dashboard
        Path outputDir = Paths.get("output");
        if (!Files.exists(outputDir) && Files.exists(Paths.get("cookietrace", "output"))) {
            outputDir = Paths.get("cookietrace", "output");
        }
        if (!Files.exists(outputDir)) {
            try {
                Files.createDirectories(outputDir);
            } catch (IOException e) {
                System.err.println("Could not create output directory: " + e.getMessage());
            }
        }

        Path dashboardFile = outputDir.resolve("dashboard.html");
        DashboardGenerator generator = new DashboardGenerator();
        try {
            generator.generate(reports, history, timeline, dashboardFile);
        } catch (IOException e) {
            System.err.println("Failed to write dashboard: " + e.getMessage());
            return;
        }

        // 7. Print summary output
        System.out.println("\n================================================================================");
        System.out.println("=== Dashboard Generation Summary ===");
        System.out.println("================================================================================");
        System.out.println("Dashboard path:           " + dashboardFile.toAbsolutePath());
        System.out.println("History rows loaded:      " + history.size());
        System.out.println("Timeline entries recorded: " + timeline.size());
        System.out.println("================================================================================");

        System.out.println("\nStage 8B completed successfully!");
    }
}
