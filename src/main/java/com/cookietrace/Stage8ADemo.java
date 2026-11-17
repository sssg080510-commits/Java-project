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
import com.cookietrace.report.SessionReport;
import com.cookietrace.storage.RunHistoryStore;
import com.cookietrace.storage.RunSummary;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Stage 8A Demonstration: Persistent Run History Storage with SQLite & JDBC.
 *
 * Demonstrates:
 * 1. Database Persistence: SQLite stores historical threat assessments for auditing.
 * 2. ACID Transactions: Multi-table inserts (runs, session_results, alerts) committed atomically.
 * 3. SQL Injection Defense: Parameterized PreparedStatements used for all dynamic values.
 * 4. Resource Management: RunHistoryStore lifecycle handled automatically via try-with-resources.
 */
public class Stage8ADemo {

    public static void main(String[] args) {
        System.out.println("=== CookieTrace: Stage 8A - SQLite Run History Storage Demo ===\n");

        // 1. Locate and load session events from data/sessions_dev.csv
        Path eventsPath = Paths.get("data", "sessions_dev.csv");
        if (!Files.exists(eventsPath)) {
            eventsPath = Paths.get("cookietrace", "data", "sessions_dev.csv");
        }

        SessionLoader loader = new SessionLoader();
        List<SessionEvent> events = loader.load(eventsPath);
        System.out.println("Loaded " + events.size() + " session events from " + eventsPath + ".");

        // 2. Build RiskEngine with 5 rule analyzers + AnomalyAnalyzer(0.20)
        List<SecurityAnalyzer> analyzers = new ArrayList<SecurityAnalyzer>();
        analyzers.add(new CookieAttributeAnalyzer());
        analyzers.add(new IpChangeAnalyzer());
        analyzers.add(new UserAgentAnalyzer());
        analyzers.add(new ConcurrentSessionAnalyzer());
        analyzers.add(new ImpossibleTravelAnalyzer());
        analyzers.add(new AnomalyAnalyzer(0.20));

        RiskEngine engine = new RiskEngine(analyzers);

        // 3. Evaluate risks and build SessionReports
        List<SessionRisk> risks = engine.evaluate(events);
        List<SessionReport> reports = SessionReport.build(risks, events);
        System.out.println("Evaluated " + reports.size() + " sessions across " + analyzers.size() + " analyzers.");

        // 4. Locate database file path: data/cookietrace.db
        Path dbPath = Paths.get("data", "cookietrace.db");
        if (!Files.exists(Paths.get("data")) && Files.exists(Paths.get("cookietrace", "data"))) {
            dbPath = Paths.get("cookietrace", "data", "cookietrace.db");
        }

        // 5. Open database store with try-with-resources, save run, and display history
        try (RunHistoryStore store = new RunHistoryStore(dbPath)) {
            // Save current run atomically
            long newRunId = store.saveRun("sessions_dev.csv", events.size(), reports);
            System.out.println("\nSuccessfully stored analysis run into: " + dbPath.toAbsolutePath());
            System.out.println("New Run ID: " + newRunId);

            // Fetch and print run history (up to 10 most recent runs)
            List<RunSummary> history = store.listRuns(10);
            System.out.println("\n==================================================================================================");
            System.out.println("=== Run History (Newest First, Up to 10 Runs) ===");
            System.out.println("==================================================================================================");
            System.out.printf("%-8s | %-28s | %-18s | %-8s | %-5s | %-5s | %-5s%n",
                    "Run ID", "Run Timestamp", "Dataset", "Sessions", "LOW", "MED", "HIGH");
            System.out.println("--------------------------------------------------------------------------------------------------");
            for (RunSummary run : history) {
                System.out.printf("%-8d | %-28s | %-18s | %-8d | %-5d | %-5d | %-5d%n",
                        run.getRunId(),
                        run.getRunTime(),
                        run.getDataset(),
                        run.getSessionCount(),
                        run.getLowCount(),
                        run.getMediumCount(),
                        run.getHighCount());
            }
            System.out.println("==================================================================================================");

            // Print row counts of the three tables
            System.out.println("\n=== Database Table Row Counts ===");
            System.out.printf("  runs:            %d row(s)%n", store.countRows("runs"));
            System.out.printf("  session_results: %d row(s)%n", store.countRows("session_results"));
            System.out.printf("  alerts:          %d row(s)%n", store.countRows("alerts"));
            System.out.println("=================================");

        } catch (Exception e) {
            System.err.println("Database operation failed: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("\nStage 8A completed successfully!");
    }
}
