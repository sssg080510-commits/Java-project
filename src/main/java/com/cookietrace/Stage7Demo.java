package com.cookietrace;

import com.cookietrace.analysis.ConcurrentSessionAnalyzer;
import com.cookietrace.analysis.CookieAttributeAnalyzer;
import com.cookietrace.analysis.ImpossibleTravelAnalyzer;
import com.cookietrace.analysis.IpChangeAnalyzer;
import com.cookietrace.analysis.SecurityAnalyzer;
import com.cookietrace.analysis.UserAgentAnalyzer;
import com.cookietrace.data.SessionLoader;
import com.cookietrace.engine.RiskEngine;
import com.cookietrace.engine.SessionRisk;
import com.cookietrace.model.RiskLevel;
import com.cookietrace.model.SessionEvent;
import com.cookietrace.simulation.ConsoleSimulationListener;
import com.cookietrace.simulation.LiveSimulator;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Stage 7 Demonstration: Live Streaming Event Simulation & Progressive Threat Detection.
 *
 * Demonstrates:
 * 1. Observer Pattern: Decoupling event generation from presentation via SimulationListener.
 * 2. Incremental Evaluation: Streaming events chronologically and evaluating risk progressively.
 * 3. Batch vs. Streaming Consistency: Verifies that cumulative streaming results match batch evaluation.
 */
public class Stage7Demo {

    public static void main(String[] args) {
        // Parse optional first argument: delay in milliseconds (default 1000)
        long delayMillis = 1000L;
        if (args.length > 0) {
            try {
                delayMillis = Long.parseLong(args[0]);
            } catch (NumberFormatException e) {
                System.err.println("Usage: java com.cookietrace.Stage7Demo [delayMillis]");
                System.err.println("  delayMillis: Optional event simulation delay in milliseconds (0 - 5000, default 1000).");
                return;
            }
        }

        // 1. Locate and load session events from data/sessions_dev.csv
        Path eventsPath = Paths.get("data", "sessions_dev.csv");
        if (!Files.exists(eventsPath)) {
            eventsPath = Paths.get("cookietrace", "data", "sessions_dev.csv");
        }

        SessionLoader loader = new SessionLoader();
        List<SessionEvent> events = loader.load(eventsPath);

        // 2. Build RiskEngine with ONLY the five rule-based analyzers (no AnomalyAnalyzer)
        List<SecurityAnalyzer> ruleAnalyzers = new ArrayList<SecurityAnalyzer>();
        ruleAnalyzers.add(new CookieAttributeAnalyzer());
        ruleAnalyzers.add(new IpChangeAnalyzer());
        ruleAnalyzers.add(new UserAgentAnalyzer());
        ruleAnalyzers.add(new ConcurrentSessionAnalyzer());
        ruleAnalyzers.add(new ImpossibleTravelAnalyzer());

        RiskEngine engine = new RiskEngine(ruleAnalyzers);

        // 3. Set up and run the live simulator with ConsoleSimulationListener
        ConsoleSimulationListener listener = new ConsoleSimulationListener();
        LiveSimulator simulator = new LiveSimulator(engine, listener, delayMillis);

        System.out.println("=== CookieTrace: Stage 7 - Live Event Simulation Demo ===");
        System.out.println("Loaded " + events.size() + " session events from " + eventsPath + ".");
        System.out.println("Configured 5 rule-based analyzers in RiskEngine.");
        System.out.println("Streaming events with delay = " + delayMillis + " ms...\n");

        simulator.run(events);

        // 4. Print final table of sessions that are MEDIUM or HIGH
        Map<String, SessionRisk> streamRisks = simulator.getFinalRisks();

        System.out.println("\n================================================================================");
        System.out.println("=== Final Flagged Sessions (MEDIUM / HIGH) ===");
        System.out.println("================================================================================");
        System.out.printf("%-15s | %-10s | %s%n", "Session ID", "Score", "Risk Level");
        System.out.println("--------------------------------------------------------------------------------");

        for (SessionRisk risk : streamRisks.values()) {
            if (risk.getLevel() == RiskLevel.MEDIUM || risk.getLevel() == RiskLevel.HIGH) {
                System.out.printf("%-15s | %-10d | %s%n",
                        risk.getSessionId(), risk.getTotalPoints(), risk.getLevel());
            }
        }
        System.out.println("================================================================================");

        // 5. Print the number of escalations printed
        System.out.println("\nNumber of escalations printed: " + listener.getEscalationCount());

        // 6. Consistency Check: evaluate same events in batch call and compare with streaming result
        System.out.println("\n=== Consistency Check ===");
        List<SessionRisk> batchRisks = engine.evaluate(events);
        Map<String, SessionRisk> batchMap = new LinkedHashMap<String, SessionRisk>();
        for (SessionRisk r : batchRisks) {
            batchMap.put(r.getSessionId(), r);
        }

        int matchCount = 0;
        int totalSessions = streamRisks.size();
        for (Map.Entry<String, SessionRisk> entry : streamRisks.entrySet()) {
            String sId = entry.getKey();
            SessionRisk streamRisk = entry.getValue();
            SessionRisk batchRisk = batchMap.get(sId);

            if (batchRisk != null
                    && streamRisk.getTotalPoints() == batchRisk.getTotalPoints()
                    && streamRisk.getLevel() == batchRisk.getLevel()) {
                matchCount++;
            }
        }

        System.out.println("Consistency check: " + matchCount + " of " + totalSessions + " sessions match");
        System.out.println("\nStage 7 completed successfully!");
    }
}
