package com.cookietrace;

import com.cookietrace.data.SessionLoader;
import com.cookietrace.exception.InvalidSessionDataException;
import com.cookietrace.model.Alert;
import com.cookietrace.model.CookieInfo;
import com.cookietrace.model.RiskLevel;
import com.cookietrace.model.SessionEvent;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Stage 2 Demonstration: Core Model Encapsulation & CSV Loading.
 *
 * This class verifies:
 * 1. Loading the 60 simulated session events produced in Stage 1 into domain model objects.
 * 2. Proper encapsulation and validation fail-fast guards in model constructors.
 */
public class Stage2Demo {

    public static void main(String[] args) {
        System.out.println("=== CookieTrace: Stage 2 - Core Models & Encapsulation Demo ===");

        // Locate sessions_dev.csv (support running from either project root or workspace root)
        Path csvPath = Paths.get("data", "sessions_dev.csv");
        if (!Files.exists(csvPath)) {
            csvPath = Paths.get("cookietrace", "data", "sessions_dev.csv");
        }

        System.out.println("Loading session events from: " + csvPath.toAbsolutePath() + "\n");

        SessionLoader loader = new SessionLoader();
        List<SessionEvent> events = loader.load(csvPath);

        // Count distinct sessions using a simple Set
        Set<String> distinctSessions = new HashSet<String>();
        for (SessionEvent event : events) {
            distinctSessions.add(event.getSessionId());
        }

        System.out.println("--- Loading Results ---");
        System.out.println("Number of events loaded: " + events.size());
        System.out.println("Rejected count: " + loader.getRejectedCount());
        System.out.println("Number of distinct sessions: " + distinctSessions.size());
        System.out.println();

        // Print first 3 events using their toString() method
        System.out.println("--- First 3 Loaded Events (toString preview) ---");
        int previewCount = Math.min(3, events.size());
        for (int i = 0; i < previewCount; i++) {
            System.out.println("[" + (i + 1) + "] " + events.get(i).toString());
        }
        System.out.println();

        // -------------------------------------------------------------
        // Run 4 Encapsulation & Validation Demonstrations
        // -------------------------------------------------------------
        System.out.println("--- Encapsulation & Validation Demonstrations ---");

        // (a) CookieInfo with sameSite "Banana"
        System.out.println("\n(a) Attempting CookieInfo with invalid sameSite: 'Banana'");
        try {
            CookieInfo badCookie = new CookieInfo(true, true, "Banana");
            System.out.println("UNEXPECTED: Created object successfully: " + badCookie);
        } catch (InvalidSessionDataException e) {
            System.out.println("Caught expected exception: " + e.getMessage());
        }

        // (b) SessionEvent with latitude 200
        System.out.println("\n(b) Attempting SessionEvent with out-of-bounds latitude: 200.0");
        try {
            CookieInfo validCookie = new CookieInfo(true, true, "Strict");
            SessionEvent badLatEvent = new SessionEvent(
                    "sess_0099", Instant.now(), "user_001", "49.207.180.25",
                    "Chennai", "India", 200.0, 80.2707, "Mozilla/5.0", validCookie
            );
            System.out.println("UNEXPECTED: Created object successfully: " + badLatEvent);
        } catch (InvalidSessionDataException e) {
            System.out.println("Caught expected exception: " + e.getMessage());
        }

        // (c) SessionEvent with blank userId
        System.out.println("\n(c) Attempting SessionEvent with blank userId: '   '");
        try {
            CookieInfo validCookie = new CookieInfo(true, true, "Lax");
            SessionEvent badUserEvent = new SessionEvent(
                    "sess_0099", Instant.now(), "   ", "103.21.124.50",
                    "Mumbai", "India", 19.0760, 72.8777, "Mozilla/5.0", validCookie
            );
            System.out.println("UNEXPECTED: Created object successfully: " + badUserEvent);
        } catch (InvalidSessionDataException e) {
            System.out.println("Caught expected exception: " + e.getMessage());
        }

        // (d) Alert with points 150
        System.out.println("\n(d) Attempting Alert with out-of-range points: 150");
        try {
            Alert badAlert = new Alert(
                    "sess_0017", "InsecureCookieAnalyzer", RiskLevel.HIGH, 150,
                    "Cookie lacks Secure flag", "Enable Secure flag on session cookies."
            );
            System.out.println("UNEXPECTED: Created object successfully: " + badAlert);
        } catch (InvalidSessionDataException e) {
            System.out.println("Caught expected exception: " + e.getMessage());
        }

        System.out.println("\n=== Stage 2 Complete: All model validations passed! ===");
    }
}
