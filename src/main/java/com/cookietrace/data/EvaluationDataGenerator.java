package com.cookietrace.data;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Random;

/**
 * EvaluationDataGenerator creates a larger benchmark dataset of 500 web sessions
 * for evaluating security threat detection algorithms (rule-based and machine-learning).
 *
 * Determinism Guarantee:
 * - Same seed produces byte-for-byte identical files across multiple runs.
 * - All random selections (session timing, cities, IP addresses, browsers, cookie flags)
 *   are strictly generated via a single java.util.Random instance initialized with the given seed.
 * - No unseeded pseudo-random generators (such as Math.random()) or clock calls are used.
 */
public class EvaluationDataGenerator {

    /**
     * Inner helper class representing a city with geographic and network details.
     */
    private static class CityLocation {
        final String city;
        final String country;
        final double latitude;
        final double longitude;
        final String[] sampleIps;

        CityLocation(String city, String country, double latitude, double longitude, String[] sampleIps) {
            this.city = city;
            this.country = country;
            this.latitude = latitude;
            this.longitude = longitude;
            this.sampleIps = sampleIps;
        }

        String getRandomIp(Random random) {
            int index = random.nextInt(sampleIps.length);
            return sampleIps[index];
        }
    }

    /**
     * Inner class representing an individual event record in the CSV log.
     * Implements Comparable so events across all interleaved sessions can be
     * sorted chronologically by timestamp.
     */
    public static class EventRecord implements Comparable<EventRecord> {
        public final String sessionId;
        public final Instant eventTime;
        public final String userId;
        public final String ipAddress;
        public final String city;
        public final String country;
        public final double latitude;
        public final double longitude;
        public final String userAgent;
        public final boolean secure;
        public final boolean httpOnly;
        public final String sameSite;

        public EventRecord(String sessionId, Instant eventTime, String userId,
                           String ipAddress, String city, String country,
                           double latitude, double longitude, String userAgent,
                           boolean secure, boolean httpOnly, String sameSite) {
            this.sessionId = sessionId;
            this.eventTime = eventTime;
            this.userId = userId;
            this.ipAddress = ipAddress;
            this.city = city;
            this.country = country;
            this.latitude = latitude;
            this.longitude = longitude;
            this.userAgent = userAgent;
            this.secure = secure;
            this.httpOnly = httpOnly;
            this.sameSite = sameSite;
        }

        public String toCsvRow() {
            String timeStr = DateTimeFormatter.ISO_INSTANT.format(eventTime);
            String latStr = String.format(Locale.US, "%.4f", latitude);
            String lonStr = String.format(Locale.US, "%.4f", longitude);

            return sessionId + ","
                    + timeStr + ","
                    + userId + ","
                    + ipAddress + ","
                    + city + ","
                    + country + ","
                    + latStr + ","
                    + lonStr + ","
                    + userAgent + ","
                    + secure + ","
                    + httpOnly + ","
                    + sameSite;
        }

        @Override
        public int compareTo(EventRecord other) {
            return this.eventTime.compareTo(other.eventTime);
        }
    }

    /**
     * Inner class representing a ground-truth label entry for a session.
     */
    public static class LabelRecord {
        public final String sessionId;
        public final boolean isAnomaly;
        public final String scenario;

        public LabelRecord(String sessionId, boolean isAnomaly, String scenario) {
            this.sessionId = sessionId;
            this.isAnomaly = isAnomaly;
            this.scenario = scenario;
        }

        public String toCsvRow() {
            return sessionId + "," + isAnomaly + "," + scenario;
        }
    }

    /**
     * Pre-defined cities with realistic geographic coordinates and public-looking IPs.
     * Covers: Chennai, Mumbai, Delhi, Bangalore, London, New York, Singapore, Frankfurt, Sydney.
     */
    private static final CityLocation[] CITIES = new CityLocation[] {
        new CityLocation("Chennai", "India", 13.0827, 80.2707,
                new String[] {"49.207.180.25", "49.207.181.10", "157.48.12.34", "157.48.13.99"}),
        new CityLocation("Mumbai", "India", 19.0760, 72.8777,
                new String[] {"103.21.124.50", "103.21.125.12", "115.112.45.67", "115.112.46.88"}),
        new CityLocation("Delhi", "India", 28.6139, 77.2090,
                new String[] {"122.161.45.80", "122.161.46.90", "182.73.102.44", "182.73.103.15"}),
        new CityLocation("Bangalore", "India", 12.9716, 77.5946,
                new String[] {"106.51.72.18", "106.51.73.45", "49.205.88.102", "49.205.89.210"}),
        new CityLocation("London", "United Kingdom", 51.5074, -0.1278,
                new String[] {"82.165.197.1", "82.165.198.5", "151.101.0.81", "151.101.64.81"}),
        new CityLocation("New York", "United States", 40.7128, -74.0060,
                new String[] {"198.51.100.42", "72.229.28.185", "68.180.20.15", "68.180.21.80"}),
        new CityLocation("Singapore", "Singapore", 1.3521, 103.8198,
                new String[] {"118.189.15.22", "118.189.16.88", "202.166.192.4", "202.166.193.50"}),
        new CityLocation("Frankfurt", "Germany", 50.1109, 8.6821,
                new String[] {"85.214.132.117", "195.201.55.60", "217.160.0.124", "217.160.1.55"}),
        new CityLocation("Sydney", "Australia", -33.8688, 151.2093,
                new String[] {"139.130.4.5", "103.1.204.18", "1.120.0.45", "1.120.1.92"})
    };

    /**
     * City index pairs with distance greater than 2000 km (for IMPOSSIBLE_TRAVEL scenario).
     */
    private static final int[][] DISTANT_CITY_PAIRS = new int[][] {
        {0, 4}, // Chennai to London (~8,211 km)
        {1, 4}, // Mumbai to London (~7,200 km)
        {2, 4}, // Delhi to London (~6,700 km)
        {3, 4}, // Bangalore to London (~8,030 km)
        {4, 5}, // London to New York (~5,570 km)
        {7, 5}, // Frankfurt to New York (~6,200 km)
        {6, 4}, // Singapore to London (~10,840 km)
        {8, 6}, // Sydney to Singapore (~6,300 km)
        {8, 4}, // Sydney to London (~16,900 km)
        {8, 5}  // Sydney to New York (~16,000 km)
    };

    /**
     * Common user agent strings without commas (prevents CSV delimiter splitting conflicts).
     */
    private static final String[] USER_AGENTS = new String[] {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Version/17.2 Mobile/15E148 Safari/604.1"
    };

    /**
     * Generates 500 evaluation sessions spread over 7 days with interleaved events.
     *
     * @param seed       Random seed ensuring reproducible generation
     * @param eventsFile Target path for events CSV file (data/sessions_eval.csv)
     * @param labelsFile Target path for labels CSV file (data/labels_eval.csv)
     * @throws IOException If file writing fails
     */
    public void generate(long seed, Path eventsFile, Path labelsFile) throws IOException {
        // Comment: Deterministic generator using java.util.Random so same seed produces identical files.
        Random random = new Random(seed);

        List<EventRecord> allEvents = new ArrayList<EventRecord>();
        List<LabelRecord> allLabels = new ArrayList<LabelRecord>();

        // 7 days timeline starting 2026-03-01 00:00:00 UTC
        Instant baseTime = Instant.parse("2026-03-01T00:00:00Z");
        // Leave 4 hours buffer at end of 7-day span (7 * 86400 - 14400 = 590,400 seconds)
        int maxStartSpanSeconds = 590400;

        int sessionIndex = 0;

        // -----------------------------------------------------------------
        // 1. 400 NORMAL sessions (is_anomaly = false)
        // -----------------------------------------------------------------
        for (int i = 0; i < 400; i++) {
            sessionIndex++;
            String sessionId = String.format("sess_%04d", sessionIndex);
            String userId = String.format("user_%04d", (sessionIndex % 100) + 1);

            int eventCount = 2 + random.nextInt(5); // 2 to 6 events
            CityLocation loc = CITIES[random.nextInt(CITIES.length)];
            String ip = loc.getRandomIp(random);
            String userAgent = USER_AGENTS[random.nextInt(USER_AGENTS.length)];
            String sameSite = random.nextBoolean() ? "Strict" : "Lax";

            Instant sessionStart = baseTime.plusSeconds(random.nextInt(maxStartSpanSeconds));
            Instant currentTime = sessionStart;

            for (int e = 0; e < eventCount; e++) {
                if (e > 0) {
                    // Minutes apart (1 to 15 minutes)
                    int gapSeconds = 60 + random.nextInt(14 * 60 + 1);
                    currentTime = currentTime.plusSeconds(gapSeconds);
                }
                allEvents.add(new EventRecord(sessionId, currentTime, userId, ip,
                        loc.city, loc.country, loc.latitude, loc.longitude,
                        userAgent, true, true, sameSite));
            }

            allLabels.add(new LabelRecord(sessionId, false, "NORMAL"));
        }

        // -----------------------------------------------------------------
        // 2. 30 NORMAL_BENIGN_IP_CHANGE sessions (is_anomaly = false)
        // -----------------------------------------------------------------
        for (int i = 0; i < 30; i++) {
            sessionIndex++;
            String sessionId = String.format("sess_%04d", sessionIndex);
            String userId = String.format("user_%04d", (sessionIndex % 100) + 1);

            int eventCount = 3 + random.nextInt(4); // 3 to 6 events
            CityLocation loc = CITIES[random.nextInt(CITIES.length)];

            // Pick two distinct sample IPs from the same city
            String ip1 = loc.sampleIps[random.nextInt(loc.sampleIps.length)];
            String ip2 = loc.sampleIps[random.nextInt(loc.sampleIps.length)];
            while (ip2.equalsIgnoreCase(ip1) && loc.sampleIps.length > 1) {
                ip2 = loc.sampleIps[random.nextInt(loc.sampleIps.length)];
            }

            String userAgent = USER_AGENTS[random.nextInt(USER_AGENTS.length)];
            String sameSite = random.nextBoolean() ? "Strict" : "Lax";

            int changeIndex = 1 + random.nextInt(eventCount - 1);
            Instant sessionStart = baseTime.plusSeconds(random.nextInt(maxStartSpanSeconds));
            Instant currentTime = sessionStart;

            for (int e = 0; e < eventCount; e++) {
                if (e > 0) {
                    // Gap > 60 seconds (70 to 909 seconds = ~1.17 to 15.15 minutes)
                    // Ensuring ConcurrentSessionAnalyzer (diff <= 60s) does not fire
                    int gapSeconds = 70 + random.nextInt(14 * 60);
                    currentTime = currentTime.plusSeconds(gapSeconds);
                }
                String currentIp = (e < changeIndex) ? ip1 : ip2;
                allEvents.add(new EventRecord(sessionId, currentTime, userId, currentIp,
                        loc.city, loc.country, loc.latitude, loc.longitude,
                        userAgent, true, true, sameSite));
            }

            allLabels.add(new LabelRecord(sessionId, false, "NORMAL_BENIGN_IP_CHANGE"));
        }

        // -----------------------------------------------------------------
        // 3. 20 NORMAL_BENIGN_IP_AND_BROWSER_CHANGE sessions (is_anomaly = false)
        // -----------------------------------------------------------------
        for (int i = 0; i < 20; i++) {
            sessionIndex++;
            String sessionId = String.format("sess_%04d", sessionIndex);
            String userId = String.format("user_%04d", (sessionIndex % 100) + 1);

            int eventCount = 3 + random.nextInt(4); // 3 to 6 events
            CityLocation loc = CITIES[random.nextInt(CITIES.length)];

            String ip1 = loc.sampleIps[random.nextInt(loc.sampleIps.length)];
            String ip2 = loc.sampleIps[random.nextInt(loc.sampleIps.length)];
            while (ip2.equalsIgnoreCase(ip1) && loc.sampleIps.length > 1) {
                ip2 = loc.sampleIps[random.nextInt(loc.sampleIps.length)];
            }

            int uaIdx1 = random.nextInt(USER_AGENTS.length);
            int uaIdx2 = (uaIdx1 + 1 + random.nextInt(USER_AGENTS.length - 1)) % USER_AGENTS.length;
            String ua1 = USER_AGENTS[uaIdx1];
            String ua2 = USER_AGENTS[uaIdx2];

            String sameSite = random.nextBoolean() ? "Strict" : "Lax";

            int changeIndex = 1 + random.nextInt(eventCount - 1);
            Instant sessionStart = baseTime.plusSeconds(random.nextInt(maxStartSpanSeconds));
            Instant currentTime = sessionStart;

            for (int e = 0; e < eventCount; e++) {
                if (e > 0) {
                    // Gap > 60 seconds
                    int gapSeconds = 70 + random.nextInt(14 * 60);
                    currentTime = currentTime.plusSeconds(gapSeconds);
                }
                String currentIp = (e < changeIndex) ? ip1 : ip2;
                String currentUa = (e < changeIndex) ? ua1 : ua2;
                allEvents.add(new EventRecord(sessionId, currentTime, userId, currentIp,
                        loc.city, loc.country, loc.latitude, loc.longitude,
                        currentUa, true, true, sameSite));
            }

            allLabels.add(new LabelRecord(sessionId, false, "NORMAL_BENIGN_IP_AND_BROWSER_CHANGE"));
        }

        // -----------------------------------------------------------------
        // 4. 10 INSECURE_COOKIE sessions (is_anomaly = true)
        // -----------------------------------------------------------------
        for (int i = 0; i < 10; i++) {
            sessionIndex++;
            String sessionId = String.format("sess_%04d", sessionIndex);
            String userId = String.format("user_%04d", (sessionIndex % 100) + 1);

            int eventCount = 2 + random.nextInt(5); // 2 to 6 events
            CityLocation loc = CITIES[random.nextInt(CITIES.length)];
            String ip = loc.getRandomIp(random);
            String userAgent = USER_AGENTS[random.nextInt(USER_AGENTS.length)];

            Instant sessionStart = baseTime.plusSeconds(random.nextInt(maxStartSpanSeconds));
            Instant currentTime = sessionStart;

            for (int e = 0; e < eventCount; e++) {
                if (e > 0) {
                    int gapSeconds = 60 + random.nextInt(14 * 60 + 1);
                    currentTime = currentTime.plusSeconds(gapSeconds);
                }
                // Insecure flags: secure=false, httpOnly=false, sameSite="None"
                allEvents.add(new EventRecord(sessionId, currentTime, userId, ip,
                        loc.city, loc.country, loc.latitude, loc.longitude,
                        userAgent, false, false, "None"));
            }

            allLabels.add(new LabelRecord(sessionId, true, "INSECURE_COOKIE"));
        }

        // -----------------------------------------------------------------
        // 5. 10 IP_AND_BROWSER_CHANGE sessions (is_anomaly = true)
        // -----------------------------------------------------------------
        for (int i = 0; i < 10; i++) {
            sessionIndex++;
            String sessionId = String.format("sess_%04d", sessionIndex);
            String userId = String.format("user_%04d", (sessionIndex % 100) + 1);

            int eventCount = 3 + random.nextInt(3); // 3 to 5 events

            // Pick two distinct cities within the same country (India has 4 cities: indices 0..3)
            int cIdx1 = random.nextInt(4);
            int cIdx2 = (cIdx1 + 1 + random.nextInt(3)) % 4;
            CityLocation loc1 = CITIES[cIdx1];
            CityLocation loc2 = CITIES[cIdx2];

            String ip1 = loc1.getRandomIp(random);
            String ip2 = loc2.getRandomIp(random);

            int uaIdx1 = random.nextInt(USER_AGENTS.length);
            int uaIdx2 = (uaIdx1 + 1 + random.nextInt(USER_AGENTS.length - 1)) % USER_AGENTS.length;
            String ua1 = USER_AGENTS[uaIdx1];
            String ua2 = USER_AGENTS[uaIdx2];

            String sameSite = random.nextBoolean() ? "Strict" : "Lax";

            int changeIndex = 1 + random.nextInt(eventCount - 1);
            Instant sessionStart = baseTime.plusSeconds(random.nextInt(maxStartSpanSeconds));
            Instant currentTime = sessionStart;

            for (int e = 0; e < eventCount; e++) {
                if (e > 0) {
                    int gapSeconds = 70 + random.nextInt(14 * 60);
                    currentTime = currentTime.plusSeconds(gapSeconds);
                }
                CityLocation currentLoc = (e < changeIndex) ? loc1 : loc2;
                String currentIp = (e < changeIndex) ? ip1 : ip2;
                String currentUa = (e < changeIndex) ? ua1 : ua2;

                allEvents.add(new EventRecord(sessionId, currentTime, userId, currentIp,
                        currentLoc.city, currentLoc.country, currentLoc.latitude, currentLoc.longitude,
                        currentUa, true, true, sameSite));
            }

            allLabels.add(new LabelRecord(sessionId, true, "IP_AND_BROWSER_CHANGE"));
        }

        // -----------------------------------------------------------------
        // 6. 10 CONCURRENT_SESSION sessions (is_anomaly = true)
        // -----------------------------------------------------------------
        for (int i = 0; i < 10; i++) {
            sessionIndex++;
            String sessionId = String.format("sess_%04d", sessionIndex);
            String userId = String.format("user_%04d", (sessionIndex % 100) + 1);

            // Two distinct cities and IPs
            int cIdx1 = random.nextInt(CITIES.length);
            int cIdx2 = (cIdx1 + 1 + random.nextInt(CITIES.length - 1)) % CITIES.length;
            CityLocation loc1 = CITIES[cIdx1];
            CityLocation loc2 = CITIES[cIdx2];

            String ip1 = loc1.getRandomIp(random);
            String ip2 = loc2.getRandomIp(random);

            String userAgent = USER_AGENTS[random.nextInt(USER_AGENTS.length)];
            String sameSite = random.nextBoolean() ? "Strict" : "Lax";

            Instant sessionStart = baseTime.plusSeconds(random.nextInt(maxStartSpanSeconds));
            Instant t1 = sessionStart;
            // Within 30 seconds of another event of that session (5 to 25 seconds)
            int gapSeconds = 5 + random.nextInt(21);
            Instant t2 = t1.plusSeconds(gapSeconds);
            // Third event occurs 3 to 6 minutes later
            Instant t3 = t2.plusSeconds(180 + random.nextInt(180));

            allEvents.add(new EventRecord(sessionId, t1, userId, ip1,
                    loc1.city, loc1.country, loc1.latitude, loc1.longitude,
                    userAgent, true, true, sameSite));
            allEvents.add(new EventRecord(sessionId, t2, userId, ip2,
                    loc2.city, loc2.country, loc2.latitude, loc2.longitude,
                    userAgent, true, true, sameSite));
            allEvents.add(new EventRecord(sessionId, t3, userId, ip1,
                    loc1.city, loc1.country, loc1.latitude, loc1.longitude,
                    userAgent, true, true, sameSite));

            allLabels.add(new LabelRecord(sessionId, true, "CONCURRENT_SESSION"));
        }

        // -----------------------------------------------------------------
        // 7. 10 IMPOSSIBLE_TRAVEL sessions (is_anomaly = true)
        // -----------------------------------------------------------------
        for (int i = 0; i < 10; i++) {
            sessionIndex++;
            String sessionId = String.format("sess_%04d", sessionIndex);
            String userId = String.format("user_%04d", (sessionIndex % 100) + 1);

            // Distant city pair (> 2000 km apart)
            int[] pair = DISTANT_CITY_PAIRS[i % DISTANT_CITY_PAIRS.length];
            CityLocation loc1 = CITIES[pair[0]];
            CityLocation loc2 = CITIES[pair[1]];

            String ip1 = loc1.getRandomIp(random);
            String ip2 = loc2.getRandomIp(random);
            String userAgent = USER_AGENTS[random.nextInt(USER_AGENTS.length)];
            String sameSite = random.nextBoolean() ? "Strict" : "Lax";

            Instant sessionStart = baseTime.plusSeconds(random.nextInt(maxStartSpanSeconds));
            Instant t1 = sessionStart;
            // 5 to 20 minutes apart (300 to 1200 seconds)
            int gapSeconds = 300 + random.nextInt(901);
            Instant t2 = t1.plusSeconds(gapSeconds);
            Instant t3 = t2.plusSeconds(300 + random.nextInt(300));

            allEvents.add(new EventRecord(sessionId, t1, userId, ip1,
                    loc1.city, loc1.country, loc1.latitude, loc1.longitude,
                    userAgent, true, true, sameSite));
            allEvents.add(new EventRecord(sessionId, t2, userId, ip2,
                    loc2.city, loc2.country, loc2.latitude, loc2.longitude,
                    userAgent, true, true, sameSite));
            allEvents.add(new EventRecord(sessionId, t3, userId, ip2,
                    loc2.city, loc2.country, loc2.latitude, loc2.longitude,
                    userAgent, true, true, sameSite));

            allLabels.add(new LabelRecord(sessionId, true, "IMPOSSIBLE_TRAVEL"));
        }

        // -----------------------------------------------------------------
        // 8. 10 BEHAVIOR_BURST sessions (is_anomaly = true)
        // -----------------------------------------------------------------
        for (int i = 0; i < 10; i++) {
            sessionIndex++;
            String sessionId = String.format("sess_%04d", sessionIndex);
            String userId = String.format("user_%04d", (sessionIndex % 100) + 1);

            int burstEvents = 40 + random.nextInt(21); // 40 to 60 events
            CityLocation loc = CITIES[random.nextInt(CITIES.length)];
            String ip = loc.getRandomIp(random);
            String userAgent = USER_AGENTS[random.nextInt(USER_AGENTS.length)];
            String sameSite = random.nextBoolean() ? "Strict" : "Lax";

            Instant sessionStart = baseTime.plusSeconds(random.nextInt(maxStartSpanSeconds));
            Instant currentTime = sessionStart;

            for (int e = 0; e < burstEvents; e++) {
                if (e > 0) {
                    // Only 1 to 3 seconds apart
                    int stepSeconds = 1 + random.nextInt(3);
                    currentTime = currentTime.plusSeconds(stepSeconds);
                }
                // Clean cookies, single IP, single browser, same city -> no existing rule fires
                allEvents.add(new EventRecord(sessionId, currentTime, userId, ip,
                        loc.city, loc.country, loc.latitude, loc.longitude,
                        userAgent, true, true, sameSite));
            }

            allLabels.add(new LabelRecord(sessionId, true, "BEHAVIOR_BURST"));
        }

        // -----------------------------------------------------------------
        // 9. Sort all events chronologically so sessions are interleaved
        // -----------------------------------------------------------------
        Collections.sort(allEvents);

        // -----------------------------------------------------------------
        // 10. Ensure target parent directories exist
        // -----------------------------------------------------------------
        if (eventsFile.getParent() != null) {
            Files.createDirectories(eventsFile.getParent());
        }
        if (labelsFile.getParent() != null) {
            Files.createDirectories(labelsFile.getParent());
        }

        // -----------------------------------------------------------------
        // 11. Write events CSV
        // -----------------------------------------------------------------
        try (BufferedWriter writer = Files.newBufferedWriter(eventsFile)) {
            writer.write("session_id,event_time,user_id,ip_address,city,country,latitude,longitude,user_agent,secure,http_only,same_site");
            writer.newLine();
            for (EventRecord event : allEvents) {
                writer.write(event.toCsvRow());
                writer.newLine();
            }
        }

        // -----------------------------------------------------------------
        // 12. Write labels CSV
        // -----------------------------------------------------------------
        try (BufferedWriter writer = Files.newBufferedWriter(labelsFile)) {
            writer.write("session_id,is_anomaly,scenario");
            writer.newLine();
            for (LabelRecord label : allLabels) {
                writer.write(label.toCsvRow());
                writer.newLine();
            }
        }
    }
}
