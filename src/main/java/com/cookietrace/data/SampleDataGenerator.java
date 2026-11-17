package com.cookietrace.data;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Random;

/**
 * SampleDataGenerator is responsible for generating simulated web session logs
 * and ground-truth labels for the CookieTrace threat detection tool.
 *
 * It creates realistic session events with both normal browsing patterns and
 * specific attack scenarios (e.g., cookie theft, session hijacking, impossible travel).
 */
public class SampleDataGenerator {

    /**
     * Inner helper class representing a single city with geographic and network details.
     * Simple plain Java object so students can easily explain it in viva.
     */
    private static class CityLocation {
        String city;
        String country;
        double latitude;
        double longitude;
        String[] sampleIps;

        CityLocation(String city, String country, double latitude, double longitude, String[] sampleIps) {
            this.city = city;
            this.country = country;
            this.latitude = latitude;
            this.longitude = longitude;
            this.sampleIps = sampleIps;
        }

        // Returns a random IP address assigned to this city
        String getRandomIp(Random random) {
            int index = random.nextInt(sampleIps.length);
            return sampleIps[index];
        }
    }

    /**
     * Inner class representing a single event in a web session.
     * Implements Comparable so events can be sorted chronologically by event_time.
     */
    public static class SessionEvent implements Comparable<SessionEvent> {
        public String sessionId;
        public Instant eventTime;
        public String userId;
        public String ipAddress;
        public String city;
        public String country;
        public double latitude;
        public double longitude;
        public String userAgent;
        public boolean secure;
        public boolean httpOnly;
        public String sameSite;

        public SessionEvent(String sessionId, Instant eventTime, String userId,
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

        /**
         * Converts this event into a CSV row matching the required format.
         */
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
        public int compareTo(SessionEvent other) {
            return this.eventTime.compareTo(other.eventTime);
        }
    }

    /**
     * Inner class representing ground truth label for a session.
     */
    public static class SessionLabel {
        public String sessionId;
        public boolean isAnomaly;
        public String scenario;

        public SessionLabel(String sessionId, boolean isAnomaly, String scenario) {
            this.sessionId = sessionId;
            this.isAnomaly = isAnomaly;
            this.scenario = scenario;
        }

        public String toCsvRow() {
            return sessionId + "," + isAnomaly + "," + scenario;
        }
    }

    /**
     * Pre-defined cities with realistic coordinates and public-looking example IPs.
     */
    private static final CityLocation[] CITIES = new CityLocation[] {
        new CityLocation("Chennai", "India", 13.0827, 80.2707,
                new String[] {"49.207.180.25", "49.207.181.10", "157.48.12.34"}),
        new CityLocation("Mumbai", "India", 19.0760, 72.8777,
                new String[] {"103.21.124.50", "103.21.125.12", "115.112.45.67"}),
        new CityLocation("Delhi", "India", 28.6139, 77.2090,
                new String[] {"122.161.45.80", "122.161.46.90", "182.73.102.44"}),
        new CityLocation("London", "United Kingdom", 51.5074, -0.1278,
                new String[] {"82.165.197.1", "82.165.198.5", "151.101.0.81"}),
        new CityLocation("New York", "United States", 40.7128, -74.0060,
                new String[] {"198.51.100.42", "72.229.28.185", "68.180.20.15"})
    };

    /**
     * Common user agents (without commas to avoid simple CSV splitting issues).
     */
    private static final String[] USER_AGENTS = new String[] {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0 Safari/537.36"
    };

    /**
     * Generates simulated session events and corresponding ground truth labels.
     *
     * @param sessionCount Total number of sessions to generate (e.g. 20)
     * @param seed         Seed for java.util.Random to ensure repeatability
     * @param eventsFile   Target path for events CSV file
     * @param labelsFile   Target path for labels CSV file
     * @throws IOException If writing to disk fails
     */
    public void generate(int sessionCount, long seed, Path eventsFile, Path labelsFile) throws IOException {
        Random random = new Random(seed);

        List<SessionEvent> allEvents = new ArrayList<SessionEvent>();
        List<SessionLabel> allLabels = new ArrayList<SessionLabel>();

        // Base start timestamp: 2026-03-01 08:00:00 UTC
        Instant baseTime = Instant.parse("2026-03-01T08:00:00Z");

        // Determine normal vs attack counts
        int attackCount = Math.min(4, sessionCount);
        int normalCount = sessionCount - attackCount;

        int sessionIndex = 0;

        // -------------------------------------------------------------
        // 1. Generate NORMAL sessions (e.g. 16 sessions)
        // -------------------------------------------------------------
        for (int i = 0; i < normalCount; i++) {
            sessionIndex++;
            String sessionId = String.format("sess_%04d", sessionIndex);
            String userId = String.format("user_%03d", (sessionIndex % 15) + 1);

            // Normal session: pick one location and one browser for all 3 events
            CityLocation location = CITIES[random.nextInt(CITIES.length)];
            String ip = location.getRandomIp(random);
            String userAgent = USER_AGENTS[random.nextInt(USER_AGENTS.length)];
            String sameSite = random.nextBoolean() ? "Strict" : "Lax";

            // Session start time staggered across the day
            Instant sessionStart = baseTime.plusSeconds(i * 1200L + random.nextInt(300));

            // Event 1
            Instant t1 = sessionStart;
            allEvents.add(new SessionEvent(sessionId, t1, userId, ip, location.city, location.country,
                    location.latitude, location.longitude, userAgent, true, true, sameSite));

            // Event 2 (3 to 6 minutes later)
            Instant t2 = t1.plusSeconds(180 + random.nextInt(180));
            allEvents.add(new SessionEvent(sessionId, t2, userId, ip, location.city, location.country,
                    location.latitude, location.longitude, userAgent, true, true, sameSite));

            // Event 3 (3 to 6 minutes after Event 2)
            Instant t3 = t2.plusSeconds(180 + random.nextInt(180));
            allEvents.add(new SessionEvent(sessionId, t3, userId, ip, location.city, location.country,
                    location.latitude, location.longitude, userAgent, true, true, sameSite));

            // Normal label
            allLabels.add(new SessionLabel(sessionId, false, "NORMAL"));
        }

        // -------------------------------------------------------------
        // 2. Generate ATTACK-LIKE sessions (4 scenarios, 1 of each)
        // -------------------------------------------------------------

        // Scenario a: INSECURE_COOKIE
        // Cookie lacks secure and httpOnly flags, and sameSite is set to None.
        if (sessionIndex < sessionCount) {
            sessionIndex++;
            String sessionId = String.format("sess_%04d", sessionIndex);
            String userId = String.format("user_%03d", (sessionIndex % 15) + 1);

            CityLocation location = CITIES[random.nextInt(CITIES.length)];
            String ip = location.getRandomIp(random);
            String userAgent = USER_AGENTS[random.nextInt(USER_AGENTS.length)];

            Instant sessionStart = baseTime.plusSeconds(sessionIndex * 1200L + 50);
            Instant t1 = sessionStart;
            Instant t2 = t1.plusSeconds(200);
            Instant t3 = t2.plusSeconds(200);

            // Insecure cookie settings: secure=false, http_only=false, same_site=None
            allEvents.add(new SessionEvent(sessionId, t1, userId, ip, location.city, location.country,
                    location.latitude, location.longitude, userAgent, false, false, "None"));
            allEvents.add(new SessionEvent(sessionId, t2, userId, ip, location.city, location.country,
                    location.latitude, location.longitude, userAgent, false, false, "None"));
            allEvents.add(new SessionEvent(sessionId, t3, userId, ip, location.city, location.country,
                    location.latitude, location.longitude, userAgent, false, false, "None"));

            allLabels.add(new SessionLabel(sessionId, true, "INSECURE_COOKIE"));
        }

        // Scenario b: IP_AND_BROWSER_CHANGE
        // Same city, but the IP and User-Agent change in the 3rd event.
        if (sessionIndex < sessionCount) {
            sessionIndex++;
            String sessionId = String.format("sess_%04d", sessionIndex);
            String userId = String.format("user_%03d", (sessionIndex % 15) + 1);

            // Pick a city with multiple IPs (e.g. Mumbai)
            CityLocation location = CITIES[1]; // Mumbai
            String ip1 = location.sampleIps[0];
            String ip2 = location.sampleIps[1]; // Changed IP in same city

            String ua1 = USER_AGENTS[0]; // Chrome Windows
            String ua2 = USER_AGENTS[1]; // Firefox Windows (Changed browser)

            Instant sessionStart = baseTime.plusSeconds(sessionIndex * 1200L + 80);
            Instant t1 = sessionStart;
            Instant t2 = t1.plusSeconds(210);
            Instant t3 = t2.plusSeconds(240);

            allEvents.add(new SessionEvent(sessionId, t1, userId, ip1, location.city, location.country,
                    location.latitude, location.longitude, ua1, true, true, "Lax"));
            allEvents.add(new SessionEvent(sessionId, t2, userId, ip1, location.city, location.country,
                    location.latitude, location.longitude, ua1, true, true, "Lax"));
            // 3rd event has new IP and new User-Agent in the same city
            allEvents.add(new SessionEvent(sessionId, t3, userId, ip2, location.city, location.country,
                    location.latitude, location.longitude, ua2, true, true, "Lax"));

            allLabels.add(new SessionLabel(sessionId, true, "IP_AND_BROWSER_CHANGE"));
        }

        // Scenario c: CONCURRENT_SESSION
        // Same session appears from different IP and city at nearly the same time.
        // Total remains 3 events by replacing event 2 with a concurrent event from another city.
        if (sessionIndex < sessionCount) {
            sessionIndex++;
            String sessionId = String.format("sess_%04d", sessionIndex);
            String userId = String.format("user_%03d", (sessionIndex % 15) + 1);

            CityLocation loc1 = CITIES[2]; // Delhi
            CityLocation loc2 = CITIES[1]; // Mumbai

            String ip1 = loc1.getRandomIp(random);
            String ip2 = loc2.getRandomIp(random);
            String ua = USER_AGENTS[2]; // Mac Safari

            Instant sessionStart = baseTime.plusSeconds(sessionIndex * 1200L + 120);
            Instant t1 = sessionStart;
            // Event 2 is only 5 seconds after Event 1, but from Mumbai instead of Delhi
            Instant t2 = t1.plusSeconds(5);
            // Event 3 occurs 4 minutes later
            Instant t3 = t1.plusSeconds(240);

            allEvents.add(new SessionEvent(sessionId, t1, userId, ip1, loc1.city, loc1.country,
                    loc1.latitude, loc1.longitude, ua, true, true, "Strict"));
            allEvents.add(new SessionEvent(sessionId, t2, userId, ip2, loc2.city, loc2.country,
                    loc2.latitude, loc2.longitude, ua, true, true, "Strict"));
            allEvents.add(new SessionEvent(sessionId, t3, userId, ip1, loc1.city, loc1.country,
                    loc1.latitude, loc1.longitude, ua, true, true, "Strict"));

            allLabels.add(new SessionLabel(sessionId, true, "CONCURRENT_SESSION"));
        }

        // Scenario d: IMPOSSIBLE_TRAVEL
        // Event 1 in Chennai, event 2 in London only 10 minutes later.
        if (sessionIndex < sessionCount) {
            sessionIndex++;
            String sessionId = String.format("sess_%04d", sessionIndex);
            String userId = String.format("user_%03d", (sessionIndex % 15) + 1);

            CityLocation chennai = CITIES[0]; // Chennai
            CityLocation london = CITIES[3];  // London

            String ipChennai = chennai.getRandomIp(random);
            String ipLondon = london.getRandomIp(random);
            String ua = USER_AGENTS[0];

            Instant sessionStart = baseTime.plusSeconds(sessionIndex * 1200L + 160);
            Instant t1 = sessionStart;
            // Exactly 10 minutes (600 seconds) later in London!
            Instant t2 = t1.plusSeconds(600);
            Instant t3 = t2.plusSeconds(600);

            allEvents.add(new SessionEvent(sessionId, t1, userId, ipChennai, chennai.city, chennai.country,
                    chennai.latitude, chennai.longitude, ua, true, true, "Lax"));
            allEvents.add(new SessionEvent(sessionId, t2, userId, ipLondon, london.city, london.country,
                    london.latitude, london.longitude, ua, true, true, "Lax"));
            allEvents.add(new SessionEvent(sessionId, t3, userId, ipLondon, london.city, london.country,
                    london.latitude, london.longitude, ua, true, true, "Lax"));

            allLabels.add(new SessionLabel(sessionId, true, "IMPOSSIBLE_TRAVEL"));
        }

        // -------------------------------------------------------------
        // 3. Sort all events chronologically by event_time
        // -------------------------------------------------------------
        Collections.sort(allEvents);

        // -------------------------------------------------------------
        // 4. Ensure destination parent directories exist
        // -------------------------------------------------------------
        if (eventsFile.getParent() != null) {
            Files.createDirectories(eventsFile.getParent());
        }
        if (labelsFile.getParent() != null) {
            Files.createDirectories(labelsFile.getParent());
        }

        // -------------------------------------------------------------
        // 5. Write Events CSV
        // -------------------------------------------------------------
        BufferedWriter eventWriter = Files.newBufferedWriter(eventsFile);
        try {
            // Header row as specified
            eventWriter.write("session_id,event_time,user_id,ip_address,city,country,latitude,longitude,user_agent,secure,http_only,same_site");
            eventWriter.newLine();

            for (SessionEvent event : allEvents) {
                eventWriter.write(event.toCsvRow());
                eventWriter.newLine();
            }
        } finally {
            eventWriter.close();
        }

        // -------------------------------------------------------------
        // 6. Write Labels CSV
        // -------------------------------------------------------------
        BufferedWriter labelWriter = Files.newBufferedWriter(labelsFile);
        try {
            // Header row as specified
            labelWriter.write("session_id,is_anomaly,scenario");
            labelWriter.newLine();

            for (SessionLabel label : allLabels) {
                labelWriter.write(label.toCsvRow());
                labelWriter.newLine();
            }
        } finally {
            labelWriter.close();
        }
    }
}
