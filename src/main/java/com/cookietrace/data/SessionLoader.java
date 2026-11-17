package com.cookietrace.data;

import com.cookietrace.exception.InvalidSessionDataException;
import com.cookietrace.model.CookieInfo;
import com.cookietrace.model.SessionEvent;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads and parses web session events from a CSV log file.
 *
 * Resilience Design:
 * - If any row is corrupted (e.g., missing columns, invalid numbers, or failed validation checks),
 *   SessionLoader skips that row, increments the rejected counter, and logs a descriptive reason.
 * - This prevents the entire pipeline from failing due to bad or malformed log entries.
 */
public class SessionLoader {

    // Counter tracking how many invalid rows were skipped
    private int rejectedCount = 0;

    /**
     * Reads a session event CSV file and returns a list of valid SessionEvent objects.
     *
     * @param eventsFile Path to the CSV file
     * @return List of parsed SessionEvent objects
     */
    public List<SessionEvent> load(Path eventsFile) {
        rejectedCount = 0;
        List<SessionEvent> events = new ArrayList<SessionEvent>();

        if (eventsFile == null || !Files.exists(eventsFile)) {
            System.err.println("Warning: Events file does not exist: " + eventsFile);
            return events;
        }

        try (BufferedReader reader = Files.newBufferedReader(eventsFile)) {
            int lineNumber = 0;
            String line;

            // Read the header row first and skip it
            String header = reader.readLine();
            lineNumber++;

            while ((line = reader.readLine()) != null) {
                lineNumber++;
                String trimmedLine = line.trim();

                // Skip blank lines
                if (trimmedLine.isEmpty()) {
                    continue;
                }

                // Expected CSV format:
                // session_id,event_time,user_id,ip_address,city,country,latitude,longitude,user_agent,secure,http_only,same_site
                String[] parts = trimmedLine.split(",");

                if (parts.length != 12) {
                    rejectedCount++;
                    System.out.println("Line " + lineNumber + " skipped: Expected 12 columns but found " + parts.length);
                    continue;
                }

                try {
                    String sessionId = parts[0].trim();
                    Instant eventTime = Instant.parse(parts[1].trim());
                    String userId = parts[2].trim();
                    String ipAddress = parts[3].trim();
                    String city = parts[4].trim();
                    String country = parts[5].trim();
                    double latitude = Double.parseDouble(parts[6].trim());
                    double longitude = Double.parseDouble(parts[7].trim());
                    String userAgent = parts[8].trim();
                    boolean secure = Boolean.parseBoolean(parts[9].trim());
                    boolean httpOnly = Boolean.parseBoolean(parts[10].trim());
                    String sameSite = parts[11].trim();

                    // Instantiate CookieInfo (validates sameSite)
                    CookieInfo cookie = new CookieInfo(secure, httpOnly, sameSite);

                    // Instantiate SessionEvent (validates IP, coordinates, non-blank strings)
                    SessionEvent event = new SessionEvent(
                            sessionId, eventTime, userId, ipAddress,
                            city, country, latitude, longitude,
                            userAgent, cookie
                    );

                    events.add(event);

                } catch (InvalidSessionDataException e) {
                    rejectedCount++;
                    System.out.println("Line " + lineNumber + " rejected (validation error): " + e.getMessage());
                } catch (DateTimeParseException e) {
                    rejectedCount++;
                    System.out.println("Line " + lineNumber + " rejected (invalid date format): " + e.getMessage());
                } catch (NumberFormatException e) {
                    rejectedCount++;
                    System.out.println("Line " + lineNumber + " rejected (invalid coordinate number): " + e.getMessage());
                } catch (Exception e) {
                    rejectedCount++;
                    System.out.println("Line " + lineNumber + " rejected: " + e.getMessage());
                }
            }

        } catch (IOException e) {
            System.err.println("I/O error while reading file: " + eventsFile + " (" + e.getMessage() + ")");
        }

        return events;
    }

    /**
     * Returns the number of malformed or invalid rows that were rejected during the last load operation.
     *
     * @return Number of rejected rows
     */
    public int getRejectedCount() {
        return rejectedCount;
    }
}
