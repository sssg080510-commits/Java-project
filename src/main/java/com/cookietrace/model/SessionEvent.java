package com.cookietrace.model;

import com.cookietrace.exception.InvalidSessionDataException;

import java.time.Instant;

/**
 * Represents an individual event observed during a user's web session.
 *
 * Encapsulation Design:
 * - All fields are declared 'private final' to ensure immutability and complete data integrity.
 * - By disallowing setters, no external class can alter sensitive audit information (such as
 *   tampering with the IP address, timestamp, or geo-coordinates) once the event is logged.
 * - The constructor validates all inputs immediately upon creation (fail-fast principle),
 *   guaranteeing that corrupted or invalid events cannot circulate in the detection pipeline.
 */
public class SessionEvent {

    // Private final fields to enforce encapsulation and state protection
    private final String sessionId;
    private final Instant eventTime;
    private final String userId;
    private final String ipAddress;
    private final String city;
    private final String country;
    private final double latitude;
    private final double longitude;
    private final String userAgent;
    private final CookieInfo cookie;

    /**
     * Constructs and strictly validates a new SessionEvent.
     *
     * @param sessionId  Unique session identifier
     * @param eventTime  Timestamp of the event (UTC Instant)
     * @param userId     Unique user identifier
     * @param ipAddress  Client IPv4 address
     * @param city       Geographic city name
     * @param country    Geographic country name
     * @param latitude   Geographic latitude (-90 to +90)
     * @param longitude  Geographic longitude (-180 to +180)
     * @param userAgent  Browser/client user agent string
     * @param cookie     Associated CookieInfo object
     * @throws InvalidSessionDataException If any validation check fails
     */
    public SessionEvent(String sessionId, Instant eventTime, String userId,
                        String ipAddress, String city, String country,
                        double latitude, double longitude, String userAgent,
                        CookieInfo cookie) {

        // Validate sessionId
        if (sessionId == null || sessionId.trim().isEmpty()) {
            throw new InvalidSessionDataException("sessionId cannot be null or blank.");
        }

        // Validate eventTime
        if (eventTime == null) {
            throw new InvalidSessionDataException("eventTime cannot be null.");
        }

        // Validate userId
        if (userId == null || userId.trim().isEmpty()) {
            throw new InvalidSessionDataException("userId cannot be null or blank.");
        }

        // Validate ipAddress
        if (ipAddress == null || ipAddress.trim().isEmpty()) {
            throw new InvalidSessionDataException("ipAddress cannot be null or blank.");
        }
        if (!isValidIpv4(ipAddress.trim())) {
            throw new InvalidSessionDataException(
                "ipAddress must be a valid IPv4 address (e.g., 192.168.1.1). Received: '" + ipAddress + "'"
            );
        }

        // Validate userAgent
        if (userAgent == null || userAgent.trim().isEmpty()) {
            throw new InvalidSessionDataException("userAgent cannot be null or blank.");
        }

        // Validate latitude (-90 to +90)
        if (latitude < -90.0 || latitude > 90.0) {
            throw new InvalidSessionDataException(
                "latitude must be between -90.0 and 90.0. Received: " + latitude
            );
        }

        // Validate longitude (-180 to +180)
        if (longitude < -180.0 || longitude > 180.0) {
            throw new InvalidSessionDataException(
                "longitude must be between -180.0 and 180.0. Received: " + longitude
            );
        }

        // Validate cookie
        if (cookie == null) {
            throw new InvalidSessionDataException("cookie cannot be null.");
        }

        this.sessionId = sessionId.trim();
        this.eventTime = eventTime;
        this.userId = userId.trim();
        this.ipAddress = ipAddress.trim();
        this.city = (city != null) ? city.trim() : "";
        this.country = (country != null) ? country.trim() : "";
        this.latitude = latitude;
        this.longitude = longitude;
        this.userAgent = userAgent.trim();
        this.cookie = cookie;
    }

    /**
     * Beginner-friendly helper method to validate standard IPv4 format (4 octets, 0-255).
     *
     * @param ip The IP address string to check
     * @return true if valid IPv4, false otherwise
     */
    private static boolean isValidIpv4(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            if (part.isEmpty()) {
                return false;
            }
            try {
                int octet = Integer.parseInt(part);
                if (octet < 0 || octet > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    // Read-only getters (no setters)

    public String getSessionId() {
        return sessionId;
    }

    public Instant getEventTime() {
        return eventTime;
    }

    public String getUserId() {
        return userId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getCity() {
        return city;
    }

    public String getCountry() {
        return country;
    }

    public double getLatitude() {
        return latitude;
    }

    public double getLongitude() {
        return longitude;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public CookieInfo getCookie() {
        return cookie;
    }

    @Override
    public String toString() {
        return "SessionEvent{" +
                "session='" + sessionId + '\'' +
                ", time=" + eventTime +
                ", user='" + userId + '\'' +
                ", ip='" + ipAddress + '\'' +
                ", location='" + city + ", " + country + "' (" + latitude + ", " + longitude + ")" +
                ", browser='" + userAgent + '\'' +
                ", cookie=" + cookie +
                '}';
    }
}
