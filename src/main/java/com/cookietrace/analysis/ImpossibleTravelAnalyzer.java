package com.cookietrace.analysis;

import com.cookietrace.model.Alert;
import com.cookietrace.model.SessionEvent;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * ImpossibleTravelAnalyzer flags sessions where consecutive requests originate from
 * geographic locations too far apart to be physically reachable within the elapsed time.
 *
 * Attack Vectors Targeted:
 * - Geographically Dispersed Session Hijacking: An attacker on a different continent
 *   or distant city uses a compromised session token while the legitimate user's session
 *   is still active.
 * - Credential Stuffing / Proxy Rotation: Automated attacks routing stolen session tokens
 *   through multi-region exit nodes.
 */
public class ImpossibleTravelAnalyzer extends SecurityAnalyzer {

    /**
     * Constructs an ImpossibleTravelAnalyzer with a maximum risk score of 40.
     */
    public ImpossibleTravelAnalyzer() {
        super("ImpossibleTravelAnalyzer", 40);
    }

    @Override
    public List<Alert> analyze(List<SessionEvent> events) {
        List<Alert> alerts = new ArrayList<Alert>();
        Map<String, List<SessionEvent>> sessionMap = groupBySession(events);

        for (Map.Entry<String, List<SessionEvent>> entry : sessionMap.entrySet()) {
            String sessionId = entry.getKey();
            List<SessionEvent> sessionEvents = entry.getValue();

            // Need at least 2 events to measure travel speed
            if (sessionEvents.size() < 2) {
                continue;
            }

            boolean impossibleFound = false;
            String fromCity = "";
            String toCity = "";
            double alertDistanceKm = 0.0;
            double alertMinutes = 0.0;
            double alertSpeedKmH = 0.0;

            for (int i = 0; i < sessionEvents.size() - 1; i++) {
                SessionEvent e1 = sessionEvents.get(i);
                SessionEvent e2 = sessionEvents.get(i + 1);

                double distanceKm = haversineDistanceKm(
                        e1.getLatitude(), e1.getLongitude(),
                        e2.getLatitude(), e2.getLongitude()
                );

                long seconds = Math.abs(Duration.between(e1.getEventTime(), e2.getEventTime()).getSeconds());

                // Guard against zero or near-zero time gap to prevent division by zero
                double hours = Math.max(seconds / 3600.0, 0.0001);
                double speedKmH = distanceKm / hours;

                // Threshold: travel distance > 100 km and speed > 900 km/h (faster than commercial passenger flights)
                if (distanceKm > 100.0 && speedKmH > 900.0) {
                    impossibleFound = true;
                    fromCity = e1.getCity();
                    toCity = e2.getCity();
                    alertDistanceKm = distanceKm;
                    alertMinutes = seconds / 60.0;
                    alertSpeedKmH = speedKmH;
                    break;
                }
            }

            // Emit at most one Alert per session
            if (impossibleFound) {
                String explanation = String.format(
                        Locale.US,
                        "Impossible travel detected between %s and %s: distance %.1f km traveled in %.1f minutes, implying an impossible speed of %.1f km/h.",
                        fromCity, toCity, alertDistanceKm, alertMinutes, alertSpeedKmH
                );

                String recommendation = "Treat as likely stolen session and require re-authentication.";

                alerts.add(buildAlert(sessionId, 40, explanation, recommendation));
            }
        }

        return alerts;
    }

    /**
     * Calculates the great-circle distance between two geographic coordinates using the Haversine formula.
     *
     * In viva explanation:
     * - The Earth is approximated as a sphere with mean radius R = 6371.0 km.
     * - Converts latitude and longitude differences from degrees to radians.
     * - Applies spherical trigonometry: a = sin²(Δlat/2) + cos(lat1)*cos(lat2)*sin²(Δlon/2)
     * - Central angle c = 2 * atan2(√a, √(1-a))
     * - Distance = R * c
     *
     * @param lat1 Latitude of first point in degrees
     * @param lon1 Longitude of first point in degrees
     * @param lat2 Latitude of second point in degrees
     * @param lon2 Longitude of second point in degrees
     * @return Distance in kilometers
     */
    private double haversineDistanceKm(double lat1, double lon1, double lat2, double lon2) {
        final double EARTH_RADIUS_KM = 6371.0;

        double dLat = Math.toRadians(lat2 - lat1);
        double dLon = Math.toRadians(lon2 - lon1);

        double radLat1 = Math.toRadians(lat1);
        double radLat2 = Math.toRadians(lat2);

        double a = Math.sin(dLat / 2.0) * Math.sin(dLat / 2.0) +
                   Math.cos(radLat1) * Math.cos(radLat2) *
                   Math.sin(dLon / 2.0) * Math.sin(dLon / 2.0);

        double c = 2.0 * Math.atan2(Math.sqrt(a), Math.sqrt(1.0 - a));

        return EARTH_RADIUS_KM * c;
    }
}
