package com.cookietrace.analysis;

import com.cookietrace.model.CookieInfo;
import com.cookietrace.model.SessionEvent;

import java.time.Duration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * FeatureExtractor transforms raw web session event streams into numerical feature vectors
 * suitable for machine learning anomaly detection (e.g. Isolation Forest).
 *
 * It extracts 9 distinct behavioral, temporal, network, and security metrics for each session.
 */
public class FeatureExtractor {

    /**
     * Exact names of the 9 extracted features in sequential column order.
     */
    public static final String[] FEATURE_NAMES = new String[] {
        "eventCount",
        "durationSeconds",
        "distinctIps",
        "distinctCities",
        "distinctUserAgents",
        "minGapSeconds",
        "maxGapSeconds",
        "missingCookieFlags",
        "maxDistanceKm"
    };

    /**
     * Extracts numerical feature vectors for all provided sessions.
     *
     * @param sessions Map of sessionId to chronologically sorted list of session events
     * @return Map of sessionId to double[] feature vector of length 9
     */
    public Map<String, double[]> extract(Map<String, List<SessionEvent>> sessions) {
        Map<String, double[]> featureMap = new LinkedHashMap<String, double[]>();

        if (sessions == null) {
            return featureMap;
        }

        for (Map.Entry<String, List<SessionEvent>> entry : sessions.entrySet()) {
            String sessionId = entry.getKey();
            List<SessionEvent> se = entry.getValue();

            double[] row = new double[FEATURE_NAMES.length];

            if (se == null || se.isEmpty()) {
                featureMap.put(sessionId, row);
                continue;
            }

            // 1. eventCount
            double eventCount = se.size();

            // 2. durationSeconds (last event time minus first event time)
            double durationSeconds = 0.0;
            if (se.size() > 1) {
                durationSeconds = Math.abs(Duration.between(
                        se.get(0).getEventTime(),
                        se.get(se.size() - 1).getEventTime()
                ).getSeconds());
            }

            // 3. distinctIps, 4. distinctCities, 5. distinctUserAgents
            Set<String> uniqueIps = new HashSet<String>();
            Set<String> uniqueCities = new HashSet<String>();
            Set<String> uniqueUas = new HashSet<String>();

            // 8. missingCookieFlags (0-3: count of secure=false, httpOnly=false, sameSite=None)
            boolean secureMissing = false;
            boolean httpOnlyMissing = false;
            boolean sameSiteNone = false;

            // 6. minGapSeconds, 7. maxGapSeconds, 9. maxDistanceKm
            double minGap = Double.MAX_VALUE;
            double maxGap = 0.0;
            double maxDistKm = 0.0;

            for (int i = 0; i < se.size(); i++) {
                SessionEvent current = se.get(i);
                uniqueIps.add(current.getIpAddress());
                uniqueCities.add(current.getCity());
                uniqueUas.add(current.getUserAgent());

                CookieInfo cookie = current.getCookie();
                if (!cookie.isSecure()) {
                    secureMissing = true;
                }
                if (!cookie.isHttpOnly()) {
                    httpOnlyMissing = true;
                }
                if ("None".equalsIgnoreCase(cookie.getSameSite())) {
                    sameSiteNone = true;
                }

                // Consecutive pair metrics
                if (i < se.size() - 1) {
                    SessionEvent next = se.get(i + 1);

                    double gapSec = Math.abs(Duration.between(
                            current.getEventTime(),
                            next.getEventTime()
                    ).getSeconds());

                    if (gapSec < minGap) {
                        minGap = gapSec;
                    }
                    if (gapSec > maxGap) {
                        maxGap = gapSec;
                    }

                    double dist = haversineDistanceKm(
                            current.getLatitude(), current.getLongitude(),
                            next.getLatitude(), next.getLongitude()
                    );
                    if (dist > maxDistKm) {
                        maxDistKm = dist;
                    }
                }
            }

            // If session had fewer than 2 events, gaps are 0
            if (minGap == Double.MAX_VALUE) {
                minGap = 0.0;
            }

            double missingCookieCount = (secureMissing ? 1.0 : 0.0) +
                                        (httpOnlyMissing ? 1.0 : 0.0) +
                                        (sameSiteNone ? 1.0 : 0.0);

            row[0] = eventCount;
            row[1] = durationSeconds;
            row[2] = uniqueIps.size();
            row[3] = uniqueCities.size();
            row[4] = uniqueUas.size();
            row[5] = minGap;
            row[6] = maxGap;
            row[7] = missingCookieCount;
            row[8] = maxDistKm;

            featureMap.put(sessionId, row);
        }

        return featureMap;
    }

    /**
     * Great-circle distance between two points on Earth using the Haversine formula.
     *
     * @param lat1 Latitude 1
     * @param lon1 Longitude 1
     * @param lat2 Latitude 2
     * @param lon2 Longitude 2
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
