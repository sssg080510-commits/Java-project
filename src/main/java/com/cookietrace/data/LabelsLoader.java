package com.cookietrace.data;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Loads ground-truth evaluation labels from a CSV file (e.g. data/labels_eval.csv).
 *
 * Expected CSV columns:
 * session_id,is_anomaly,scenario
 */
public class LabelsLoader {

    /**
     * Container holding the parsed ground-truth labels.
     */
    public static class LoadedLabels {
        private final Map<String, Boolean> isAnomalyMap;
        private final Map<String, String> scenarioMap;

        public LoadedLabels(Map<String, Boolean> isAnomalyMap, Map<String, String> scenarioMap) {
            this.isAnomalyMap = isAnomalyMap;
            this.scenarioMap = scenarioMap;
        }

        public Map<String, Boolean> getIsAnomalyMap() {
            return isAnomalyMap;
        }

        public Map<String, String> getScenarioMap() {
            return scenarioMap;
        }
    }

    /**
     * Parses the labels CSV file into two synchronized lookup maps.
     *
     * @param labelsFile Path to data/labels_eval.csv
     * @return LoadedLabels containing session_id -> is_anomaly and session_id -> scenario name
     * @throws IOException If file reading fails
     */
    public LoadedLabels load(Path labelsFile) throws IOException {
        Map<String, Boolean> isAnomalyMap = new LinkedHashMap<String, Boolean>();
        Map<String, String> scenarioMap = new LinkedHashMap<String, String>();

        if (labelsFile == null || !Files.exists(labelsFile)) {
            System.err.println("Warning: Labels file does not exist: " + labelsFile);
            return new LoadedLabels(isAnomalyMap, scenarioMap);
        }

        try (BufferedReader reader = Files.newBufferedReader(labelsFile)) {
            // Read and skip the header row: session_id,is_anomaly,scenario
            String header = reader.readLine();

            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }

                String[] parts = trimmed.split(",");
                if (parts.length >= 3) {
                    String sessionId = parts[0].trim();
                    boolean isAnomaly = Boolean.parseBoolean(parts[1].trim());
                    String scenario = parts[2].trim();

                    isAnomalyMap.put(sessionId, isAnomaly);
                    scenarioMap.put(sessionId, scenario);
                }
            }
        }

        return new LoadedLabels(isAnomalyMap, scenarioMap);
    }
}
