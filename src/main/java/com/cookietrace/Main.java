package com.cookietrace;

import com.cookietrace.data.SampleDataGenerator;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Main entry point for CookieTrace - Stage 1.
 *
 * This class runs the sample data generator to create simulated web session logs
 * and ground truth labels, then prints verification statistics and a preview of
 * the generated data.
 */
public class Main {

    public static void main(String[] args) {
        System.out.println("=== CookieTrace: Stage 1 - Simulated Data Generation ===");

        // Target paths for generated CSV files inside the 'data' directory
        Path eventsPath = Paths.get("data", "sessions_dev.csv");
        Path labelsPath = Paths.get("data", "labels_dev.csv");

        int sessionCount = 20;
        long seed = 42L;

        try {
            // Create data directory if it does not already exist
            Path dataDir = Paths.get("data");
            if (!Files.exists(dataDir)) {
                Files.createDirectories(dataDir);
                System.out.println("Created directory: " + dataDir.toAbsolutePath());
            }

            // Instantiate generator and generate data
            SampleDataGenerator generator = new SampleDataGenerator();
            System.out.println("Generating " + sessionCount + " sessions with seed " + seed + "...");
            generator.generate(sessionCount, seed, eventsPath, labelsPath);
            System.out.println("Data generated successfully.\n");

            // -------------------------------------------------------------
            // Count event rows (excluding the header line)
            // -------------------------------------------------------------
            int eventRows = 0;
            BufferedReader eventReader = Files.newBufferedReader(eventsPath);
            try {
                String line = eventReader.readLine(); // Skip header
                while ((line = eventReader.readLine()) != null) {
                    if (!line.trim().isEmpty()) {
                        eventRows++;
                    }
                }
            } finally {
                eventReader.close();
            }

            // -------------------------------------------------------------
            // Count total sessions and anomalous sessions from labels file
            // -------------------------------------------------------------
            int totalSessions = 0;
            int anomalousSessions = 0;

            BufferedReader labelReader = Files.newBufferedReader(labelsPath);
            try {
                String line = labelReader.readLine(); // Skip header
                while ((line = labelReader.readLine()) != null) {
                    if (!line.trim().isEmpty()) {
                        totalSessions++;
                        // Label format: session_id,is_anomaly,scenario
                        String[] parts = line.split(",");
                        if (parts.length >= 2 && "true".equalsIgnoreCase(parts[1].trim())) {
                            anomalousSessions++;
                        }
                    }
                }
            } finally {
                labelReader.close();
            }

            // -------------------------------------------------------------
            // Print required summary statistics
            // -------------------------------------------------------------
            System.out.println("Summary Statistics:");
            System.out.println("Number of event rows: " + eventRows);
            System.out.println("Number of sessions: " + totalSessions);
            System.out.println("Number of anomalous sessions: " + anomalousSessions);
            System.out.println();

            // -------------------------------------------------------------
            // Print the first 5 lines of the events file
            // -------------------------------------------------------------
            System.out.println("First 5 lines of " + eventsPath + ":");
            System.out.println("--------------------------------------------------------------------------------");
            BufferedReader previewReader = Files.newBufferedReader(eventsPath);
            try {
                int linesPrinted = 0;
                String line;
                while ((line = previewReader.readLine()) != null && linesPrinted < 5) {
                    System.out.println(line);
                    linesPrinted++;
                }
            } finally {
                previewReader.close();
            }
            System.out.println("--------------------------------------------------------------------------------");
            System.out.println("Stage 1 completed successfully!");

        } catch (IOException e) {
            System.err.println("Error while generating or reading data: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
