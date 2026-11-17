package com.cookietrace.storage;

import com.cookietrace.engine.SessionRisk;
import com.cookietrace.model.Alert;
import com.cookietrace.model.RiskLevel;
import com.cookietrace.report.SessionReport;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Manages persistent storage and retrieval of session analysis run histories using SQLite JDBC.
 *
 * Implements AutoCloseable to support clean resource management via try-with-resources.
 */
public class RunHistoryStore implements AutoCloseable {

    private final Connection connection;

    /**
     * Initializes the SQLite database connection and sets up required schema tables.
     *
     * @param dbFile Target SQLite database file path
     */
    public RunHistoryStore(Path dbFile) {
        if (dbFile == null) {
            throw new IllegalArgumentException("Database file path cannot be null.");
        }

        try {
            // Ensure the parent directory exists
            if (dbFile.getParent() != null) {
                Files.createDirectories(dbFile.getParent());
            }

            // Connect using SQLite JDBC URL
            String jdbcUrl = "jdbc:sqlite:" + dbFile.toAbsolutePath();
            this.connection = DriverManager.getConnection(jdbcUrl);

            // Initialize schema if not already present
            initSchema();
        } catch (IOException e) {
            throw new RuntimeException("Failed to create database directory: " + e.getMessage(), e);
        } catch (SQLException e) {
            throw new RuntimeException("Failed to initialize SQLite database connection: " + e.getMessage(), e);
        }
    }

    /**
     * Creates database tables if they do not exist.
     */
    private void initSchema() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            // 1. Runs table: tracks metadata and overall summary statistics
            stmt.execute("CREATE TABLE IF NOT EXISTS runs ("
                    + "run_id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    + "run_time TEXT, "
                    + "dataset TEXT, "
                    + "event_count INTEGER, "
                    + "session_count INTEGER, "
                    + "low_count INTEGER, "
                    + "medium_count INTEGER, "
                    + "high_count INTEGER"
                    + ");");

            // 2. Session results table: stores evaluated scores, level, and cookie grade per session
            stmt.execute("CREATE TABLE IF NOT EXISTS session_results ("
                    + "run_id INTEGER, "
                    + "session_id TEXT, "
                    + "raw_points INTEGER, "
                    + "total_points INTEGER, "
                    + "level TEXT, "
                    + "cookie_grade TEXT, "
                    + "analyzers TEXT"
                    + ");");

            // 3. Alerts table: stores individual threat alert details
            stmt.execute("CREATE TABLE IF NOT EXISTS alerts ("
                    + "run_id INTEGER, "
                    + "session_id TEXT, "
                    + "analyzer TEXT, "
                    + "points INTEGER, "
                    + "level TEXT, "
                    + "explanation TEXT, "
                    + "recommendation TEXT"
                    + ");");
        }
    }

    /**
     * Persists an analysis run and all associated session reports and alerts in a single atomic transaction.
     *
     * DATABASE CONCEPT - ACID ATOMICITY (All-or-Nothing):
     * We disable auto-commit (setAutoCommit(false)) so that the run summary, all session results,
     * and all alerts are committed together as a single atomic unit of work. If an error occurs
     * anywhere during writing (e.g. disk full, power loss, or database lock), the transaction
     * is rolled back completely. This prevents partial/corrupted historical records from being
     * stored in the database.
     *
     * SECURITY NOTE - SQL INJECTION PREVENTION:
     * EVERY SQL statement with dynamic parameters uses PreparedStatement with parameterized '?'
     * placeholders instead of string concatenation. The JDBC driver handles strict type binding
     * and escaping, ensuring untrusted strings (such as crafted user agents, session IDs, or explanations)
     * can never be interpreted as executable SQL commands.
     *
     * @param dataset    Identifier/filename of the analyzed dataset
     * @param eventCount Total number of raw events analyzed
     * @param reports    Evaluated session reports
     * @return The auto-generated run_id
     */
    public long saveRun(String dataset, int eventCount, List<SessionReport> reports) {
        if (dataset == null || dataset.trim().isEmpty()) {
            throw new IllegalArgumentException("Dataset name cannot be null or blank.");
        }
        if (reports == null) {
            throw new IllegalArgumentException("Reports list cannot be null.");
        }

        // Count risk tiers
        int sessionCount = reports.size();
        int lowCount = 0;
        int mediumCount = 0;
        int highCount = 0;

        for (SessionReport report : reports) {
            RiskLevel level = report.getRisk().getLevel();
            if (level == RiskLevel.LOW) {
                lowCount++;
            } else if (level == RiskLevel.MEDIUM) {
                mediumCount++;
            } else if (level == RiskLevel.HIGH) {
                highCount++;
            }
        }

        String runTime = Instant.now().toString();

        try {
            // Begin atomic transaction
            connection.setAutoCommit(false);

            // 1. Insert into runs table
            String insertRunSql = "INSERT INTO runs "
                    + "(run_time, dataset, event_count, session_count, low_count, medium_count, high_count) "
                    + "VALUES (?, ?, ?, ?, ?, ?, ?)";

            long runId;
            try (PreparedStatement pstmt = connection.prepareStatement(insertRunSql, Statement.RETURN_GENERATED_KEYS)) {
                pstmt.setString(1, runTime);
                pstmt.setString(2, dataset);
                pstmt.setInt(3, eventCount);
                pstmt.setInt(4, sessionCount);
                pstmt.setInt(5, lowCount);
                pstmt.setInt(6, mediumCount);
                pstmt.setInt(7, highCount);
                pstmt.executeUpdate();

                try (ResultSet rs = pstmt.getGeneratedKeys()) {
                    if (rs.next()) {
                        runId = rs.getLong(1);
                    } else {
                        throw new SQLException("Failed to obtain generated run_id.");
                    }
                }
            }

            // 2. Insert into session_results table
            String insertSessionSql = "INSERT INTO session_results "
                    + "(run_id, session_id, raw_points, total_points, level, cookie_grade, analyzers) "
                    + "VALUES (?, ?, ?, ?, ?, ?, ?)";

            try (PreparedStatement pstmt = connection.prepareStatement(insertSessionSql)) {
                for (SessionReport report : reports) {
                    SessionRisk risk = report.getRisk();

                    // Collect unique analyzer names separated by semicolon
                    Set<String> uniqueAnalyzers = new LinkedHashSet<String>();
                    for (Alert alert : risk.getAlerts()) {
                        uniqueAnalyzers.add(alert.getAnalyzerName());
                    }

                    StringBuilder analyzersSb = new StringBuilder();
                    int count = 0;
                    for (String aName : uniqueAnalyzers) {
                        if (count > 0) {
                            analyzersSb.append(";");
                        }
                        analyzersSb.append(aName);
                        count++;
                    }

                    pstmt.setLong(1, runId);
                    pstmt.setString(2, risk.getSessionId());
                    pstmt.setInt(3, risk.getRawPoints());
                    pstmt.setInt(4, risk.getTotalPoints());
                    pstmt.setString(5, risk.getLevel().name());
                    pstmt.setString(6, report.getCookieGrade().name());
                    pstmt.setString(7, analyzersSb.toString());
                    pstmt.addBatch();
                }
                pstmt.executeBatch();
            }

            // 3. Insert into alerts table
            String insertAlertSql = "INSERT INTO alerts "
                    + "(run_id, session_id, analyzer, points, level, explanation, recommendation) "
                    + "VALUES (?, ?, ?, ?, ?, ?, ?)";

            try (PreparedStatement pstmt = connection.prepareStatement(insertAlertSql)) {
                for (SessionReport report : reports) {
                    SessionRisk risk = report.getRisk();
                    for (Alert alert : risk.getAlerts()) {
                        pstmt.setLong(1, runId);
                        pstmt.setString(2, risk.getSessionId());
                        pstmt.setString(3, alert.getAnalyzerName());
                        pstmt.setInt(4, alert.getPoints());
                        pstmt.setString(5, alert.getLevel().name());
                        pstmt.setString(6, alert.getExplanation());
                        pstmt.setString(7, alert.getRecommendation());
                        pstmt.addBatch();
                    }
                }
                pstmt.executeBatch();
            }

            // Commit the complete transaction
            connection.commit();
            return runId;

        } catch (SQLException e) {
            // Roll back all changes if any part fails
            try {
                connection.rollback();
            } catch (SQLException rollbackEx) {
                // Suppress rollback secondary exception
            }
            throw new RuntimeException("Database transaction failed during saveRun: " + e.getMessage(), e);
        } finally {
            // Always restore auto-commit mode
            try {
                connection.setAutoCommit(true);
            } catch (SQLException e) {
                // ignore cleanup error
            }
        }
    }

    /**
     * Lists recent analysis runs ordered newest first up to the given limit.
     *
     * @param limit Maximum number of records to return
     * @return List of RunSummary instances
     */
    public List<RunSummary> listRuns(int limit) {
        String query = "SELECT run_id, run_time, dataset, event_count, session_count, low_count, medium_count, high_count "
                + "FROM runs ORDER BY run_id DESC LIMIT ?";

        List<RunSummary> list = new ArrayList<RunSummary>();
        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            pstmt.setInt(1, limit);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    list.add(new RunSummary(
                            rs.getLong("run_id"),
                            rs.getString("run_time"),
                            rs.getString("dataset"),
                            rs.getInt("event_count"),
                            rs.getInt("session_count"),
                            rs.getInt("low_count"),
                            rs.getInt("medium_count"),
                            rs.getInt("high_count")
                    ));
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to query run history: " + e.getMessage(), e);
        }
        return list;
    }

    /**
     * Counts the total number of rows in the specified table.
     * Only allows the three known tables: 'runs', 'session_results', 'alerts'.
     *
     * @param table Target table name
     * @return Number of rows
     * @throws IllegalArgumentException If an unknown table name is supplied
     */
    public int countRows(String table) {
        if (!"runs".equals(table) && !"session_results".equals(table) && !"alerts".equals(table)) {
            throw new IllegalArgumentException("Unknown table: '" + table + "'. Allowed tables: runs, session_results, alerts");
        }

        // Table name is strictly validated against an exact whitelist above
        String query = "SELECT COUNT(*) FROM " + table;
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            if (rs.next()) {
                return rs.getInt(1);
            }
            return 0;
        } catch (SQLException e) {
            throw new RuntimeException("Failed to count rows in table '" + table + "': " + e.getMessage(), e);
        }
    }

    @Override
    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to close database connection: " + e.getMessage(), e);
        }
    }
}
