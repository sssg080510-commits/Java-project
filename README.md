# CookieTrace: Session Hijacking & Behavioral Anomaly Detection System

CookieTrace is an advanced Java security analysis system engineered to detect session hijacking, credential abuse, and behavioral anomalies in enterprise web applications. It pairs deterministic rule-based heuristic analyzers with an unsupervised machine learning model (Isolation Forest) and provides interactive live simulation, SQLite historical tracking, and comprehensive reporting dashboards.

---

## Architecture Overview

```
                                      +-------------------------+
                                      |   Session Event Stream  |
                                      +------------+------------+
                                                   |
                     +-----------------------------+-----------------------------+
                     |                                                           |
                     v                                                           v
      +------------------------------+                           +-------------------------------+
      |    Rule-Based Analyzers      |                           |     AnomalyAnalyzer (ML)      |
      |                              |                           |                               |
      | - CookieAttributeAnalyzer    |                           | - FeatureExtractor (9 metrics)|
      | - IpChangeAnalyzer           |                           | - Isolation Forest (Smile)    |
      | - UserAgentAnalyzer          |                           | - Deterministic ForkJoinPool  |
      | - ConcurrentSessionAnalyzer  |                           +---------------+---------------+
      | - ImpossibleTravelAnalyzer   |                                           |
      +--------------+---------------+                                           |
                     |                                                           |
                     +-----------------------------+-----------------------------+
                                                   |
                                                   v
                                      +-------------------------+
                                      |       RiskEngine        |
                                      |  (Score Aggregator &    |
                                      |   Risk Classification)  |
                                      +------------+------------+
                                                   |
                     +-----------------------------+-----------------------------+
                     |                             |                             |
                     v                             v                             v
      +------------------------------+ +-----------------------+ +-------------------------------+
      |       Report Exporters       | |    Live Simulator     | |      RunHistoryStore (DB)     |
      |                              | |                       | |                               |
      | - ConsoleExporter            | | - Event playback      | | - SQLite persistence          |
      | - CsvExporter                | | - Dynamic escalation  | | - Historical run summaries    |
      | - JsonExporter               | | - Event listeners     | | - HTML Dashboard generator    |
      | - HtmlExporter (with grade)  | +-----------------------+ +-------------------------------+
      +------------------------------+
```

---

## Features & Project Stages

1. **Core Domain & Ingestion (Stages 1–2)**
   - Type-safe domain models: `SessionEvent`, `CookieInfo`, `Alert`, `RiskLevel`.
   - Robust CSV parser (`SessionLoader`) with row validation and error tolerance.
   - Comprehensive unit test harness and sample data generation (`SampleDataGenerator`).

2. **Security Analyzers (Stages 3–4)**
   - **CookieAttributeAnalyzer**: Flags missing `Secure`, `HttpOnly`, or weak `SameSite` flags.
   - **IpChangeAnalyzer**: Detects rapid IP rotation across session requests.
   - **UserAgentAnalyzer**: Flags suspicious operating system/browser user-agent changes.
   - **ConcurrentSessionAnalyzer**: Detects overlapping requests across distant geo-locations.
   - **ImpossibleTravelAnalyzer**: Uses the Haversine formula to detect physical speed violations (> 900 km/h).
   - **AnomalyAnalyzer (ML)**: Extracts 9 behavioral metrics (intervals, event frequencies, geospatial distances) and trains an **Isolation Forest** via Smile ML to isolate statistical outliers.

3. **Risk Engine & Grading (Stages 5–6)**
   - `RiskEngine` aggregates weighted findings, caps maximum point contributions per analyzer, and assigns `LOW`, `MEDIUM`, or `HIGH` risk classifications.
   - Multi-format exporters: Console, CSV, JSON, and rich HTML with `CookieGrader` letter grades (A–F).

4. **Live Stream Simulation & Persistence (Stages 7–8)**
   - `LiveSimulator`: Simulates real-time event streaming with configurable delay and event listener callbacks.
   - `RunHistoryStore`: Persistent JDBC SQLite storage (`data/cookietrace.db`) tracking multi-run trends.
   - `DashboardGenerator`: Generates a self-contained, responsive HTML executive dashboard.

5. **Evaluation & Diagnosis (Stage 9)**
   - 500-session synthetic evaluation benchmark (`data/sessions_eval.csv` and `data/labels_eval.csv`).
   - `Evaluator` & `ConfusionMatrix`: Precision, Recall, F1 score, and accuracy metrics comparing Rule-Based, ML, and Hybrid detectors.
   - Diagnostic suites (`Stage9DDiagnostic`, `Stage9D2Diagnostic`) exploring feature scaling and Isolation Forest behavior.

---

## Project Structure

```
cookietrace/
├── pom.xml                                 # Maven configuration
├── .gitignore                              # Git exclusion rules
├── mvnw / mvnw.cmd                         # Maven wrapper executables
├── data/                                   # Evaluation datasets & SQLite database
│   ├── cookietrace.db
│   ├── sessions_dev.csv / labels_dev.csv
│   └── sessions_eval.csv / labels_eval.csv
├── output/                                 # Generated evaluation reports & dashboards
│   ├── dashboard.html
│   ├── evaluation.csv
│   └── evaluation_by_scenario.csv
└── src/main/java/com/cookietrace/
    ├── Main.java                           # Application entry point
    ├── Stage*Demo.java                     # Stage-specific milestone demonstrations
    ├── model/                              # Core domain entities
    ├── data/                               # CSV loaders and data generators
    ├── analysis/                           # Rule-based analyzers & ML Isolation Forest
    ├── engine/                             # Risk scoring and classification engine
    ├── report/                             # Multi-format report exporters & grading
    ├── simulation/                         # Live event streaming simulator
    ├── storage/                            # SQLite persistence store
    ├── dashboard/                          # HTML dashboard generation
    ├── evaluation/                         # Confusion matrix and benchmark evaluators
    └── exception/                          # Domain exceptions
```

---

## Building and Running

### Prerequisites
- Java 17+ (JDK 17)
- Maven 3.8+ (or use the included `./mvnw` wrapper)

### Build the Project
```bash
./mvnw clean compile
```

### Run Stage Demonstrations
Each milestone includes a dedicated demonstration class:

```bash
# Stage 4: Security Analyzers Demo (Rules + ML)
./mvnw exec:java -Dexec.mainClass="com.cookietrace.Stage4Demo"

# Stage 5: Risk Engine & Scoring Demo
./mvnw exec:java -Dexec.mainClass="com.cookietrace.Stage5Demo"

# Stage 6: Multi-format Exporters (Console, CSV, JSON, HTML)
./mvnw exec:java -Dexec.mainClass="com.cookietrace.Stage6Demo"

# Stage 7: Real-time Live Simulator (0ms delay for instant run)
./mvnw exec:java -Dexec.mainClass="com.cookietrace.Stage7Demo" -Dexec.args="0"

# Stage 8B: Historical Run Storage & HTML Dashboard
./mvnw exec:java -Dexec.mainClass="com.cookietrace.Stage8BDemo"

# Stage 9: Comprehensive Detection Benchmark (Rules vs ML vs Hybrid)
./mvnw exec:java -Dexec.mainClass="com.cookietrace.Stage9Demo"
```

---

## License
Educational Coursework Project.
