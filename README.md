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

## Working website and local security lab

The Java web entry point connects real authentication and protected HTTP activity to
CookieTrace's existing rule analyzers. It includes a responsive account-scoped dashboard,
SQLite users and event history, PBKDF2 password hashing, one-hour random sessions,
HttpOnly/SameSite=Strict cookies, CSRF checks, and login attempt limits. Raw session
cookies are never written to the database. Sessions are held in memory and end on restart;
accounts and observed events persist in `data/web.db`, separate from the coursework database.

### Start locally

Install Java 17+ and Maven, then run:

```sh
./scripts/run-web.sh
```

Open **http://127.0.0.1:8080**, create an account, and select **Open monitored website**. Requests from that storefront are captured automatically.
The dashboard updates every second. The configured monitor sees the latest 500 website events; other accounts see only their own events.
Dashboard polling does not generate activity events; authenticated website API requests do. Sign out invalidates the server session.

For a demo, open **Session intelligence** and select **Look up** with your current
session ID already filled in. You can also paste a full hashed session ID or select
**Use session ID** on an observed session. The lookup shows the username, whether
the session is active, and its last recorded request. Signed-in users can look up
their own sessions, and the configured monitor can look up any recorded session.

Docker alternative:

```sh
docker compose up --build
```

Docker binds the published port to loopback and stores data in the `web-data` volume.

### Run security scenarios

For the private-note demo, sign in and open **Open monitored website**. Under
**Private note**, save fictional information and select **Open saved note**.
The request feed shows `/api/note` activity without including the note content.
Notes persist per account in the local SQLite database.

With lab mode enabled and a monitor signed in, choose a scenario under
**Private note access demo** and select **Run scenario**. Each run adds an
isolated set of labeled synthetic requests for a fictional account. The demo
resolves an internal test credential using the same session lookup as live
requests, then reads a temporary fictional note using the regular note query.
The test credential stays in an isolated store for that run. The panel shows
the resolved account and returned note, and the matching
session appears first under **Session intelligence**. Try normal browsing,
browser change, overlapping IPs, impossible travel, request burst, and combined
signals. Combined signals reach high risk. Use **Sign out** in the monitored
website to end your real session and clear the note from the page.

Start with lab fixtures enabled to exercise all scenarios:

```sh
COOKIETRACE_ADMIN=your_username COOKIETRACE_LAB=true ./scripts/run-web.sh
# Or: COOKIETRACE_ADMIN=your_username COOKIETRACE_LAB=true docker compose up --build
```

In a second terminal:

```sh
python3 scripts/security_scenarios.py
```

The script creates random dedicated test accounts, copies only its own test session cookie,
changes client identity, performs near-concurrent requests with Chennai/London fixtures,
and sends a bounded burst of 20 requests. It asserts exact detector names, HIGH risk for
the combined scenario, account isolation, CSRF rejection, logout invalidation, and fresh
login with retained history. It never extracts browser cookies or targets external websites.
It only accepts `http://127.0.0.1:<port>` and disables HTTP proxies.

Run the same script with lab mode off to verify that fixture headers are ignored. Test
accounts and events remain available for inspection; repeated test runs create new accounts.
Normal browsing should have no behavior alerts. Local HTTP intentionally produces a
cookie-security finding because `Secure` is off.

### Configuration and scope

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8080` | Listening port |
| `BIND_ADDRESS` | `127.0.0.1` | Server bind address; Docker uses `0.0.0.0` inside its container |
| `COOKIETRACE_DB` | `data/web.db` | Separate website SQLite database |
| `COOKIETRACE_ADMIN` | empty | Existing username allowed to monitor all website sessions |
| `COOKIETRACE_LAB` | `false` | Explicitly enable labelled synthetic location fixtures |
| `COOKIE_SECURE` | `false` | Set `true` when served through HTTPS |

This is a working local security demo, not a publicly deployed production service.
`X-Forwarded-For` is ignored; source addresses come from the socket. A future proxy
integration needs an explicit trusted-proxy configuration. No GeoIP provider is configured:
normal requests have unknown locations and do not participate in impossible-travel checks.
Lab fixtures use documentation-only IP addresses and are labelled in the UI. The legacy
IPv4 model receives a deterministic IPv4-shaped digest for IPv6 comparison; these are not
actual geolocated IPv4 addresses. Live scoring uses deterministic rules, including a
20-request/10-second burst signal. The existing ML benchmark remains separate because
synthetic benchmark training does not establish a reliable live baseline.

The dashboard groups by hashed session ID and uses a bounded recent-event window;
older evidence remains in SQLite. An alert is an investigation signal, not proof of cookie
theft. Automatic risk-based revocation, production scaling, TLS termination, retention,
account recovery, and deployment remain future work. Logout revocation works now.

### Live monitoring workflow

Set `COOKIETRACE_ADMIN` to your account username when starting the server, then sign in.
Select **Open monitored website** to open the connected storefront in another tab. Its
protected API requests are captured automatically, including item views and a five-second
refresh while the tab is visible. The dashboard polls server data every second and flags
high-risk sessions with an alert banner and expanded detector evidence.

In lab mode the monitor can select **Run security test**. A background worker creates a
separate random test account and sends genuine localhost HTTP requests: normal browsing,
cookie replay with a changed client identity, labelled location fixtures, and a bounded
burst. Watch the stage text, request feed, and flagged session update. There is no need to
run a terminal script for this flow. Ordinary accounts cannot start the test or read the
website-wide event stream. The Python scenarios remain available for regression checks.

This monitors the included website, not unrelated websites. Connecting another application
requires server-side instrumentation and authenticated event ingestion. Location fixtures
remain simulations; browser changes and request bursts are measured from actual requests.
