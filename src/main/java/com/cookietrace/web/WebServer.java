package com.cookietrace.web;

import com.cookietrace.analysis.*;
import com.cookietrace.engine.*;
import com.cookietrace.model.*;
import com.sun.net.httpserver.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/** Live website monitoring with explicit administrator access and labelled lab fixtures. */
public final class WebServer {
    private static final String NOTE_PATH = "/api/note";
    private static final String DEMO_NOTE_PATH = "/api/note-demo";
    private static final String DEMO_NOTE = "Demo recovery phrase: BLUE ORCHID";
    private final Connection db;
    private final String admin = System.getenv().getOrDefault("COOKIETRACE_ADMIN", "");
    private final LabScenario scenario = new LabScenario();
    private final boolean lab = Boolean.parseBoolean(System.getenv("COOKIETRACE_LAB"));
    private final boolean secure = Boolean.parseBoolean(System.getenv("COOKIE_SECURE"));
    private final Map<String, Session> sessions = new HashMap<>();
    private final Map<String, ArrayDeque<Long>> attempts = new HashMap<>();
    private record Session(String user, String csrf, long expires) {}
    private static final SecureRandom RANDOM = new SecureRandom();
    private static String token() { byte[] b = new byte[32]; RANDOM.nextBytes(b); return HexFormat.of().formatHex(b); }
    private static String hash(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }
    private static Session resolveSession(Map<String, Session> store, String id) {
        Session session = store.get(id);
        return session != null && session.expires > System.currentTimeMillis() ? session : null;
    }
    private static byte[] password(String value, byte[] salt) throws Exception {
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(
            new PBEKeySpec(value.toCharArray(), salt, 210000, 256)).getEncoded();
    }
    private WebServer() throws Exception {
        Path path = Path.of(System.getenv().getOrDefault("COOKIETRACE_DB", "data/web.db"));
        Files.createDirectories(path.toAbsolutePath().getParent());
        db = DriverManager.getConnection("jdbc:sqlite:" + path);
        try (Statement s = db.createStatement()) {
            s.execute("PRAGMA journal_mode=WAL");
            s.execute("CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, salt BLOB NOT NULL, password BLOB NOT NULL)");
            s.execute("CREATE TABLE IF NOT EXISTS private_notes (user TEXT PRIMARY KEY, note TEXT NOT NULL)");
            s.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, session TEXT, user TEXT, time TEXT, ip TEXT, ua TEXT, location TEXT, simulated INTEGER, secure INTEGER, path TEXT)");
            s.execute("CREATE INDEX IF NOT EXISTS events_user ON events(user,id)");
            s.execute("CREATE INDEX IF NOT EXISTS events_session ON events(session,id)");
        }
    }
    public static void main(String[] args) throws Exception {
        WebServer app = new WebServer();
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        String bind = System.getenv().getOrDefault("BIND_ADDRESS", "127.0.0.1");
        HttpServer server = HttpServer.create(new InetSocketAddress(bind, port), 64);
        server.createContext("/", app::handle);
        server.setExecutor(Executors.newFixedThreadPool(8));
        Runtime.getRuntime().addShutdownHook(new Thread(() -> { server.stop(1); try { app.db.close(); } catch (Exception ignored) {} }));
        server.start();
        System.out.println("CookieTrace: http://" + bind + ":" + port + " | lab=" + app.lab);
    }
    private synchronized void handle(HttpExchange x) throws java.io.IOException {
        try {
            x.getResponseHeaders().set("Cache-Control", "no-store");
            x.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
            x.getResponseHeaders().set("X-Frame-Options", "DENY");
            x.getResponseHeaders().set("Referrer-Policy", "no-referrer");
            x.getResponseHeaders().set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
            String path = x.getRequestURI().getPath();
            if (path.equals("/health") && x.getRequestMethod().equals("GET")) { send(x, 200, "{\"ok\":true}"); return; }
            if (!path.startsWith("/api/")) { staticFile(x, path); return; }
            if (!Set.of("GET", "POST").contains(x.getRequestMethod())) { send(x,405,"{\"error\":\"Method not allowed\"}"); return; }
            if (path.equals("/api/register") || path.equals("/api/login")) { authenticate(x, path.endsWith("register")); return; }
            sessions.values().removeIf(s -> s.expires < System.currentTimeMillis());
            String raw = cookie(x);
            String id = hash(raw);
            Session s = resolveSession(sessions, id);
            if (s == null) { send(x,401,"{\"error\":\"Please sign in\"}"); return; }
            if (x.getRequestMethod().equals("POST") && !s.csrf.equals(x.getRequestHeaders().getFirst("X-CSRF-Token"))) {
                send(x,403,"{\"error\":\"Invalid CSRF token\"}"); return;
            }
            if (!Set.of("/api/me", "/api/dashboard", "/api/demo", "/api/session", DEMO_NOTE_PATH).contains(path)) record(x,id,s.user);
            if (path.equals(NOTE_PATH)) {
                privateNote(x, s.user);
                return;
            }
            if (path.equals(DEMO_NOTE_PATH) && x.getRequestMethod().equals("POST")) {
                if (!lab || !s.user.equals(admin)) {
                    send(x,403,"{\"error\":\"Administrator and lab mode required\"}");
                    return;
                }
                runNoteDemo(x);
                return;
            }
            if (path.equals("/api/logout") && x.getRequestMethod().equals("POST")) {
                sessions.remove(id); setCookie(x,"",0); send(x,200,"{\"ok\":true}"); return;
            }
            if (path.equals("/api/me") && x.getRequestMethod().equals("GET")) {
                send(x,200,"{\"user\":"+q(s.user)+",\"sessionId\":"+q(id)+",\"admin\":"+s.user.equals(admin)+",\"csrf\":"+q(s.csrf)+",\"lab\":"+lab+",\"secureCookie\":"+secure+"}"); return;
            }
            if (path.equals("/api/session") && x.getRequestMethod().equals("GET")) {
                lookupSession(x, s.user);
                return;
            }
            if (path.equals("/api/profile") && x.getRequestMethod().equals("GET")) {
                send(x,200,"{\"user\":"+q(s.user)+",\"ok\":true}"); return;
            }
            if (path.equals("/api/activity") && x.getRequestMethod().equals("POST")) {
                send(x,200,"{\"ok\":true}"); return;
            }
            if (path.equals("/api/demo") && x.getRequestMethod().equals("POST")) {
                if (!lab || !s.user.equals(admin)) { send(x,403,"{\"error\":\"Administrator and lab mode required\"}"); return; }
                boolean started=scenario.start(x.getLocalAddress().getPort());
                send(x,started?202:409,started?"{\"ok\":true}":"{\"error\":\"A scenario is already running\"}"); return;
            }
            if (path.equals("/api/dashboard") && x.getRequestMethod().equals("GET")) { send(x,200,dashboard(s.user)); return; }
            send(x,404,"{\"error\":\"Route not found\"}");
        } catch (IllegalArgumentException e) { send(x,400,"{\"error\":\"Invalid request\"}"); }
        catch (Exception e) { System.err.println("Request failed: " + e.getClass().getSimpleName()); send(x,500,"{\"error\":\"Server error\"}"); }
        finally { x.close(); }
    }
    private void authenticate(HttpExchange x, boolean register) throws Exception {
        if (!x.getRequestMethod().equals("POST")) { send(x,405,"{\"error\":\"Use POST\"}"); return; }
        String origin=x.getRequestHeaders().getFirst("Origin");
        if(origin!=null && !origin.equals((secure?"https://":"http://")+x.getRequestHeaders().getFirst("Host"))) { send(x,403,"{\"error\":\"Origin rejected\"}"); return; }
        long now=System.currentTimeMillis();
        attempts.entrySet().removeIf(e -> e.getValue().isEmpty() || e.getValue().getLast()<now-60000);
        String ip=x.getRemoteAddress().getAddress().getHostAddress();
        var queue=attempts.computeIfAbsent(ip,k->new ArrayDeque<>());
        while(!queue.isEmpty() && queue.getFirst()<now-60000) queue.removeFirst();
        if(queue.size()>=20) { send(x,429,"{\"error\":\"Too many attempts; wait one minute\"}"); return; }
        queue.add(now);
        byte[] body=x.getRequestBody().readNBytes(4097);
        if(body.length>4096) { send(x,413,"{\"error\":\"Request too large\"}"); return; }
        Map<String,String> form=new HashMap<>();
        for(String pair:new String(body,StandardCharsets.UTF_8).split("&")) {
            String[] kv=pair.split("=",2); if(kv.length==2) form.put(URLDecoder.decode(kv[0],StandardCharsets.UTF_8),URLDecoder.decode(kv[1],StandardCharsets.UTF_8));
        }
        String user=form.getOrDefault("username","").toLowerCase(Locale.ROOT), pass=form.getOrDefault("password","");
        if(!user.matches("[a-z0-9_]{3,32}") || pass.length()<12 || pass.length()>256) {
            send(x,400,"{\"error\":\"Use a 3–32 character username (letters, numbers, underscore) and a 12–256 character password\"}"); return;
        }
        if(register) {
            byte[] salt=new byte[16]; RANDOM.nextBytes(salt);
            try(PreparedStatement p=db.prepareStatement("INSERT OR IGNORE INTO users VALUES(?,?,?)")) {
                p.setString(1,user); p.setBytes(2,salt); p.setBytes(3,password(pass,salt));
                if(p.executeUpdate()!=1) { send(x,409,"{\"error\":\"Username unavailable\"}"); return; }
            }
        } else {
            boolean valid=false;
            try(PreparedStatement p=db.prepareStatement("SELECT salt,password FROM users WHERE name=?")) {
                p.setString(1,user); try(ResultSet r=p.executeQuery()) {
                    if(r.next()) valid=MessageDigest.isEqual(password(pass,r.getBytes(1)),r.getBytes(2));
                    else password(pass,new byte[16]);
                }
            }
            if(!valid) { send(x,401,"{\"error\":\"Invalid credentials\"}"); return; }
        }
        sessions.remove(hash(cookie(x)));
        if(sessions.size()>=10000) sessions.values().removeIf(s->s.expires<now);
        if(sessions.size()>=10000) { send(x,503,"{\"error\":\"Session capacity reached\"}"); return; }
        String raw=token(), id=hash(raw); Session s=new Session(user,token(),now+3600000);
        sessions.put(id,s); setCookie(x,raw,3600); record(x,id,user);
        send(x,200,"{\"ok\":true}");
    }
    private void record(HttpExchange x,String id,String user) throws Exception {
        String ip=x.getRemoteAddress().getAddress().getHostAddress();
        if(ip.equals("0:0:0:0:0:0:0:1") || ip.equals("::1")) ip="127.0.0.1";
        // The legacy model supports IPv4; IPv6 is retained as a stable IPv4-shaped digest for comparison.
        if(ip.contains(":")) { byte[] b=MessageDigest.getInstance("SHA-256").digest(ip.getBytes(StandardCharsets.UTF_8)); ip="240."+(b[0]&255)+"."+(b[1]&255)+"."+(b[2]&255); }
        String fixture=lab?Objects.toString(x.getRequestHeaders().getFirst("X-Lab-Location"),""):"";
        if(!Set.of("","chennai","london").contains(fixture)) throw new IllegalArgumentException();
        if(fixture.equals("chennai")) ip="192.0.2.10";
        if(fixture.equals("london")) ip="198.51.100.20";
        String ua=Objects.toString(x.getRequestHeaders().getFirst("User-Agent"),"Unknown");
        ua=ua.isBlank()?"Unknown":ua.substring(0,Math.min(512,ua.length()));
        try(PreparedStatement p=db.prepareStatement("INSERT INTO events(session,user,time,ip,ua,location,simulated,secure,path) VALUES(?,?,?,?,?,?,?,?,?)")) {
            p.setString(1,id); p.setString(2,user); p.setString(3,Instant.now().toString()); p.setString(4,ip); p.setString(5,ua);
            p.setString(6,fixture); p.setInt(7,fixture.isEmpty()?0:1); p.setInt(8,secure?1:0); p.setString(9,x.getRequestURI().getPath()); p.executeUpdate();
        }
    }
    private void lookupSession(HttpExchange x, String viewer) throws Exception {
        String query = Objects.toString(x.getRequestURI().getRawQuery(), "");
        if (!query.matches("id=[a-fA-F0-9]{64}")) {
            send(x, 400, "{\"error\":\"Enter the full 64-character session ID\"}");
            return;
        }
        String id = query.substring(3).toLowerCase(Locale.ROOT);
        try (PreparedStatement p = db.prepareStatement(
                "SELECT user,time FROM events WHERE session=? AND (user=? OR ?=1) ORDER BY id DESC LIMIT 1")) {
            p.setString(1, id);
            p.setString(2, viewer);
            p.setInt(3, viewer.equals(admin) ? 1 : 0);
            try (ResultSet r = p.executeQuery()) {
                if (r.next()) {
                    Session active = sessions.get(id);
                    send(x, 200, "{\"user\":" + q(r.getString("user"))
                            + ",\"active\":" + (active != null && active.expires > System.currentTimeMillis())
                            + ",\"lastSeen\":" + q(r.getString("time")) + "}");
                    return;
                }
            }
        }
        send(x, 404, "{\"error\":\"Session not found\"}");
    }
    private void privateNote(HttpExchange x, String user) throws Exception {
        if (x.getRequestMethod().equals("POST")) {
            byte[] body = x.getRequestBody().readNBytes(4097);
            if (body.length > 4096) {
                send(x, 413, "{\"error\":\"Note must be at most 4096 bytes\"}");
                return;
            }
            try (PreparedStatement p = db.prepareStatement(
                    "INSERT INTO private_notes(user,note) VALUES(?,?) ON CONFLICT(user) DO UPDATE SET note=excluded.note")) {
                p.setString(1, user);
                p.setString(2, new String(body, StandardCharsets.UTF_8));
                p.executeUpdate();
            }
            send(x, 200, "{\"ok\":true}");
            return;
        }
        send(x, 200, "{\"note\":" + q(readNote(user)) + "}");
    }

    private String readNote(String user) throws SQLException {
        try (PreparedStatement p = db.prepareStatement("SELECT note FROM private_notes WHERE user=?")) {
            p.setString(1, user);
            try (ResultSet r = p.executeQuery()) {
                return r.next() ? r.getString("note") : "";
            }
        }
    }

    private void runNoteDemo(HttpExchange x) throws Exception {
        String scenario = new String(x.getRequestBody().readNBytes(32), StandardCharsets.UTF_8);
        if (!Set.of("normal", "browser", "concurrent", "travel", "burst", "combined").contains(scenario)) {
            send(x, 400, "{\"error\":\"Choose a demo scenario\"}");
            return;
        }
        boolean travel = Set.of("travel", "combined").contains(scenario);
        boolean newIp = travel || scenario.equals("concurrent");
        boolean newBrowser = Set.of("browser", "combined").contains(scenario);
        int count = Set.of("burst", "combined").contains(scenario) ? 20 : 2;
        String fixtureCredential = token();
        String id = hash(fixtureCredential);
        String user = "lab-note-" + id.substring(0, 16);
        Session fixtureSession = new Session(user, token(), System.currentTimeMillis() + 60_000);
        Map<String, Session> fixtureSessions = Map.of(id, fixtureSession);
        Session resolved = resolveSession(fixtureSessions, hash(fixtureCredential));
        if (resolved == null) {
            send(x, 401, "{\"error\":\"Demo session expired\"}");
            return;
        }
        String exposedNote;
        Instant end = Instant.now();
        try (PreparedStatement p = db.prepareStatement(
                "INSERT INTO events(session,user,time,ip,ua,location,simulated,secure,path) VALUES(?,?,?,?,?,?,1,1,?)");
             PreparedStatement save = db.prepareStatement("INSERT INTO private_notes(user,note) VALUES(?,?)");
             PreparedStatement clear = db.prepareStatement("DELETE FROM private_notes WHERE user=?")) {
            db.setAutoCommit(false);
            try {
                save.setString(1, user);
                save.setString(2, DEMO_NOTE);
                save.executeUpdate();
                exposedNote = readNote(resolved.user);
                clear.setString(1, user);
                clear.executeUpdate();
                for (int i = 0; i < count; i++) {
                    boolean changed = i > 0;
                    p.setString(1, id);
                    p.setString(2, user);
                    p.setString(3, end.minusMillis((count - i - 1) * 400L).toString());
                    p.setString(4, changed && newIp ? "198.51.100.20" : "192.0.2.10");
                    p.setString(5, changed && newBrowser ? "Demo Firefox" : "Demo Chrome");
                    p.setString(6, travel ? (changed ? "london" : "chennai") : "");
                    p.setString(7, NOTE_PATH);
                    p.addBatch();
                }
                p.executeBatch();
                db.commit();
            } catch (SQLException e) {
                db.rollback();
                throw e;
            } finally {
                db.setAutoCommit(true);
            }
        }
        send(x, 200, "{\"user\":" + q(resolved.user) + ",\"id\":" + q(id) + ",\"note\":" + q(exposedNote) + "}");
    }

    private String dashboard(String user) throws Exception {
        List<SessionEvent> events=new ArrayList<>(); List<String> timeline=new ArrayList<>();
        Map<String,String> owners=new HashMap<>();
        boolean monitor=user.equals(admin);
        try(PreparedStatement p=db.prepareStatement("SELECT * FROM (SELECT * FROM events WHERE (user=? OR ?=1) ORDER BY id DESC LIMIT 500) ORDER BY id")) {
            p.setString(1,user); p.setInt(2,monitor?1:0); try(ResultSet r=p.executeQuery()) { while(r.next()) {
                owners.put(r.getString("session"),r.getString("user"));
                String loc=r.getString("location"); boolean london=loc.equals("london"), known=!loc.isEmpty();
                events.add(new SessionEvent(r.getString("session"),Instant.parse(r.getString("time")),r.getString("user"),r.getString("ip"),known?(london?"London":"Chennai"):"Unknown",known?(london?"UK":"IN"):"Unknown",known?(london?51.5074:13.0827):0,known?(london?-0.1278:80.2707):0,r.getString("ua"),new CookieInfo(r.getInt("secure")==1,true,"Strict")));
                timeline.add("{\"user\":"+q(r.getString("user"))+",\"time\":"+q(r.getString("time"))+",\"ip\":"+q(r.getString("ip"))+",\"ua\":"+q(r.getString("ua"))+",\"simulated\":"+(r.getInt("simulated")==1)+",\"path\":"+q(r.getString("path"))+"}");
            }}
        }
        List<SessionEvent> geo=events.stream().filter(e->!e.getCity().equals("Unknown")).toList();
        // Never infer travel between unknown coordinates and a lab fixture.
        RiskEngine liveEngine=new RiskEngine(List.of(new CookieAttributeAnalyzer(),new IpChangeAnalyzer(),new UserAgentAnalyzer(),new ConcurrentSessionAnalyzer(),new BurstAnalyzer()));
        Map<String,List<Alert>> travel=new HashMap<>();
        for(Alert a:new ImpossibleTravelAnalyzer().analyze(geo)) travel.computeIfAbsent(a.getSessionId(),k->new ArrayList<>()).add(a);
        List<String> rows=new ArrayList<>();
        for(SessionRisk risk:liveEngine.evaluate(events)) {
            List<Alert> alerts=new ArrayList<>(risk.getAlerts()); alerts.addAll(travel.getOrDefault(risk.getSessionId(),List.of()));
            int score=Math.min(100,alerts.stream().mapToInt(Alert::getPoints).sum());
            List<String> evidence=new ArrayList<>();
            for(Alert a:alerts) evidence.add("{\"analyzer\":"+q(a.getAnalyzerName())+",\"explanation\":"+q(a.getExplanation())+",\"recommendation\":"+q(a.getRecommendation())+"}");
            Session active=sessions.get(risk.getSessionId());
            rows.add("{\"user\":"+q(owners.get(risk.getSessionId()))+",\"id\":"+q(risk.getSessionId())+",\"active\":"+(active!=null && active.expires>System.currentTimeMillis())+",\"score\":"+score+",\"level\":"+q(score>=60?"HIGH":score>=30?"MEDIUM":"LOW")+",\"alerts\":["+String.join(",",evidence)+"]}");
        }
        Collections.reverse(timeline);
        return "{\"scope\":"+q(monitor?"website":"account")+",\"scenario\":"+q(monitor?scenario.status():"")+",\"updatedAt\":"+q(Instant.now().toString())+",\"events\":"+events.size()+",\"sessions\":["+String.join(",",rows)+"],\"timeline\":["+String.join(",",timeline.subList(0,Math.min(30,timeline.size())))+"]}";
    }
    private void setCookie(HttpExchange x,String value,int age) { x.getResponseHeaders().add("Set-Cookie","ct_session="+value+"; Path=/; HttpOnly; SameSite=Strict; Max-Age="+age+(secure?"; Secure":"")); }
    private static String cookie(HttpExchange x) {
        for(String header:x.getRequestHeaders().getOrDefault("Cookie",List.of())) for(String part:header.split(";")) if(part.trim().startsWith("ct_session=")) return part.trim().substring(11);
        return "";
    }
    static String q(String s) {
        StringBuilder b=new StringBuilder("\""); for(char c:s.toCharArray()) {
            if(c=='"' || c=='\\') b.append('\\').append(c); else if(c<32) b.append(String.format("\\u%04x",(int)c)); else b.append(c);
        } return b.append('"').toString();
    }
    private static void send(HttpExchange x,int status,String value) throws java.io.IOException {
        byte[] b=value.getBytes(StandardCharsets.UTF_8); x.getResponseHeaders().set("Content-Type","application/json; charset=utf-8"); x.sendResponseHeaders(status,b.length); x.getResponseBody().write(b);
    }
    private static void staticFile(HttpExchange x,String path) throws Exception {
        if(!x.getRequestMethod().equals("GET")) { send(x,405,"{}"); return; }
        String name=switch(path) { case "/" -> "index.html"; case "/app.js" -> "app.js"; case "/style.css" -> "style.css"; case "/shop" -> "shop.html"; case "/shop.js" -> "shop.js"; default -> null; };
        if(name==null) { send(x,404,"{}"); return; }
        try(var in=WebServer.class.getResourceAsStream("/web/"+name)) {
            byte[] b=in.readAllBytes(); x.getResponseHeaders().set("Content-Type",name.endsWith("html")?"text/html; charset=utf-8":name.endsWith("js")?"text/javascript; charset=utf-8":"text/css; charset=utf-8");
            x.sendResponseHeaders(200,b.length); x.getResponseBody().write(b);
        }
    }
}
