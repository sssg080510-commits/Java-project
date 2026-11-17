package com.cookietrace.web;

import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.UUID;

/** Sends genuine HTTP requests using only a newly created local lab account. */
final class LabScenario {
    private volatile String status="Ready — no test running";
    private boolean running;
    String status() { return status; }
    synchronized boolean start(int port) {
        if(running) return false;
        running=true; status="Starting dedicated test account";
        Thread worker=new Thread(()-> {
            try { run(port); }
            catch(Exception e) { status="Test failed: "+e.getClass().getSimpleName(); }
            finally { synchronized(this) { running=false; } }
        },"local-security-scenario");
        worker.setDaemon(true); worker.start(); return true;
    }
    private void run(int port) throws Exception {
        HttpClient http=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        String base="http://127.0.0.1:"+port;
        status="Normal browsing — creating lab account";
        String name="lab_"+UUID.randomUUID().toString().replace("-", "").substring(0,12);
        var register=http.send(HttpRequest.newBuilder(URI.create(base+"/api/register"))
            .timeout(Duration.ofSeconds(10)).header("User-Agent","Lab Chrome / legitimate browser")
            .header("Content-Type","application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString("username="+name+"&password="+UUID.randomUUID())).build(),HttpResponse.BodyHandlers.ofString());
        if(register.statusCode()!=200) throw new IllegalStateException("Registration rejected");
        String cookie=register.headers().firstValue("Set-Cookie").orElseThrow().split(";",2)[0];
        String userAgent="Lab Chrome / legitimate browser";
        for(int i=0;i<4;i++) { request(http,base,cookie,userAgent,null); Thread.sleep(1000); }
        status="Session replay — same test cookie used by a different browser";
        request(http,base,cookie,"Lab Firefox / replay client",null); Thread.sleep(2000);
        status="Location change — labelled Chennai and London test fixtures";
        request(http,base,cookie,userAgent,"chennai"); Thread.sleep(1500);
        request(http,base,cookie,"Lab Firefox / replay client","london"); Thread.sleep(2000);
        status="Request burst — 20 requests from replay client";
        for(int i=0;i<20;i++) request(http,base,cookie,"Lab Firefox / replay client","london");
        status="Complete — replay, location change and burst requests sent. Review the flagged lab session below.";
    }
    private void request(HttpClient http,String base,String cookie,String ua,String location) throws Exception {
        var builder=HttpRequest.newBuilder(URI.create(base+"/api/profile")).timeout(Duration.ofSeconds(10))
            .header("Cookie",cookie).header("User-Agent",ua).GET();
        if(location!=null) builder.header("X-Lab-Location",location);
        var response=http.send(builder.build(),HttpResponse.BodyHandlers.discarding());
        if(response.statusCode()!=200) throw new IllegalStateException("Activity rejected");
    }
}
