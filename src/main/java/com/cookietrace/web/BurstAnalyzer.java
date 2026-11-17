package com.cookietrace.web;
import com.cookietrace.analysis.SecurityAnalyzer;
import com.cookietrace.model.*;
import java.time.Duration;
import java.util.*;
/** Sliding-window burst signal; an indicator, not proof of compromise. */
public final class BurstAnalyzer extends SecurityAnalyzer {
    public BurstAnalyzer() { super("BurstAnalyzer",20); }
    public List<Alert> analyze(List<SessionEvent> events) {
        List<Alert> alerts=new ArrayList<>();
        for(var entry:groupBySession(events).entrySet()) {
            var list=entry.getValue();
            for(int i=19;i<list.size();i++) if(Duration.between(list.get(i-19).getEventTime(),list.get(i).getEventTime()).toMillis()<=10000) {
                alerts.add(buildAlert(entry.getKey(),20,"At least 20 requests occurred within 10 seconds; automation or rapid interaction may be present.","Review request activity and apply rate limits if needed.")); break;
            }
        }
        return alerts;
    }
}
