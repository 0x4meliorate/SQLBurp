package com.sqlburp;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class ScanRecord {

    public static final String STATUS_QUEUED  = "Queued";
    public static final String STATUS_RUNNING = "Running";
    public static final String STATUS_DONE    = "Finished";
    public static final String STATUS_VULN    = "Vulnerable";
    public static final String STATUS_ERROR   = "Error";
    public static final String STATUS_STOPPED = "Stopped";

    public final String     taskId;
    public final String     target;
    public final String     method;
    public       String     status;
    public       int        findings;
    public final String     started;
    public final List<String> logLines;
    public final List<Object> results;
    public       ScanOptions  options;

    public ScanRecord(String taskId, String target, String method) {
        this.taskId   = taskId;
        this.target   = target;
        this.method   = method;
        this.status   = STATUS_QUEUED;
        this.findings = 0;
        this.started  = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        this.logLines = new ArrayList<>();
        this.results  = new ArrayList<>();
        this.options  = new ScanOptions();
    }

    public void appendLog(String line) {
        logLines.add(line);
    }
}
