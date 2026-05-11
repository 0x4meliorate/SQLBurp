package com.sqlburp;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.utilities.json.JsonArrayNode;
import burp.api.montoya.utilities.json.JsonNode;
import burp.api.montoya.utilities.json.JsonObjectNode;

import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.utilities.json.JsonArrayNode.jsonArrayNode;
import static burp.api.montoya.utilities.json.JsonObjectNode.jsonObjectNode;

public class PersistenceManager {

    private static final String KEY_TASKS    = "sqlburp_tasks";
    private static final String KEY_SCAN_PFX = "sqlburp_scan_";

    private final PersistedObject store;
    private final Logging         logging;

    /** In-memory cache to avoid deserialising the task list on every add/remove. */
    private List<String> taskIdCache;

    public PersistenceManager(PersistedObject store, Logging logging) {
        this.store   = store;
        this.logging = logging;
    }

    // ------------------------------------------------------------------
    // Task list
    // ------------------------------------------------------------------

    public synchronized List<String> loadTaskIds() {
        if (taskIdCache != null) {
            logging.logToOutput("SQLBurp: loadTaskIds (cached): " + taskIdCache);
            return new ArrayList<>(taskIdCache);
        }
        String raw = store.getString(KEY_TASKS);
        logging.logToOutput("SQLBurp: loadTaskIds from store: " + raw);
        if (raw == null || raw.isEmpty()) {
            taskIdCache = new ArrayList<>();
            return new ArrayList<>();
        }
        try {
            List<String> ids = new ArrayList<>();
            JsonNode node = JsonNode.jsonNode(raw);
            if (node != null && node.isArray()) {
                for (JsonNode item : node.asArray().asList()) {
                    ids.add(item.asString());
                }
            }
            taskIdCache = ids;
            return new ArrayList<>(ids);
        } catch (Exception e) {
            logging.logToError("SQLBurp: failed to load task IDs: " + e.getMessage());
            taskIdCache = new ArrayList<>();
            return new ArrayList<>();
        }
    }

    private synchronized void flushTaskIds() {
        if (taskIdCache == null) return;
        try {
            JsonArrayNode arr = jsonArrayNode();
            taskIdCache.forEach(arr::addString);
            String json = arr.toJsonString();
            store.setString(KEY_TASKS, json);
            logging.logToOutput("SQLBurp: flushed task IDs: " + json);
        } catch (Exception e) {
            logging.logToError("SQLBurp: failed to flush task IDs: " + e.getMessage());
        }
    }

    public synchronized void addTaskId(String taskId) {
        if (taskIdCache == null) loadTaskIds();
        if (!taskIdCache.contains(taskId)) {
            taskIdCache.add(taskId);
            flushTaskIds();
        }
    }

    public synchronized void removeTaskId(String taskId) {
        if (taskIdCache == null) loadTaskIds();
        if (taskIdCache.remove(taskId)) {
            flushTaskIds();
        }
    }

    // ------------------------------------------------------------------
    // Scan records
    // ------------------------------------------------------------------

    public synchronized void saveScanRecord(ScanRecord rec) {
        try {
            JsonObjectNode n = jsonObjectNode();
            n.putString("taskId",   rec.taskId);
            n.putString("target",   rec.target);
            n.putString("method",   rec.method);
            n.putString("status",   rec.status);
            n.putNumber("findings", (long) rec.findings);
            n.putString("started",  rec.started);

            JsonArrayNode log = jsonArrayNode();
            synchronized (rec.logLines) {
                for (String line : rec.logLines) {
                    log.addString(line);
                }
            }
            n.put("logLines", log);

            JsonArrayNode results = jsonArrayNode();
            for (JsonNode r : rec.results) {
                results.add(r);
            }
            n.put("results", results);
            n.put("options", rec.options.toJson());

            store.setString(KEY_SCAN_PFX + rec.taskId, n.toJsonString());
            logging.logToOutput("SQLBurp: saved scan record " + rec.taskId
                + " [" + rec.status + ", " + rec.logLines.size() + " log lines]");
        } catch (Exception e) {
            logging.logToError("SQLBurp: failed to save scan record "
                + rec.taskId + ": " + e.getMessage());
        }
    }

    public synchronized ScanRecord loadScanRecord(String taskId) {
        String raw = store.getString(KEY_SCAN_PFX + taskId);
        if (raw == null || raw.isEmpty()) return null;
        try {
            JsonNode node = JsonNode.jsonNode(raw);
            if (node == null || !node.isObject()) return null;
            JsonObjectNode j = node.asObject();

            JsonNode targetNode  = j.get("target");
            JsonNode methodNode  = j.get("method");
            JsonNode statusNode  = j.get("status");
            JsonNode findingsNode = j.get("findings");

            ScanRecord r = new ScanRecord(
                taskId,
                (targetNode != null && targetNode.isString()) ? targetNode.asString() : "(unknown)",
                (methodNode != null && methodNode.isString()) ? methodNode.asString() : "GET"
            );
            r.status   = (statusNode != null && statusNode.isString()) ? statusNode.asString() : ScanRecord.STATUS_DONE;
            r.findings = (findingsNode != null && findingsNode.isNumber()) ? ((Number) findingsNode.asNumber()).intValue() : 0;

            JsonNode logNode = j.get("logLines");
            if (logNode != null && logNode.isArray()) {
                for (JsonNode line : logNode.asArray().asList()) r.logLines.add(line.asString());
            }

            JsonNode resultsNode = j.get("results");
            if (resultsNode != null && resultsNode.isArray()) {
                for (JsonNode res : resultsNode.asArray().asList()) r.results.add(res);
            }

            JsonNode optsNode = j.get("options");
            r.options = optsNode != null && optsNode.isObject()
                ? ScanOptions.fromJson(optsNode.asObject())
                : new ScanOptions();

            return r;
        } catch (Exception e) {
            logging.logToError("SQLBurp: failed to load scan record "
                + taskId + ": " + e.getMessage());
            return null;
        }
    }

    public synchronized void deleteScanRecord(String taskId) {
        try {
            store.setString(KEY_SCAN_PFX + taskId, null);
        } catch (Exception e) {
            logging.logToError("SQLBurp: failed to delete scan record "
                + taskId + ": " + e.getMessage());
        }
        removeTaskId(taskId);
    }
}
