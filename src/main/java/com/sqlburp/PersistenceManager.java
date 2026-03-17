package com.sqlburp;

import burp.api.montoya.persistence.PersistedObject;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.List;

/**
 * All persistence goes through PersistedObject (extensionData()), which the
 * Montoya API stores in the Burp project file.  No fingerprinting needed.
 *
 * Schema:
 *   sqlburp_tasks          -> JSON array of task ID strings
 *   sqlburp_scan_<taskId>  -> JSON object with full scan record
 */
public class PersistenceManager {

    private static final String KEY_TASKS     = "sqlburp_tasks";
    private static final String KEY_SCAN_PFX  = "sqlburp_scan_";

    private final PersistedObject store;
    private final ObjectMapper    mapper;

    public PersistenceManager(PersistedObject store, ObjectMapper mapper) {
        this.store  = store;
        this.mapper = mapper;
    }

    // ------------------------------------------------------------------
    // Task list
    // ------------------------------------------------------------------

    public List<String> loadTaskIds() {
        String raw = store.getString(KEY_TASKS);
        if (raw == null || raw.isEmpty()) return new ArrayList<>();
        try {
            List<String> ids = new ArrayList<>();
            for (JsonNode n : mapper.readTree(raw)) ids.add(n.asText());
            return ids;
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    public void saveTaskIds(List<String> ids) {
        try {
            ArrayNode arr = mapper.createArrayNode();
            ids.forEach(arr::add);
            store.setString(KEY_TASKS, mapper.writeValueAsString(arr));
        } catch (Exception ignored) {}
    }

    public void addTaskId(String taskId) {
        List<String> ids = loadTaskIds();
        if (!ids.contains(taskId)) {
            ids.add(taskId);
            saveTaskIds(ids);
        }
    }

    public void removeTaskId(String taskId) {
        List<String> ids = loadTaskIds();
        ids.remove(taskId);
        saveTaskIds(ids);
    }

    // ------------------------------------------------------------------
    // Scan records
    // ------------------------------------------------------------------

    public void saveScanRecord(ScanRecord rec) {
        try {
            ObjectNode n = mapper.createObjectNode();
            n.put("taskId",   rec.taskId);
            n.put("target",   rec.target);
            n.put("method",   rec.method);
            n.put("status",   rec.status);
            n.put("findings", rec.findings);
            n.put("started",  rec.started);

            ArrayNode log = mapper.createArrayNode();
            rec.logLines.forEach(log::add);
            n.set("logLines", log);

            ArrayNode results = mapper.createArrayNode();
            for (Object r : rec.results) {
                results.add(mapper.valueToTree(r));
            }
            n.set("results", results);
            n.set("options", rec.options.toJson(mapper));

            store.setString(KEY_SCAN_PFX + rec.taskId, mapper.writeValueAsString(n));
        } catch (Exception ignored) {}
    }

    /** Returns null if no record is stored. */
    public ScanRecord loadScanRecord(String taskId) {
        String raw = store.getString(KEY_SCAN_PFX + taskId);
        if (raw == null || raw.isEmpty()) return null;
        try {
            JsonNode j   = mapper.readTree(raw);
            ScanRecord r = new ScanRecord(
                j.path("taskId").asText(taskId),
                j.path("target").asText("(unknown)"),
                j.path("method").asText("GET")
            );
            r.status   = j.path("status").asText(ScanRecord.STATUS_DONE);
            r.findings = j.path("findings").asInt(0);
            for (JsonNode line : j.path("logLines")) r.logLines.add(line.asText());
            for (JsonNode res  : j.path("results"))  r.results.add(res);
            r.options  = ScanOptions.fromJson(j.path("options"));
            return r;
        } catch (Exception e) {
            return null;
        }
    }

    public void deleteScanRecord(String taskId) {
        store.setString(KEY_SCAN_PFX + taskId, null);
        removeTaskId(taskId);
    }
}
