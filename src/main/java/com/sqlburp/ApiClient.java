package com.sqlburp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class ApiClient {

    private final ObjectMapper mapper = new ObjectMapper();

    private JsonNode request(String method, String baseUrl, String path, String body) throws IOException {
        URL url = new URL(baseUrl.replaceAll("/$", "") + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method.toUpperCase());
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Accept",       "application/json");
        conn.setConnectTimeout(5_000);
        conn.setReadTimeout(30_000);
        if (body != null) {
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
        }
        int status = conn.getResponseCode();
        InputStream stream = status < 400 ? conn.getInputStream() : conn.getErrorStream();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            return mapper.readTree(sb.toString());
        }
    }

    public JsonNode get(String baseUrl, String path) throws IOException {
        return request("GET", baseUrl, path, null);
    }

    public JsonNode post(String baseUrl, String path, ObjectNode payload) throws IOException {
        return request("POST", baseUrl, path, mapper.writeValueAsString(payload));
    }

    public ObjectMapper mapper() {
        return mapper;
    }

    /** Create a new sqlmap task, return taskid or throw. */
    public String newTask(String baseUrl) throws IOException {
        JsonNode resp = get(baseUrl, "/task/new");
        String tid = resp.path("taskid").asText(null);
        if (tid == null || tid.isEmpty()) throw new IOException("No taskid in response: " + resp);
        return tid;
    }

    /** Delete a task from sqlmapapi (best-effort). */
    public void deleteTask(String baseUrl, String taskId) {
        try { get(baseUrl, "/task/" + taskId + "/delete"); } catch (Exception ignored) {}
    }

    /** Stop a running task (best-effort). */
    public void stopTask(String baseUrl, String taskId) {
        try { get(baseUrl, "/scan/" + taskId + "/stop"); } catch (Exception ignored) {}
    }

    /** Poll scan status. Returns status string e.g. "running", "terminated". */
    public String scanStatus(String baseUrl, String taskId) throws IOException {
        return get(baseUrl, "/scan/" + taskId + "/status").path("status").asText("unknown");
    }

    /** Fetch log lines as JsonNode array from offset. */
    public JsonNode scanLog(String baseUrl, String taskId) throws IOException {
        return get(baseUrl, "/scan/" + taskId + "/log").path("log");
    }

    /** Fetch scan data (injection results). */
    public JsonNode scanData(String baseUrl, String taskId) throws IOException {
        return get(baseUrl, "/scan/" + taskId + "/data").path("data");
    }
}
