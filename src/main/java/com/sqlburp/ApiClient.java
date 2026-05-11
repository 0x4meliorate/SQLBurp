package com.sqlburp;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.utilities.json.JsonNode;
import burp.api.montoya.utilities.json.JsonObjectNode;

import java.io.IOException;

import static burp.api.montoya.utilities.json.JsonObjectNode.jsonObjectNode;

public class ApiClient {

    private final Http http;

    public ApiClient(Http http) {
        this.http = http;
    }

    private static String stripTrailingSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    private JsonNode request(String method, String baseUrl, String path, String body) throws IOException {
        String url = stripTrailingSlash(baseUrl) + path;

        HttpRequest req = HttpRequest.httpRequestFromUrl(url)
            .withMethod(method.toUpperCase())
            .withHeader("Accept", "application/json");

        if (body != null) {
            req = req.withHeader("Content-Type", "application/json")
                     .withBody(body);
        }

        HttpRequestResponse rr = http.sendRequest(req);
        if (rr.response() == null) {
            throw new IOException("No response from " + url);
        }

        String responseBody = rr.response().bodyToString();
        JsonNode node = JsonNode.jsonNode(responseBody);
        if (node == null) {
            throw new IOException("Invalid JSON response from " + url + ": " + responseBody);
        }
        return node;
    }

    public JsonNode get(String baseUrl, String path) throws IOException {
        return request("GET", baseUrl, path, null);
    }

    public JsonNode post(String baseUrl, String path, JsonObjectNode payload) throws IOException {
        return request("POST", baseUrl, path, payload.toJsonString());
    }

    public String newTask(String baseUrl) throws IOException {
        JsonNode resp = get(baseUrl, "/task/new");
        String tid = resp.asObject().getString("taskid");
        if (tid == null || tid.isEmpty()) throw new IOException("No taskid in response: " + resp.toJsonString());
        return tid;
    }

    public void deleteTask(String baseUrl, String taskId) {
        try { get(baseUrl, "/task/" + taskId + "/delete"); } catch (Exception ignored) {}
    }

    public void stopTask(String baseUrl, String taskId) {
        try { get(baseUrl, "/scan/" + taskId + "/stop"); } catch (Exception ignored) {}
    }

    public String scanStatus(String baseUrl, String taskId) throws IOException {
        JsonNode resp = get(baseUrl, "/scan/" + taskId + "/status");
        String status = resp.asObject().getString("status");
        return status != null ? status : "unknown";
    }

    public JsonNode scanLog(String baseUrl, String taskId) throws IOException {
        return get(baseUrl, "/scan/" + taskId + "/log").asObject().get("log");
    }

    public JsonNode scanData(String baseUrl, String taskId) throws IOException {
        return get(baseUrl, "/scan/" + taskId + "/data").asObject().get("data");
    }
}
