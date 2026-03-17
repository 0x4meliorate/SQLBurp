package com.sqlburp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class ScanOptions {

    public int     level       = 1;
    public int     risk        = 1;
    public int     threads     = 1;
    public String  technique   = "BEUSTQ";
    public String  dbms        = "(auto)";
    public String  tamper      = "";
    public boolean batch       = true;
    public boolean randomAgent = false;
    public boolean forms       = false;
    public boolean getDbs      = true;
    public boolean currentUser = true;
    public boolean banner      = true;
    public boolean isDba       = false;
    public boolean forceSSL    = false;
    public int     verbose     = 2;

    public ScanOptions() {}

    public ScanOptions copy() {
        ScanOptions c = new ScanOptions();
        c.level       = this.level;
        c.risk        = this.risk;
        c.threads     = this.threads;
        c.technique   = this.technique;
        c.dbms        = this.dbms;
        c.tamper      = this.tamper;
        c.batch       = this.batch;
        c.randomAgent = this.randomAgent;
        c.forms       = this.forms;
        c.getDbs      = this.getDbs;
        c.currentUser = this.currentUser;
        c.banner      = this.banner;
        c.isDba       = this.isDba;
        c.forceSSL    = this.forceSSL;
        c.verbose     = this.verbose;
        return c;
    }

    /** Serialise to the dict expected by /option/{id}/set */
    public ObjectNode toApiDict(ObjectMapper mapper, String requestFile) {
        ObjectNode n = mapper.createObjectNode();
        n.put("requestFile",    requestFile);
        n.put("level",          level);
        n.put("risk",           risk);
        n.put("threads",        threads);
        n.put("technique",      technique.isEmpty() ? "BEUSTQ" : technique);
        n.put("batch",          batch);
        n.put("randomAgent",    randomAgent);
        n.put("forms",          forms);
        n.put("getDbs",         getDbs);
        n.put("getCurrentUser", currentUser);
        n.put("getBanner",      banner);
        n.put("isDba",          isDba);
        n.put("forceSSL",       forceSSL);
        n.put("verbose",        verbose);
        if (dbms != null && !dbms.equals("(auto)") && !dbms.isEmpty()) {
            n.put("dbms", dbms);
        }
        if (tamper != null && !tamper.isEmpty()) {
            n.put("tamper", tamper);
        }
        return n;
    }

    /** Deserialise from persisted JSON */
    public static ScanOptions fromJson(JsonNode j) {
        ScanOptions o = new ScanOptions();
        if (j == null) return o;
        o.level       = j.path("level").asInt(1);
        o.risk        = j.path("risk").asInt(1);
        o.threads     = j.path("threads").asInt(1);
        o.technique   = j.path("technique").asText("BEUSTQ");
        o.dbms        = j.path("dbms").asText("(auto)");
        o.tamper      = j.path("tamper").asText("");
        o.batch       = j.path("batch").asBoolean(true);
        o.randomAgent = j.path("randomAgent").asBoolean(false);
        o.forms       = j.path("forms").asBoolean(false);
        o.getDbs      = j.path("getDbs").asBoolean(true);
        o.currentUser = j.path("currentUser").asBoolean(true);
        o.banner      = j.path("banner").asBoolean(true);
        o.isDba       = j.path("isDba").asBoolean(false);
        o.forceSSL    = j.path("forceSSL").asBoolean(false);
        o.verbose     = j.path("verbose").asInt(2);
        return o;
    }

    /** Serialise options sub-object to JSON */
    public ObjectNode toJson(ObjectMapper mapper) {
        ObjectNode n = mapper.createObjectNode();
        n.put("level",       level);
        n.put("risk",        risk);
        n.put("threads",     threads);
        n.put("technique",   technique);
        n.put("dbms",        dbms);
        n.put("tamper",      tamper);
        n.put("batch",       batch);
        n.put("randomAgent", randomAgent);
        n.put("forms",       forms);
        n.put("getDbs",      getDbs);
        n.put("currentUser", currentUser);
        n.put("banner",      banner);
        n.put("isDba",       isDba);
        n.put("forceSSL",    forceSSL);
        n.put("verbose",     verbose);
        return n;
    }

    public String[] summaryLines() {
        StringBuilder flags = new StringBuilder();
        if (batch)       flags.append("batch ");
        if (randomAgent) flags.append("random-agent ");
        if (forms)       flags.append("forms ");
        if (getDbs)      flags.append("enum-dbs ");
        if (currentUser) flags.append("current-user ");
        if (banner)      flags.append("banner ");
        if (isDba)       flags.append("is-dba ");
        if (forceSSL)    flags.append("force-ssl ");
        return new String[]{
            "Level     : " + level,
            "Risk      : " + risk,
            "Threads   : " + threads,
            "Technique : " + technique,
            "DBMS      : " + dbms,
            "Tamper    : " + (tamper.isEmpty() ? "(none)" : tamper),
            "Verbose   : " + verbose,
            "Flags     : " + (flags.length() == 0 ? "(none)" : flags.toString().trim()),
        };
    }
}
