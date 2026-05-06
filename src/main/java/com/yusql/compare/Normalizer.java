package com.yusql.compare;

import java.util.*;
import java.util.regex.*;

public class Normalizer {
    private static final Pattern UUID_RE = Pattern.compile("\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b");
    private static final Pattern HEX128_RE = Pattern.compile("\\b[0-9a-fA-F]{128}\\b");
    private static final Pattern HEX64_RE = Pattern.compile("\\b[0-9a-fA-F]{64}\\b");
    private static final Pattern HEX40_RE = Pattern.compile("\\b[0-9a-fA-F]{40}\\b");
    private static final Pattern HEX32_RE = Pattern.compile("\\b[0-9a-fA-F]{32}\\b");
    private static final Pattern TS13_RE = Pattern.compile("\\b1\\d{12}\\b");
    private static final Pattern TS10_RE = Pattern.compile("\\b1\\d{9}\\b");
    private static final Pattern ISO_DT_RE = Pattern.compile("\\b\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,6})?(?:Z|[+-]\\d{2}:\\d{2})?\\b");
    private static final Pattern JWT_RE = Pattern.compile("\\beyJ[a-zA-Z0-9_-]{5,}\\.[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}\\b");
    private static final Pattern TOKEN_KV_RE = Pattern.compile("(?i)(?<prefix>\\b(?:token|access[_-]?token|refresh[_-]?token|id[_-]?token|jwt)\\b\\s*[:=]\\s*[\"']?)(?<val>[A-Za-z0-9._\\-+/=]{8,})");
    private static final Pattern AUTH_BEARER_RE = Pattern.compile("(?i)(\\bAuthorization\\b\\s*:\\s*\\bBearer\\b\\s+)([A-Za-z0-9._\\-+/=]{8,})");
    private static final Pattern SESSION_KV_RE = Pattern.compile("(?i)(?<prefix>\\b(?:sessionid|session_id|jsessionid|phpsessid)\\b\\s*[:=]\\s*[\"']?)(?<val>[A-Za-z0-9._\\-]{6,})");
    private static final Pattern COOKIE_SESSION_RE = Pattern.compile("(?i)(?<prefix>\\b(?:sessionid|session_id|JSESSIONID|PHPSESSID)\\b=)(?<val>[^;,\\s\"]+)");
    private static final Pattern DYNAMIC_KV_RE = Pattern.compile("(?i)(?<prefix>\\b(?:csrf|nonce|requestId|traceId|reqId|timestamp|_t)\\b\\s*[:=]\\s*[\"']?)(?<val>[^\"',&\\s]+)");

    private List<Pattern> customNoisePatterns = new ArrayList<>();
    private boolean removeWs = false;

    public void setNoise(List<Pattern> patterns) { this.customNoisePatterns = patterns != null ? patterns : new ArrayList<>(); }
    public void setRemoveWs(boolean v) { this.removeWs = v; }

    public String normalize(String body) {
        if (body == null) return "";
        String s = body;
        // Step 1: strip single quotes
        s = s.replace("\\'", "").replace("'", "");
        // Step 2: built-in patterns
        s = UUID_RE.matcher(s).replaceAll("<UUID>");
        s = HEX128_RE.matcher(s).replaceAll("<HEX>");
        s = HEX64_RE.matcher(s).replaceAll("<HEX>");
        s = HEX40_RE.matcher(s).replaceAll("<HEX>");
        s = HEX32_RE.matcher(s).replaceAll("<HEX>");
        s = TS13_RE.matcher(s).replaceAll("<TS>");
        s = TS10_RE.matcher(s).replaceAll("<TS>");
        s = ISO_DT_RE.matcher(s).replaceAll("<DATETIME>");
        s = JWT_RE.matcher(s).replaceAll("<JWT>");
        s = TOKEN_KV_RE.matcher(s).replaceAll("${prefix}<TOKEN>");
        s = AUTH_BEARER_RE.matcher(s).replaceAll("$1<TOKEN>");
        s = SESSION_KV_RE.matcher(s).replaceAll("${prefix}<SESSION>");
        s = COOKIE_SESSION_RE.matcher(s).replaceAll("${prefix}<SESSION>");
        s = DYNAMIC_KV_RE.matcher(s).replaceAll("${prefix}<NOISE>");
        // Step 3: custom noise patterns
        for (Pattern p : customNoisePatterns) s = p.matcher(s).replaceAll("<NOISE>");
        // Step 4: optional whitespace removal
        if (removeWs) s = s.replaceAll("\\s+", "");
        return s;
    }
}
