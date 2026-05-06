package com.yusql.parser;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class JsonInParamParser {

    public static String decode(String v) {
        if (v == null) return null;
        try { return URLDecoder.decode(v, StandardCharsets.UTF_8); }
        catch (Exception e) { return v; }
    }

    public static String encode(String v) {
        if (v == null) return null;
        try { return URLEncoder.encode(v, StandardCharsets.UTF_8)
            .replace("+", "%20").replace("%7B", "{").replace("%7D", "}")
            .replace("%22", "%22").replace("%3A", ":").replace("%2C", ",")
            .replace("%5B", "[").replace("%5D", "]"); }
        catch (Exception e) { return v; }
    }

    public static boolean looksLikeJson(String value) {
        if (value == null || value.isEmpty()) return false;
        String trimmed = value.trim();
        return (trimmed.startsWith("{") && trimmed.endsWith("}"))
            || (trimmed.startsWith("[") && trimmed.endsWith("]"));
    }
}
