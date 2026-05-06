package com.yusql.parser;

import com.yusql.model.*;
import java.util.*;

public class ParameterParser {
    private final String method;
    private final String url;
    private final byte[] body;
    private final String contentType;
    private final boolean enableJsonValue;
    private final boolean enableJsonInParam;

    public ParameterParser(String method, String url, byte[] body, String contentType,
                          boolean enableJsonValue, boolean enableJsonInParam) {
        this.method = method;
        this.url = url;
        this.body = body;
        this.contentType = contentType != null ? contentType : "";
        this.enableJsonValue = enableJsonValue;
        this.enableJsonInParam = enableJsonInParam;
    }

    public List<TestPoint> findAll() {
        List<TestPoint> points = new ArrayList<>();
        if (isJsonBody()) {
            if (enableJsonValue) parseJsonBody(points);
        } else {
            parseQueryParams(points);
            if (isForm()) parseFormBody(points);
        }
        return points;
    }

    private boolean isJsonBody() { return contentType.toLowerCase().contains("application/json"); }
    private boolean isForm() { return contentType.toLowerCase().contains("application/x-www-form-urlencoded") || (body != null && body.length > 0); }

    private void parseQueryParams(List<TestPoint> points) {
        String q = getQuery(url);
        if (q == null || q.isEmpty()) return;
        for (String p : q.split("&")) {
            if (p.isEmpty()) continue;
            String[] kv = split(p);
            if (kv == null) continue;
            String key = JsonInParamParser.decode(kv[0]);
            String raw = kv.length > 1 ? kv[1] : "";
            String val = JsonInParamParser.decode(raw);
            boolean isJson = JsonInParamParser.looksLikeJson(val);
            points.add(new TestPoint(key, val, ParamType.GET, "", isJson ? JsonTestType.VALUE : JsonTestType.NONE, false));
            if (enableJsonInParam) checkJsonInParam(points, key, raw, val, ParamType.GET);
        }
    }

    private void parseFormBody(List<TestPoint> points) {
        if (body == null || body.length == 0) return;
        String s = new String(body, java.nio.charset.StandardCharsets.UTF_8);
        for (String p : s.split("&")) {
            if (p.isEmpty()) continue;
            String[] kv = split(p);
            if (kv == null) continue;
            String key = JsonInParamParser.decode(kv[0]);
            String raw = kv.length > 1 ? kv[1] : "";
            String val = JsonInParamParser.decode(raw);
            boolean isJson = JsonInParamParser.looksLikeJson(val);
            points.add(new TestPoint(key, val, ParamType.POST_FORM, "", isJson ? JsonTestType.VALUE : JsonTestType.NONE, false));
            if (enableJsonInParam) checkJsonInParam(points, key, raw, val, ParamType.POST_FORM);
        }
    }

    private void checkJsonInParam(List<TestPoint> points, String outerKey, String rawVal, String decodedVal, ParamType outerType) {
        if (!JsonInParamParser.looksLikeJson(decodedVal)) return;
        Object root = SimpleJson.parse(decodedVal);
        if (root == null) return;
        boolean wasEncoded = !rawVal.equals(decodedVal);
        addJsonPoints(points, root, "$", outerKey, ParamType.JSON_IN_PARAM, wasEncoded);
    }

    private void parseJsonBody(List<TestPoint> points) {
        if (body == null || body.length == 0) return;
        String json = new String(body, java.nio.charset.StandardCharsets.UTF_8);
        Object root = SimpleJson.parse(json);
        if (root != null) addJsonPoints(points, root, "$", "", ParamType.JSON_BODY, false);
    }

    @SuppressWarnings("unchecked")
    private void addJsonPoints(List<TestPoint> points, Object node, String path, String outerParam, ParamType paramType, boolean encoded) {
        if (node instanceof Map) {
            Map<String,Object> m = (Map<String,Object>) node;
            for (Map.Entry<String,Object> e : m.entrySet()) {
                String newPath = path.equals("$") ? "$." + e.getKey() : path + "." + e.getKey();
                Object child = e.getValue();
                if (child instanceof String) {
                    String childStr = (String) child;
                    points.add(new TestPoint(outerParam.isEmpty() ? e.getKey() : outerParam,
                        childStr, paramType, newPath, JsonTestType.VALUE, encoded));
                    // 递归解析嵌套JSON字符串(如 {"ids":"{\"a\":\"v\"}"})
                    if (JsonInParamParser.looksLikeJson(childStr)) {
                        Object inner = SimpleJson.parse(childStr);
                        if (inner != null) {
                            addJsonPoints(points, inner, newPath, outerParam.isEmpty() ? e.getKey() : outerParam, paramType, encoded);
                        }
                    }
                } else if (child instanceof Number) {
                    points.add(new TestPoint(outerParam.isEmpty() ? e.getKey() : outerParam,
                        child.toString(), paramType, newPath, JsonTestType.VALUE, encoded));
                } else if (child instanceof Map) {
                    addJsonPoints(points, child, newPath, outerParam, paramType, encoded);
                }
                // Arrays (List) are skipped
            }
        }
        // Arrays (List) at root level are skipped
    }

    public static String getQuery(String url) {
        int qi = url.indexOf('?');
        return qi >= 0 && qi < url.length() - 1 ? url.substring(qi + 1) : null;
    }

    public static String stripQuery(String url) {
        int qi = url.indexOf('?');
        return qi >= 0 ? url.substring(0, qi) : url;
    }

    private static String[] split(String p) {
        int i = p.indexOf('=');
        return i < 0 ? new String[]{p, ""} : new String[]{p.substring(0, i), p.substring(i + 1)};
    }
}
