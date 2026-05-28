package com.yusql.mutate;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.yusql.model.*;
import com.yusql.parser.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static burp.api.montoya.core.ByteArray.byteArray;

public class RequestBuilder {
    private final HttpService httpService;
    private final byte[] originalBytes;
    private final String method;
    private final String url;
    private final byte[] body;
    private final String contentType;
    private final List<HttpHeader> headers;
    private final HttpRequest originalRequest;
    private String urlEncodeChars = "";
    private List<Map.Entry<String, String>> customHeaders = Collections.emptyList();

    public RequestBuilder(byte[] requestBytes, HttpService httpService) {
        this.originalBytes = requestBytes;
        this.httpService = httpService;
        String reqStr = new String(requestBytes, StandardCharsets.UTF_8);
        String[] lines = reqStr.split("\r\n");
        String[] reqLine = lines[0].split(" ", 3);
        this.method = reqLine[0];
        this.url = reqLine.length > 1 ? reqLine[1] : "/";
        // Parse headers
        List<HttpHeader> hdrs = new ArrayList<>();
        String ct = "";
        int i = 1;
        for (; i < lines.length; i++) {
            if (lines[i].isEmpty()) break;
            int ci = lines[i].indexOf(':');
            if (ci > 0) {
                String hn = lines[i].substring(0, ci).strip();
                String hv = lines[i].substring(ci + 1).strip();
                hdrs.add(new HttpHeader(hn, hv));
                if (hn.equalsIgnoreCase("content-type")) ct = hv;
            }
        }
        this.headers = hdrs;
        this.contentType = ct;
        // Parse body
        StringBuilder bodySb = new StringBuilder();
        for (i = i + 1; i < lines.length; i++) bodySb.append(lines[i]).append("\r\n");
        this.body = bodySb.toString().strip().getBytes(StandardCharsets.UTF_8);
        this.originalRequest = HttpRequest.httpRequest(httpService, byteArray(requestBytes));
    }

    public HttpRequest build(TestPoint tp, String payload) {
        return switch (tp.getParamType()) {
            case GET -> buildGet(tp, payload);
            case POST_FORM -> buildPostForm(tp, payload);
            case JSON_BODY -> buildJsonBody(tp, payload);
            case JSON_IN_PARAM -> buildJsonInParam(tp, payload);
        };
    }

    public HttpRequest buildOrder(String key, String value) {
        if (isJsonBody()) {
            String json = new String(body, StandardCharsets.UTF_8).strip();
            if (!json.startsWith("{")) return originalRequest;
            String insert = "\"" + SimpleJson.esc(key) + "\":" + jsonValue(value);
            String modified = json.replaceFirst("\\}$", "," + insert + "}");
            return HttpRequest.httpRequest(httpService, rebuildRequest(url, modified.getBytes(StandardCharsets.UTF_8)));
        } else if (isForm()) {
            byte[] newBody = upsertFormBody(key, value);
            return HttpRequest.httpRequest(httpService, rebuildRequest(url, newBody));
        } else {
            String q = ParameterParser.getQuery(url);
            String nq = upsertQueryParam(q, urlEncode(key), customEncode(urlEncode(value)));
            String nu = ParameterParser.stripQuery(url) + "?" + nq;
            return HttpRequest.httpRequest(httpService, rebuildRequest(nu, body));
        }
    }

    /** Append multiple key:value pairs in a single request (for bundled non-individual params) */
    public HttpRequest buildOrderBatch(Map<String, String> params) {
        if (params.isEmpty()) return originalRequest;
        if (isJsonBody()) {
            String json = new String(body, StandardCharsets.UTF_8).strip();
            if (!json.startsWith("{")) return originalRequest;
            StringBuilder sb = new StringBuilder(json.substring(0, json.length() - 1));
            for (var e : params.entrySet()) {
                sb.append(",\"").append(SimpleJson.esc(e.getKey()))
                  .append("\":").append(jsonValue(e.getValue()));
            }
            sb.append("}");
            return HttpRequest.httpRequest(httpService, rebuildRequest(url, sb.toString().getBytes(StandardCharsets.UTF_8)));
        } else if (isForm()) {
            String s = body != null && body.length > 0 ? new String(body, StandardCharsets.UTF_8).strip() : "";
            String result = upsertFormParams(s, params);
            return HttpRequest.httpRequest(httpService, rebuildRequest(url, result.getBytes(StandardCharsets.UTF_8)));
        } else {
            String q = ParameterParser.getQuery(url);
            String nq = upsertQueryParams(q != null ? q : "", params);
            String nu = ParameterParser.stripQuery(url) + "?" + nq;
            return HttpRequest.httpRequest(httpService, rebuildRequest(nu, body));
        }
    }

    private HttpRequest buildGet(TestPoint tp, String payload) {
        String q = ParameterParser.getQuery(url);
        if (q == null) return originalRequest;
        String newVal = urlEncode(tp.getParamValue() + payload);
        String nq = replaceQueryParam(q, tp.getParamName(), newVal);
        String nu = ParameterParser.stripQuery(url) + "?" + nq;
        return HttpRequest.httpRequest(httpService, rebuildRequest(nu, body));
    }

    private HttpRequest buildPostForm(TestPoint tp, String payload) {
        String newVal = urlEncode(tp.getParamValue() + payload);
        byte[] newBody = replaceFormBodyParam(tp.getParamName(), newVal);
        return HttpRequest.httpRequest(httpService, rebuildRequest(url, newBody));
    }

    private HttpRequest buildJsonBody(TestPoint tp, String payload) {
        String json = new String(body, StandardCharsets.UTF_8);
        try {
            Object root = SimpleJson.parse(json);
            if (root == null) return originalRequest;
            mutateJsonValue(root, tp.getJsonPath(), payload);
            String newJson = SimpleJson.toJson(root);
            return HttpRequest.httpRequest(httpService, rebuildRequest(url, newJson.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) { return originalRequest; }
    }

    private HttpRequest buildJsonInParam(TestPoint tp, String payload) {
        String q = ParameterParser.getQuery(url);
        String outerRaw = null;
        boolean foundInQuery = false;
        // Search GET query first
        if (q != null) {
            for (String p : q.split("&")) {
                String[] kv = split(p);
                if (kv != null && JsonInParamParser.decode(kv[0]).equals(tp.getParamName())) {
                    outerRaw = kv.length > 1 ? kv[1] : "";
                    foundInQuery = true;
                    break;
                }
            }
        }
        // If not in query, search POST body
        if (!foundInQuery && isForm() && body.length > 0) {
            String bs = new String(body, StandardCharsets.UTF_8);
            for (String p : bs.split("&")) {
                String[] kv = split(p);
                if (kv != null && JsonInParamParser.decode(kv[0]).equals(tp.getParamName())) {
                    outerRaw = kv.length > 1 ? kv[1] : "";
                    break;
                }
            }
        }
        if (outerRaw == null) return originalRequest;
        boolean wasEncoded = tp.isJsonEncoded();
        String innerJson = wasEncoded ? JsonInParamParser.decode(outerRaw) : outerRaw;
        try {
            Object root = SimpleJson.parse(innerJson);
            if (root == null) return originalRequest;
            mutateJsonValue(root, tp.getJsonPath(), payload);
            String newInner = SimpleJson.toJson(root);
            if (wasEncoded) newInner = JsonInParamParser.encode(newInner);
            if (foundInQuery) {
                String nq = replaceQueryParam(q, tp.getParamName(), newInner);
                String nu = ParameterParser.stripQuery(url) + "?" + nq;
                return HttpRequest.httpRequest(httpService, rebuildRequest(nu, body));
            } else {
                byte[] nb = replaceFormBodyParam(tp.getParamName(), newInner);
                return HttpRequest.httpRequest(httpService, rebuildRequest(url, nb));
            }
        } catch (Exception e) { return originalRequest; }
    }

    @SuppressWarnings("unchecked")
    public static boolean mutateJsonValue(Object node, String jsonPath, String payload) {
        if (node == null || jsonPath == null) return false;
        String[] segs = jsonPath.startsWith("$.") ? jsonPath.substring(2).split("\\.") : jsonPath.split("\\.");
        return traverse(node, segs, 0, payload);
    }

    @SuppressWarnings("unchecked")
    private static boolean traverse(Object node, String[] segs, int idx, String payload) {
        if (idx >= segs.length) return false;
        String seg = segs[idx];
        boolean last = (idx == segs.length - 1);
        if (node instanceof Map) {
            Map<String,Object> m = (Map<String,Object>) node;
            String key = seg; int arrIdx = -1;
            int bi = seg.indexOf('[');
            if (bi > 0) { key = seg.substring(0, bi); arrIdx = Integer.parseInt(seg.substring(bi+1, seg.indexOf(']'))); }
            if (last && arrIdx < 0) {
                Object v = m.get(key);
                if (v instanceof String) { m.put(key, (String)v + payload); return true; }
                else if (v instanceof Number) { m.put(key, v.toString() + payload); return true; }
                return false;
            }
            Object child = m.get(key);
            if (child == null) return false;
            if (arrIdx >= 0 && child instanceof List) {
                List<Object> list = (List<Object>) child;
                if (arrIdx < list.size()) {
                    Object av = list.get(arrIdx);
                    if (av instanceof String) { list.set(arrIdx, (String)av + payload); return true; }
                    else if (av instanceof Number) { list.set(arrIdx, av.toString() + payload); return true; }
                }
                return false;
            }
            return traverse(child, segs, idx + 1, payload);
        } else if (node instanceof List) {
            int ai = Integer.parseInt(seg.replaceAll("[\\[\\]]", ""));
            List<Object> list = (List<Object>) node;
            if (ai >= list.size()) return false;
            if (last) {
                Object v = list.get(ai);
                if (v instanceof String) { list.set(ai, (String)v + payload); return true; }
                else if (v instanceof Number) { list.set(ai, v.toString() + payload); return true; }
                return false;
            }
            return traverse(list.get(ai), segs, idx + 1, payload);
        }
        return false;
    }

    private ByteArray rebuildRequest(String url, byte[] newBody) {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(' ').append(url).append(" HTTP/1.1\r\n");
        boolean hasCL = false;
        for (HttpHeader h : headers) {
            if (h.name.equalsIgnoreCase("content-length")) {
                sb.append("Content-Length: ").append(newBody != null ? newBody.length : 0).append("\r\n");
                hasCL = true;
            } else {
                sb.append(h.name).append(": ").append(h.value).append("\r\n");
            }
        }
        // Inject custom headers (e.g. Range: bytes=0-1000)
        for (var ch : customHeaders) {
            sb.append(ch.getKey()).append(": ").append(ch.getValue()).append("\r\n");
        }
        if (!hasCL && newBody != null && newBody.length > 0)
            sb.append("Content-Length: ").append(newBody.length).append("\r\n");
        sb.append("\r\n");
        if (newBody != null && newBody.length > 0)
            sb.append(new String(newBody, StandardCharsets.UTF_8));
        return byteArray(sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    private boolean isJsonBody() { return contentType.toLowerCase().contains("application/json"); }
    private boolean isForm() { return contentType.toLowerCase().contains("application/x-www-form-urlencoded") || body.length > 0; }

    private String replaceQueryParam(String query, String paramName, String newValue) {
        StringBuilder sb = new StringBuilder();
        for (String p : query.split("&")) {
            if (!sb.isEmpty()) sb.append('&');
            String[] kv = split(p);
            if (kv != null && JsonInParamParser.decode(kv[0]).equals(paramName))
                sb.append(kv[0]).append('=').append(newValue);
            else sb.append(p);
        }
        return sb.toString();
    }

    private byte[] replaceFormBodyParam(String paramName, String newValue) {
        String s = new String(body, StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder();
        for (String p : s.split("&")) {
            if (!sb.isEmpty()) sb.append('&');
            String[] kv = split(p);
            if (kv != null && JsonInParamParser.decode(kv[0]).equals(paramName))
                sb.append(kv[0]).append('=').append(newValue);
            else sb.append(p);
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private byte[] upsertFormBody(String key, String value) {
        String s = body != null && body.length > 0 ? new String(body, StandardCharsets.UTF_8).strip() : "";
        String result = upsertFormParam(s, key, value);
        return result.getBytes(StandardCharsets.UTF_8);
    }

    /** Upsert a single key=value into a query string: replace if key exists, append if not */
    private String upsertQueryParam(String query, String key, String value) {
        if (query == null || query.isEmpty()) return key + "=" + value;
        boolean found = false;
        StringBuilder sb = new StringBuilder();
        for (String p : query.split("&")) {
            if (!sb.isEmpty()) sb.append('&');
            String[] kv = split(p);
            if (kv != null && kv[0].equals(key)) {
                sb.append(key).append('=').append(value);
                found = true;
            } else {
                sb.append(p);
            }
        }
        if (!found) sb.append('&').append(key).append('=').append(value);
        return sb.toString();
    }

    /** Upsert a single key=value into a form body string */
    private String upsertFormParam(String body, String key, String value) {
        if (body == null || body.isEmpty()) return key + "=" + value;
        boolean found = false;
        StringBuilder sb = new StringBuilder();
        for (String p : body.split("&")) {
            if (!sb.isEmpty()) sb.append('&');
            String[] kv = split(p);
            if (kv != null && kv[0].equals(key)) {
                sb.append(key).append('=').append(value);
                found = true;
            } else {
                sb.append(p);
            }
        }
        if (!found) sb.append('&').append(key).append('=').append(value);
        return sb.toString();
    }

    /** Upsert multiple params into a form body string */
    private String upsertFormParams(String body, Map<String, String> params) {
        String result = body != null ? body : "";
        for (var e : params.entrySet()) {
            result = upsertFormParam(result, e.getKey(), e.getValue());
        }
        return result;
    }

    /** Upsert multiple params into a query string */
    private String upsertQueryParams(String query, Map<String, String> params) {
        String result = query != null ? query : "";
        for (var e : params.entrySet()) {
            result = upsertQueryParam(result, urlEncode(e.getKey()), customEncode(urlEncode(e.getValue())));
        }
        return result;
    }

    /** Upsert multiple params into a query string with strict encoding */
    private String upsertQueryParamsStrict(String query, Map<String, String> params) {
        String result = query != null ? query : "";
        for (var e : params.entrySet()) {
            result = upsertQueryParam(result, encodeStrict(e.getKey()), encodeStrict(e.getValue()));
        }
        return result;
    }

    // Getters
    public String getMethod() { return method; }
    public String getUrl() { return url; }
    public byte[] getBody() { return body; }
    public String getContentType() { return contentType; }
    public HttpService getHttpService() { return httpService; }
    public byte[] getOriginalBytes() { return originalBytes; }
    public HttpRequest getOriginalRequest() { return originalRequest; }
    public List<HttpHeader> getHeaders() { return headers; }
    public void setUrlEncodeChars(String chars) { this.urlEncodeChars = chars != null ? chars : ""; }
    public void setCustomHeaders(List<Map.Entry<String, String>> headers) { this.customHeaders = headers != null ? headers : Collections.emptyList(); }

    private static String[] split(String p) { int i = p.indexOf('='); return i<0?new String[]{p,""}:new String[]{p.substring(0,i),p.substring(i+1)}; }
    private static String urlEncode(String v) { return JsonInParamParser.encode(v); }

    /** Full URL encoding without un-encoding special chars — for order injection payloads */
    private static String encodeStrict(String v) {
        if (v == null) return null;
        try { return java.net.URLEncoder.encode(v, StandardCharsets.UTF_8).replace("+", "%20"); }
        catch (Exception e) { return v; }
    }

    /** Like buildOrderBatch but uses strict URL encoding for GET values (commas etc. stay encoded) */
    public HttpRequest buildOrderBatchStrict(Map<String, String> params) {
        if (params.isEmpty()) return originalRequest;
        if (isJsonBody()) {
            return buildOrderBatch(params); // JSON body not affected
        } else if (isForm()) {
            return buildOrderBatch(params); // form body not affected
        } else {
            String q = ParameterParser.getQuery(url);
            String nq = upsertQueryParamsStrict(q != null ? q : "", params);
            String nu = ParameterParser.stripQuery(url) + "?" + nq;
            return HttpRequest.httpRequest(httpService, rebuildRequest(nu, body));
        }
    }

    /** Order batch for JSON-in-param: mutate inner fields of a JSON-encoded outer param */
    public HttpRequest buildOrderBatchJsonInParam(Map<String,String> params, String outerKey, boolean jsonEncoded) {
        if (params.isEmpty()) return originalRequest;
        String q = ParameterParser.getQuery(url);
        String outerRaw = null;
        boolean foundInQuery = false;
        if (q != null) {
            for (String p : q.split("&")) {
                String[] kv = split(p);
                if (kv != null && JsonInParamParser.decode(kv[0]).equals(outerKey)) {
                    outerRaw = kv.length > 1 ? kv[1] : "";
                    foundInQuery = true;
                    break;
                }
            }
        }
        if (!foundInQuery && isForm() && body.length > 0) {
            String bs = new String(body, StandardCharsets.UTF_8);
            for (String p : bs.split("&")) {
                String[] kv = split(p);
                if (kv != null && JsonInParamParser.decode(kv[0]).equals(outerKey)) {
                    outerRaw = kv.length > 1 ? kv[1] : "";
                    break;
                }
            }
        }
        if (outerRaw == null) return originalRequest;
        String innerJson = jsonEncoded ? JsonInParamParser.decode(outerRaw) : outerRaw;
        try {
            Object root = SimpleJson.parse(innerJson);
            if (root == null) return originalRequest;
            for (var e : params.entrySet()) {
                replaceJsonField(root, e.getKey(), e.getValue());
            }
            String newInner = SimpleJson.toJson(root);
            if (jsonEncoded) newInner = JsonInParamParser.encode(newInner);
            if (foundInQuery) {
                String nq = replaceQueryParam(q, outerKey, newInner);
                String nu = ParameterParser.stripQuery(url) + "?" + nq;
                return HttpRequest.httpRequest(httpService, rebuildRequest(nu, body));
            } else {
                byte[] nb = replaceFormBodyParam(outerKey, newInner);
                return HttpRequest.httpRequest(httpService, rebuildRequest(url, nb));
            }
        } catch (Exception e) { return originalRequest; }
    }

    /** Strict-encoding variant for JSON-in-param order batch (GET only: fully encode outer value) */
    public HttpRequest buildOrderBatchStrictJsonInParam(Map<String,String> params, String outerKey, boolean jsonEncoded) {
        if (params.isEmpty()) return originalRequest;
        if (isForm()) return buildOrderBatchJsonInParam(params, outerKey, jsonEncoded);
        String q = ParameterParser.getQuery(url);
        if (q == null) return originalRequest;
        String outerRaw = null;
        for (String p : q.split("&")) {
            String[] kv = split(p);
            if (kv != null && JsonInParamParser.decode(kv[0]).equals(outerKey)) {
                outerRaw = kv.length > 1 ? kv[1] : "";
                break;
            }
        }
        if (outerRaw == null) return originalRequest;
        String innerJson = jsonEncoded ? JsonInParamParser.decode(outerRaw) : outerRaw;
        try {
            Object root = SimpleJson.parse(innerJson);
            if (root == null) return originalRequest;
            for (var e : params.entrySet()) {
                replaceJsonField(root, e.getKey(), e.getValue());
            }
            String newInner = SimpleJson.toJson(root);
            String newInnerEncoded = encodeStrict(newInner);
            String nq = replaceQueryParam(q, outerKey, newInnerEncoded);
            String nu = ParameterParser.stripQuery(url) + "?" + nq;
            return HttpRequest.httpRequest(httpService, rebuildRequest(nu, body));
        } catch (Exception e) { return originalRequest; }
    }

    /** Apply custom character-level URL encoding on top of standard encoding */
    private String customEncode(String value) {
        if (urlEncodeChars.isEmpty() || value == null) return value;
        StringBuilder sb = new StringBuilder(value.length() * 2);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (urlEncodeChars.indexOf(c) >= 0) {
                sb.append('%').append(String.format("%02X", (int)c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Replace a param value for order injection testing.
     * If the value is JSON, recursively replace all string leaf values.
     * Otherwise return the replacement directly.
     */
    public static String replaceOrderValue(String originalValue, String replacement) {
        if (originalValue == null) return replacement;
        String s = originalValue.strip();
        if ((s.startsWith("[") && s.endsWith("]")) || (s.startsWith("{") && s.endsWith("}"))) {
            try {
                Object root = SimpleJson.parse(s);
                if (root != null) {
                    replaceAllStrings(root, replacement);
                    return SimpleJson.toJson(root);
                }
            } catch (Exception ignored) {}
        }
        return replacement;
    }

    @SuppressWarnings("unchecked")
    private static void replaceAllStrings(Object node, String replacement) {
        if (node instanceof Map) {
            Map<String,Object> m = (Map<String,Object>) node;
            for (var entry : m.entrySet()) {
                if (entry.getValue() instanceof String) {
                    m.put(entry.getKey(), replacement);
                } else if (entry.getValue() instanceof Map || entry.getValue() instanceof List) {
                    replaceAllStrings(entry.getValue(), replacement);
                }
            }
        } else if (node instanceof List) {
            List<Object> list = (List<Object>) node;
            for (int i = 0; i < list.size(); i++) {
                Object item = list.get(i);
                if (item instanceof String) {
                    list.set(i, replacement);
                } else if (item instanceof Map || item instanceof List) {
                    replaceAllStrings(item, replacement);
                }
            }
        }
    }

    /** Replace a field's value in a JSON tree by field name (first match, shallow then deep) */
    @SuppressWarnings("unchecked")
    private static boolean replaceJsonField(Object node, String fieldName, String newValue) {
        if (node instanceof Map) {
            Map<String,Object> m = (Map<String,Object>) node;
            if (m.containsKey(fieldName)) {
                Object v = m.get(fieldName);
                if (v instanceof String || v instanceof Number) {
                    m.put(fieldName, newValue);
                    return true;
                }
            }
            for (Object child : m.values()) {
                if (child instanceof Map || child instanceof List) {
                    if (replaceJsonField(child, fieldName, newValue)) return true;
                }
            }
        } else if (node instanceof List) {
            for (Object item : (List<Object>) node) {
                if (item instanceof Map || item instanceof List) {
                    if (replaceJsonField(item, fieldName, newValue)) return true;
                }
            }
        }
        return false;
    }

    /** If value looks like JSON object/array, insert it raw; otherwise quote and escape it */
    private static String jsonValue(String v) {
        String s = v.strip();
        if ((s.startsWith("[") && s.endsWith("]")) || (s.startsWith("{") && s.endsWith("}"))) return s;
        return "\"" + SimpleJson.esc(v) + "\"";
    }

    public record HttpHeader(String name, String value) {}
}
