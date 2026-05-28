package com.yusql.module;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.yusql.compare.*;
import com.yusql.model.*;
import com.yusql.mutate.RequestBuilder;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;

public class NumericInjectionModule {
    private final MontoyaApi api;
    private final ResponseComparator comparator;
    private final Normalizer normalizer;
    private final int lengthDiffAbs;
    private final Consumer<String> logCb;

    public NumericInjectionModule(MontoyaApi api, ResponseComparator comparator,
                                  Normalizer normalizer, int lengthDiffAbs,
                                  Consumer<String> logCb) {
        this.api = api;
        this.comparator = comparator;
        this.normalizer = normalizer;
        this.lengthDiffAbs = lengthDiffAbs;
        this.logCb = logCb;
    }

    private void log(String msg) {
        if (logCb != null) {
            try { logCb.accept(msg); } catch (Exception ignore) {}
        } else {
            api.logging().logToOutput(msg);
        }
    }

    /** Two-step numeric injection test: -0-0 (control) then -0+1 (injection). */
    public List<LogEntry> test(RequestBuilder builder, TestPoint tp, String parentMd5,
                                byte[] r0Request, byte[] r0Response, int r0Len) {
        List<LogEntry> results = new ArrayList<>();
        String origValue = tp.getParamValue();
        if (origValue == null || origValue.isEmpty()) return results;
        if (!origValue.strip().matches("\\d+")) return results;

        String paramLabel = tp.displayPath();
        String r0Body = extractBody(r0Response);
        String r0Normalized = normalizer.normalize(r0Body);
        String r0Hash = TextSimilarity.hash(r0Normalized);

        try {
            // Step 1: -0-0 control — should produce same result as R0 if math is evaluated
            LogEntry r1 = send(tp, builder, parentMd5, "-0-0", "NumC");
            results.add(r1);
            if (r1 == null) return results;

            String r1Body = extractBody(r1.getResponse());
            String r1Normalized = normalizer.normalize(r1Body);
            String r1Hash = TextSimilarity.hash(r1Normalized);

            // If control differs from R0, the param is not injectable (math not evaluated)
            if (!r1Hash.equals(r0Hash)) {
                r1.setColorLevel(0);
                return results;
            }

            // Step 2: -0+1 injection test — if differs from R0, injection confirmed
            LogEntry r2 = send(tp, builder, parentMd5, "-0+1", "NumInj");
            results.add(r2);
            if (r2 == null) return results;

            String r2Body = extractBody(r2.getResponse());
            String r2Normalized = normalizer.normalize(r2Body);
            String r2Hash = TextSimilarity.hash(r2Normalized);

            if (!r2Hash.equals(r0Hash)) {
                // Injection confirmed — mark both results yellow
                r1.setColorLevel(2);
                r1.setTestType("NumInj");
                r2.setColorLevel(2);
                r2.setTestType("NumInj");
            } else {
                // No injection
                r1.setColorLevel(0);
                r2.setColorLevel(0);
            }
        } catch (Exception e) {
            log("[错误] 数字型注入异常 " + paramLabel + ": " + e.getMessage());
        }
        return results;
    }

    private LogEntry send(TestPoint tp, RequestBuilder builder, String parentMd5,
                          String payload, String testType) {
        try {
            HttpRequest req = builder.build(tp, payload);
            long start = System.currentTimeMillis();
            HttpRequestResponse reqResp = api.http().sendRequest(req);
            HttpResponse resp = reqResp.response();
            int reqTime = (int)(System.currentTimeMillis() - start);
            byte[] reqBytes = req.toByteArray().getBytes();
            byte[] respBytes = resp.toByteArray().getBytes();
            String respBody = resp.bodyToString();
            int bodyLen = respBody.length();
            int statusCode = resp.statusCode();

            LogEntry entry = new LogEntry(tp.displayPath(), payload, "已发送",
                bodyLen, reqTime, String.valueOf(statusCode), testType,
                reqBytes, respBytes, builder.getOriginalBytes(), null, parentMd5, 0,
                builder.getHttpService().host(), builder.getHttpService().port(), builder.getHttpService().secure());
            return entry;
        } catch (Exception e) {
            log("[错误] 数字型注入 " + payload + " " + tp.displayPath() + ": " + e.getMessage());
            return null;
        }
    }

    private String extractBody(byte[] responseBytes) {
        if (responseBytes == null) return "";
        return extractBody(new String(responseBytes, StandardCharsets.UTF_8));
    }

    private String extractBody(String raw) {
        int idx = raw.indexOf("\r\n\r\n");
        return idx >= 0 ? raw.substring(idx + 4) : raw;
    }
}
