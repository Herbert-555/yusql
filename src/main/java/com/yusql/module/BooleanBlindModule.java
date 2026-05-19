package com.yusql.module;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.yusql.compare.*;
import com.yusql.model.*;
import com.yusql.mutate.RequestBuilder;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;

public class BooleanBlindModule {
    private final MontoyaApi api;
    private final ResponseComparator comparator;
    private final Normalizer normalizer;
    private final int lengthDiffAbs;
    private final Consumer<String> logCb;

    public BooleanBlindModule(MontoyaApi api, ResponseComparator comparator,
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

    /** Execute V5 short-circuit boolean blind flow. Returns list of LogEntry results. */
    public List<LogEntry> test(RequestBuilder builder, TestPoint tp, String parentMd5,
                                byte[] r0Request, byte[] r0Response, int r0Len) {
        List<LogEntry> results = new ArrayList<>();
        String paramLabel = tp.displayPath();
        try {
            // Extract body from full HTTP response for normalization comparison
            String r0Raw = r0Response != null ? new String(r0Response, StandardCharsets.UTF_8) : "";
            String r0Body = extractBody(r0Raw);
            String r0Normalized = normalizer.normalize(r0Body);

            // Step 1: Send R1 (1 single quote = ')
            LogEntry r1Entry = sendAndAnalyze("'", "R1", builder, tp, parentMd5, r0Len);
            results.add(r1Entry);
            if (r1Entry == null) {
                return results;
            }

            // Check if R1 vs R0 has change
            String r1Body = extractBody(new String(r1Entry.getResponse(), StandardCharsets.UTF_8));
            String r1Normalized = normalizer.normalize(r1Body);
            boolean r1Changed = !r1Normalized.equals(r0Normalized);

            // If R1 has NO change vs R0, stop
            if (!r1Changed) {
                finalizeEntryColor(r1Entry);
                return results;
            }

            // Step 2: R1 has change, send R3 (3 single quotes = ''')
            LogEntry r3Entry = sendAndAnalyze("'''", "R3", builder, tp, parentMd5, r0Len);
            results.add(r3Entry);
            if (r3Entry == null) {
                return results;
            }

            // Check R1 vs R3
            String r3Body = extractBody(new String(r3Entry.getResponse(), StandardCharsets.UTF_8));
            String r3Normalized = normalizer.normalize(r3Body);
            boolean r1SameR3 = r1Normalized.equals(r3Normalized);

            // If R1 != R3, stop
            if (!r1SameR3) {
                finalizeEntryColor(r1Entry);
                finalizeEntryColor(r3Entry);
                return results;
            }

            // Step 3: R1==R3, send R2 (2 single quotes = '')
            LogEntry r2Entry = sendAndAnalyze("''", "R2", builder, tp, parentMd5, r0Len);
            results.add(r2Entry);
            if (r2Entry == null) {
                return results;
            }

            // Check R2 vs R1/R3
            String r2Body = extractBody(new String(r2Entry.getResponse(), StandardCharsets.UTF_8));
            String r2Normalized = normalizer.normalize(r2Body);
            boolean r2DifferentFromR1 = !r2Normalized.equals(r1Normalized);

            if (r2DifferentFromR1) {
                updateBoolResults(results, r1Entry, r3Entry, r2Entry, r0Len);
            } else {
                finalizeEntryColor(r1Entry);
                finalizeEntryColor(r3Entry);
                finalizeEntryColor(r2Entry);
            }
        } catch (Exception e) {
            log("[错误] 布尔注入 " + paramLabel + ": " + e.getMessage());
        }
        return results;
    }

    /** Send a single boolean test request and return a LogEntry with analysis */
    private LogEntry sendAndAnalyze(String payload, String stepName, RequestBuilder builder,
                                     TestPoint tp, String parentMd5, int r0Len) {
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

            // Check error regex FIRST
            boolean hasError = comparator.hasErrorHit(respBody);
            // Check length diff
            int lenDiff = Math.abs(bodyLen - r0Len);
            boolean hasLenDiff = lenDiff > lengthDiffAbs;

            String change;
            String testType;
            int colorLevel;

            if (hasError) {
                change = "报错命中";
                testType = "Err";
                colorLevel = 3;
            } else if (hasLenDiff) {
                change = "长度" + (bodyLen > r0Len ? "+" : "") + (bodyLen - r0Len);
                testType = "Len";
                colorLevel = 1;
            } else {
                change = stepName + "已发送";
                testType = "";
                colorLevel = 0;
            }

            LogEntry entry = new LogEntry(tp.displayPath(), payload, change,
                bodyLen, reqTime, String.valueOf(statusCode), testType,
                reqBytes, respBytes, builder.getOriginalBytes(), null, parentMd5, 0,
                builder.getHttpService().host(), builder.getHttpService().port(), builder.getHttpService().secure());
            entry.setColorLevel(colorLevel);
            return entry;
        } catch (Exception e) {
            log("[错误] 布尔注入 " + stepName + " " + tp.displayPath() + ": " + e.getMessage());
            return null;
        }
    }

    /** After boolean confirmed: update all entries to YELLOW/Bool status.
     *  But if an entry already has Err (colorLevel=3), keep RED and set testType="Err,Bool" */
    private void updateBoolResults(List<LogEntry> results, LogEntry r1, LogEntry r3, LogEntry r2, int r0Len) {
        for (LogEntry entry : results) {
            if (entry.getColorLevel() >= 3) {
                entry.setTestType("Err,Bool");
            } else {
                entry.setColorLevel(2);
                entry.setTestType("Bool");
                entry.setChange("Bool:R1=R3/R2≠R1");
            }
        }
    }

    /** For non-boolean result: keep color as set during sendAndAnalyze */
    private void finalizeEntryColor(LogEntry entry) {
        // Color already set during sendAndAnalyze
    }

    /** Extract body from full HTTP response bytes (skip status line + headers) */
    private static String extractBody(String rawHttp) {
        if (rawHttp == null) return "";
        int idx = rawHttp.indexOf("\r\n\r\n");
        return idx >= 0 ? rawHttp.substring(idx + 4) : rawHttp;
    }
}
