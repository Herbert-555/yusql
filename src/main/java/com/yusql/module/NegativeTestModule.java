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

public class NegativeTestModule {
    private final MontoyaApi api;
    private final ResponseComparator comparator;
    private final Normalizer normalizer;
    private final int lengthDiffAbs;
    private final Consumer<String> logCb;

    public NegativeTestModule(MontoyaApi api, ResponseComparator comparator,
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

    public List<LogEntry> test(RequestBuilder builder, TestPoint tp, String parentMd5,
                                byte[] r0Request, byte[] r0Response, int r0Len) {
        List<LogEntry> results = new ArrayList<>();
        String origValue = tp.getParamValue();
        if (origValue == null || origValue.isEmpty()) return results;

        String negated = negateIfNumeric(origValue);
        if (negated == null) return results;

        try {
            long start = System.currentTimeMillis();
            HttpRequest req = builder.buildReplace(tp, negated);
            HttpRequestResponse reqResp = api.http().sendRequest(req);
            HttpResponse resp = reqResp.response();
            int reqTime = (int)(System.currentTimeMillis() - start);
            byte[] reqBytes = req.toByteArray().getBytes();
            byte[] respBytes = resp.toByteArray().getBytes();
            String respBody = resp.bodyToString();
            int bodyLen = respBody.length();
            int statusCode = resp.statusCode();

            // Compare with R0
            String r0Body = extractBody(r0Response);
            String r0Normalized = normalizer.normalize(r0Body);
            String r1Normalized = normalizer.normalize(respBody);
            String r0Hash = TextSimilarity.hash(r0Normalized);
            String r1Hash = TextSimilarity.hash(r1Normalized);

            boolean hasChange = !r0Hash.equals(r1Hash);
            boolean hasError = comparator.hasErrorHit(respBody);
            int lenDiff = Math.abs(bodyLen - r0Len);

            if (hasChange || hasError || lenDiff > lengthDiffAbs) {
                String change;
                String testType;
                int colorLevel;
                if (hasError) {
                    change = "报错命中";
                    testType = "NegErr";
                    colorLevel = 3;
                } else if (lenDiff > lengthDiffAbs) {
                    change = "长度" + (bodyLen > r0Len ? "+" : "") + (bodyLen - r0Len);
                    testType = "NegLen";
                    colorLevel = 1;
                } else {
                    double sim = TextSimilarity.levenshteinRatio(r0Normalized, r1Normalized);
                    change = "相似度" + String.format("%.2f", sim);
                    testType = "Neg";
                    colorLevel = 1;
                }

                LogEntry entry = new LogEntry(tp.displayPath(), negated, change,
                    bodyLen, reqTime, String.valueOf(statusCode), testType,
                    reqBytes, respBytes, builder.getOriginalBytes(), null, parentMd5, 0,
                    builder.getHttpService().host(), builder.getHttpService().port(), builder.getHttpService().secure());
                entry.setColorLevel(colorLevel);
                results.add(entry);
            }
        } catch (Exception e) {
            log("[错误] 负数测试异常 " + tp.displayPath() + ": " + e.getMessage());
        }
        return results;
    }

    static String negateIfNumeric(String value) {
        if (value == null || value.isEmpty()) return null;
        String s = value.strip();
        boolean isNeg = s.startsWith("-");
        if (isNeg) s = s.substring(1);
        if (!s.matches("\\d+")) return null;
        return isNeg ? s : "-" + value.strip();
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
