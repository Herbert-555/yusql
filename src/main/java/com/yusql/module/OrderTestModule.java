package com.yusql.module;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.yusql.compare.*;
import com.yusql.model.*;
import com.yusql.mutate.RequestBuilder;

import java.util.*;

public class OrderTestModule {
    private final MontoyaApi api;
    private final ResponseComparator comparator;
    private final List<Map.Entry<String,String>> appendParams;
    private final Map<String,Integer> paramGroups;
    private final int lengthDiffAbs;
    private final Normalizer normalizer;

    public OrderTestModule(MontoyaApi api, ResponseComparator comparator,
                           List<Map.Entry<String,String>> appendParams, Map<String,Integer> paramGroups,
                           int lengthDiffAbs, Normalizer normalizer) {
        this.api = api;
        this.comparator = comparator;
        this.appendParams = appendParams != null ? appendParams : new ArrayList<>();
        this.paramGroups = paramGroups != null ? paramGroups : new LinkedHashMap<>();
        this.lengthDiffAbs = lengthDiffAbs;
        this.normalizer = normalizer;
    }

    /** Group params by group number, send each group bundled together via buildOrderBatch.
     *  Within each group: dedup identical key:value pairs, and for keys with multiple
     *  values send the first in the bundle and each subsequent value as a separate request. */
    public List<LogEntry> test(RequestBuilder builder, String parentMd5,
                                byte[] r0Request, byte[] r0Response, int r0Len) {
        List<LogEntry> results = new ArrayList<>();
        if (appendParams.isEmpty()) {
            api.logging().logToOutput("[追加] 无追加参数配置，跳过");
            return results;
        }

        // Group params: first-value-per-key → bundle; subsequent different values → separate
        // Track exact duplicates to skip them
        Map<Integer, Map<String,String>> groupBundles = new LinkedHashMap<>();
        Map<Integer, List<Map.Entry<String,String>>> groupOverflows = new LinkedHashMap<>();
        Set<String> seenKeyValues = new HashSet<>();

        for (var e : appendParams) {
            int group = paramGroups.getOrDefault(e.getKey(), 0);
            String kv = e.getKey() + "=" + e.getValue();
            if (!seenKeyValues.add(kv)) continue; // exact duplicate, skip

            Map<String,String> bundle = groupBundles.computeIfAbsent(group, k -> new LinkedHashMap<>());
            if (bundle.containsKey(e.getKey())) {
                // Same key, different value → overflow
                groupOverflows.computeIfAbsent(group, k -> new ArrayList<>())
                    .add(new AbstractMap.SimpleEntry<>(e.getKey(), e.getValue()));
            } else {
                bundle.put(e.getKey(), e.getValue());
            }
        }

        // Send each group's bundle + overflows
        for (var groupEntry : groupBundles.entrySet()) {
            int groupNum = groupEntry.getKey();
            Map<String,String> batch = groupEntry.getValue();

            // Send bundle
            if (!batch.isEmpty()) {
                List<String> names = new ArrayList<>(batch.keySet());
                String paramLabel = "追加(组" + groupNum + "):" + String.join(",", names);
                String payload = buildBundledPayload(batch);
                LogEntry entry = sendGroup(builder, batch, paramLabel, payload, r0Len,
                    r0Request, r0Response, parentMd5);
                if (entry != null) results.add(entry);
            }

            // Send overflows (each as a single-param bundle)
            List<Map.Entry<String,String>> overflows = groupOverflows.getOrDefault(groupNum, Collections.emptyList());
            for (var ov : overflows) {
                Map<String,String> single = new LinkedHashMap<>();
                single.put(ov.getKey(), ov.getValue());
                String paramLabel = "追加(组" + groupNum + "溢出):" + ov.getKey();
                String payload = ov.getKey() + ":" + ov.getValue();
                LogEntry entry = sendGroup(builder, single, paramLabel, payload, r0Len,
                    r0Request, r0Response, parentMd5);
                if (entry != null) results.add(entry);
            }
        }

        return results;
    }

    private LogEntry sendGroup(RequestBuilder builder, Map<String,String> batch,
                                String paramLabel, String payload, int r0Len,
                                byte[] r0Request, byte[] r0Response, String parentMd5) {
        try {
            HttpRequest req = builder.buildOrderBatch(batch);
            long start = System.currentTimeMillis();
            HttpRequestResponse reqResp = api.http().sendRequest(req);
            HttpResponse resp = reqResp.response();
            int reqTime = (int)(System.currentTimeMillis() - start);
            byte[] reqBytes = req.toByteArray().getBytes();
            byte[] respBytes = resp.toByteArray().getBytes();
            String respBody = resp.bodyToString();
            int bodyLen = respBody.length();
            int statusCode = resp.statusCode();

            return analyzeAndBuildEntry(paramLabel, payload, respBody, bodyLen, reqTime,
                String.valueOf(statusCode), r0Len, reqBytes, respBytes,
                r0Request, r0Response, parentMd5, builder);
        } catch (Exception e) {
            api.logging().logToError("[错误] 追加 " + paramLabel + ": " + e.getMessage());
            return null;
        }
    }

    private LogEntry analyzeAndBuildEntry(String paramLabel, String payload,
                                           String respBody, int bodyLen, int reqTime, String statusCode,
                                           int r0Len, byte[] reqBytes, byte[] respBytes,
                                           byte[] r0Request, byte[] r0Response, String parentMd5,
                                           RequestBuilder builder) {
        // 1. Check SQL error regex FIRST
        if (comparator.hasErrorHit(respBody)) {
            List<String[]> hits = comparator.matchErrors(respBody);
            String hitRegex = hits.isEmpty() ? "" : hits.get(0)[0];
            api.logging().logToOutput("[追加] " + paramLabel +
                " payload=" + truncate(payload) +
                " → 报错命中: " + hitRegex +
                " 长度" + bodyLen +
                " 用时" + reqTime + "ms" +
                " 状态码" + statusCode);

            LogEntry entry = new LogEntry(paramLabel, payload,
                "报错命中", bodyLen, reqTime, statusCode, "Err",
                reqBytes, respBytes, r0Request, r0Response, parentMd5, 0,
                builder.getHttpService().host(), builder.getHttpService().port(), builder.getHttpService().secure());
            entry.setColorLevel(3);
            return entry;
        }

        // 2. Check length diff
        int lenDiff = Math.abs(bodyLen - r0Len);
        if (lenDiff > lengthDiffAbs) {
            String change = "长度" + (bodyLen > r0Len ? "+" : "") + (bodyLen - r0Len);
            api.logging().logToOutput("[追加] " + paramLabel +
                " payload=" + truncate(payload) +
                " → " + change +
                " 长度" + bodyLen +
                " 用时" + reqTime + "ms" +
                " 状态码" + statusCode);

            LogEntry entry = new LogEntry(paramLabel, payload, change,
                bodyLen, reqTime, statusCode, "Len",
                reqBytes, respBytes, r0Request, r0Response, parentMd5, 0,
                builder.getHttpService().host(), builder.getHttpService().port(), builder.getHttpService().secure());
            entry.setColorLevel(1);
            return entry;
        }

        // 3. No change
        api.logging().logToOutput("[追加] " + paramLabel +
            " payload=" + truncate(payload) +
            " → 无变化" +
            " 长度" + bodyLen +
            " 用时" + reqTime + "ms" +
            " 状态码" + statusCode);

        LogEntry entry = new LogEntry(paramLabel, payload, "无变化",
            bodyLen, reqTime, statusCode, "",
            reqBytes, respBytes, r0Request, r0Response, parentMd5, 0,
            builder.getHttpService().host(), builder.getHttpService().port(), builder.getHttpService().secure());
        entry.setColorLevel(0);
        return entry;
    }

    private String buildBundledPayload(Map<String,String> params) {
        StringBuilder sb = new StringBuilder();
        for (var e : params.entrySet()) {
            if (!sb.isEmpty()) sb.append('&');
            sb.append(e.getKey()).append('=').append(e.getValue());
        }
        return sb.toString();
    }

    private static String truncate(String s) {
        if (s == null) return "";
        return s.length() > 50 ? s.substring(0, 47) + "..." : s;
    }
}
