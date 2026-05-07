package com.yusql.module;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.yusql.compare.Normalizer;
import com.yusql.model.*;
import com.yusql.mutate.RequestBuilder;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;

public class OrderInjectionModule {
    private final MontoyaApi api;
    private final Normalizer normalizer;
    private final Set<String> orderInjectionParams;
    private final Consumer<String> logCb;

    public OrderInjectionModule(MontoyaApi api, Normalizer normalizer,
                                 Set<String> orderInjectionParams,
                                 Consumer<String> logCb) {
        this.api = api;
        this.normalizer = normalizer;
        this.orderInjectionParams = orderInjectionParams != null ? orderInjectionParams : new LinkedHashSet<>();
        this.logCb = logCb;
    }

    private void log(String msg) {
        if (logCb != null) {
            try { logCb.accept(msg); } catch (Exception ignore) {}
        } else {
            api.logging().logToOutput(msg);
        }
    }

    /**
     * Test a single parameter that already exists in the original request.
     * Only this param's value is changed; all other original params stay intact.
     */
    public List<LogEntry> testSingle(RequestBuilder builder, String parentMd5,
                                      byte[] r0Response, String key, String value) {
        Map<String,String> single = new LinkedHashMap<>();
        single.put(key, value);
        return testGroup(builder, parentMd5, r0Response, single, key + "(排序注入)");
    }

    /** Test a JSON-in-param inner field for order injection. */
    public List<LogEntry> testSingleJsonInParam(RequestBuilder builder, String parentMd5,
                                                  byte[] r0Response, String outerKey,
                                                  String innerKey, String value, boolean jsonEncoded) {
        Map<String,String> single = new LinkedHashMap<>();
        single.put(innerKey, value);
        return testGroupJsonInParam(builder, parentMd5, r0Response, single,
            innerKey + "(排序注入)", outerKey, jsonEncoded);
    }

    /** Group params and run order injection test on each group. */
    public List<LogEntry> testAll(RequestBuilder builder, String parentMd5,
                                   byte[] r0Request, byte[] r0Response, int r0Len,
                                   List<Map.Entry<String,String>> appendParams,
                                   Map<String,Integer> paramGroups) {
        List<LogEntry> results = new ArrayList<>();
        if (appendParams == null || appendParams.isEmpty()) return results;

        // Simple grouping (first value per key per group)
        Map<Integer, Map<String,String>> groups = new LinkedHashMap<>();
        for (var e : appendParams) {
            int group = paramGroups.getOrDefault(e.getKey(), 0);
            Map<String,String> bundle = groups.computeIfAbsent(group, k -> new LinkedHashMap<>());
            if (!bundle.containsKey(e.getKey())) {
                bundle.put(e.getKey(), e.getValue());
            }
        }

        for (var groupEntry : groups.entrySet()) {
            results.addAll(testGroup(builder, parentMd5, r0Response, groupEntry.getValue(),
                "排序注入(组" + groupEntry.getKey() + ")"));
        }
        return results;
    }

    // =========================================================================
    // Main 5-step flow
    // =========================================================================

    private List<LogEntry> testGroup(RequestBuilder builder, String parentMd5,
                                      byte[] r0Response, Map<String,String> groupParams,
                                      String paramLabel) {
        return testGroupJsonInParam(builder, parentMd5, r0Response, groupParams, paramLabel, null, false);
    }

    private List<LogEntry> testGroupJsonInParam(RequestBuilder builder, String parentMd5,
                                                  byte[] r0Response, Map<String,String> groupParams,
                                                  String paramLabel,
                                                  String jsonOuterKey, boolean jsonEncoded) {
        List<LogEntry> allEntries = new ArrayList<>();

        // Check OI params
        Set<String> oiParamNames = new LinkedHashSet<>();
        for (String key : groupParams.keySet()) {
            if (orderInjectionParams.isEmpty() || orderInjectionParams.contains(key)) {
                oiParamNames.add(key);
            }
        }
        if (oiParamNames.isEmpty()) {
            return allEntries;
        }

        String r0Body = extractBody(new String(r0Response, StandardCharsets.UTF_8));

        // --- R1: append with _aaa suffix to ensure column doesn't exist (triggers error) ---
        Map<String,String> r1Params = new LinkedHashMap<>();
        for (var e : groupParams.entrySet()) {
            r1Params.put(e.getKey(), e.getValue() + "_aaa");
        }
        LogEntry r1 = sendStep(builder, r1Params, "R1(基线)", paramLabel, parentMd5, jsonOuterKey, jsonEncoded);
        if (r1 == null) return allEntries;
        allEntries.add(r1);
        String r1Body = extractBody(new String(r1.getResponse(), StandardCharsets.UTF_8));

        // R0 vs R1 normalized
        if (normalizedEq(r0Body, r1Body, oiParamNames, groupParams.keySet())) {
            log("[排序] " + paramLabel + " R0=R1 → 不存在排序注入");
            return allEntries;
        }

        // --- R2: values → 1 ---
        Map<String,String> r2Params = buildReplacedParams(groupParams, oiParamNames, "1");
        LogEntry r2 = sendStepStrict(builder, r2Params, "R2(→1)", paramLabel, parentMd5, jsonOuterKey, jsonEncoded);
        if (r2 == null) return allEntries;
        allEntries.add(r2);
        String r2Body = extractBody(new String(r2.getResponse(), StandardCharsets.UTF_8));

        // R2 vs R1 normalized (clean: paramNames + ["1"])
        if (normalizedEq(r2Body, r1Body, oiParamNames, null, "1")) {
            log("[排序] " + paramLabel + " R2=R1 → 不存在排序注入");
            return allEntries;
        }

        // --- R3: values → 1,aaa ---
        Map<String,String> r3Params = buildReplacedParams(groupParams, oiParamNames, "1,aaa");
        LogEntry r3 = sendStepStrict(builder, r3Params, "R3(→1,aaa)", paramLabel, parentMd5, jsonOuterKey, jsonEncoded);
        if (r3 == null) return allEntries;
        allEntries.add(r3);
        String r3Body = extractBody(new String(r3.getResponse(), StandardCharsets.UTF_8));

        // R3 vs R2 normalized (clean: paramNames + ["1", "1,aaa"])
        if (normalizedEq(r3Body, r2Body, oiParamNames, null, "1", "1,aaa")) {
            log("[排序] " + paramLabel + " R3=R2 → 不存在排序注入");
            return allEntries;
        }

        // --- R4: values → 1,current_timestamp ---
        Map<String,String> r4Params = buildReplacedParams(groupParams, oiParamNames, "1,current_timestamp");
        LogEntry r4 = sendStepStrict(builder, r4Params, "R4(→1,current_timestamp)", paramLabel, parentMd5, jsonOuterKey, jsonEncoded);
        if (r4 == null) return allEntries;
        allEntries.add(r4);
        String r4Body = extractBody(new String(r4.getResponse(), StandardCharsets.UTF_8));

        // R4 vs R2 (clean: paramNames + ["1", "1,current_timestamp"])
        boolean r4Hit = normalizedEq(r4Body, r2Body, oiParamNames, null, "1", "1,current_timestamp");

        // --- Step 4: check for regular hit ---
        if (r4Hit) {
            log("[排序] ★ " + paramLabel + " 排序注入成立 (常规命中): R4==R2");
            markAllOrderInj(allEntries, "排序注入:常规命中", oiParamNames);
            return allEntries;
        }

        // --- Check for comma filtering fallback ---
        boolean r4NeedFallback = normalizedEq(r4Body, r3Body, oiParamNames, null, "1,aaa", "1,current_timestamp");

        if (!r4NeedFallback) {
            log("[排序] " + paramLabel + " R4≠R2且R4≠R3 → 不存在排序注入");
            return allEntries;
        }

        // --- Step 5A: comma bypass ---
        log("[排序] " + paramLabel + " R4==R3，疑似逗号过滤 → 进入兜底检测");

        // R5: values → current_timestamp
        Map<String,String> r5Params = buildReplacedParams(groupParams, oiParamNames, "current_timestamp");
        LogEntry r5 = sendStepStrict(builder, r5Params, "R5(→current_timestamp)", paramLabel, parentMd5, jsonOuterKey, jsonEncoded);
        if (r5 == null) return allEntries;
        allEntries.add(r5);
        String r5Body = extractBody(new String(r5.getResponse(), StandardCharsets.UTF_8));

        if (!normalizedEq(r5Body, r2Body, oiParamNames, null, "1", "current_timestamp")) {
            log("[排序] " + paramLabel + " R5≠R2 → 不存在排序注入");
            return allEntries;
        }

        // --- Step 5B: aaa counter-test ---
        Map<String,String> r6Params = buildReplacedParams(groupParams, oiParamNames, "aaa");
        LogEntry r6 = sendStepStrict(builder, r6Params, "R6(→aaa)", paramLabel, parentMd5, jsonOuterKey, jsonEncoded);
        if (r6 == null) return allEntries;
        allEntries.add(r6);
        String r6Body = extractBody(new String(r6.getResponse(), StandardCharsets.UTF_8));

        boolean r6neR2 = !normalizedEq(r6Body, r2Body, oiParamNames, null, "1", "aaa");
        boolean r6neR5 = !normalizedEq(r6Body, r5Body, oiParamNames, null, "current_timestamp", "aaa");

        if (r6neR2 && r6neR5) {
            log("[排序] ★ " + paramLabel + " 排序注入成立 (逗号过滤兜底)");
            markAllOrderInj(allEntries, "排序注入:逗号过滤兜底", oiParamNames);
            return allEntries;
        }

        log("[排序] " + paramLabel + " R6未通过反证 → 不存在排序注入");
        return allEntries;
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private Map<String,String> buildReplacedParams(Map<String,String> original,
                                                    Set<String> oiNames, String replacement) {
        Map<String,String> result = new LinkedHashMap<>();
        for (var e : original.entrySet()) {
            if (oiNames.contains(e.getKey())) {
                result.put(e.getKey(), RequestBuilder.replaceOrderValue(e.getValue(), replacement));
            } else {
                result.put(e.getKey(), e.getValue());
            }
        }
        return result;
    }

    private LogEntry sendStep(RequestBuilder builder, Map<String,String> params,
                               String stepName, String paramLabel, String parentMd5,
                               String jsonOuterKey, boolean jsonEncoded) {
        return send(builder, params, stepName, paramLabel, parentMd5, false, jsonOuterKey, jsonEncoded);
    }

    private LogEntry sendStepStrict(RequestBuilder builder, Map<String,String> params,
                                     String stepName, String paramLabel, String parentMd5,
                                     String jsonOuterKey, boolean jsonEncoded) {
        return send(builder, params, stepName, paramLabel, parentMd5, true, jsonOuterKey, jsonEncoded);
    }

    private LogEntry send(RequestBuilder builder, Map<String,String> params,
                           String stepName, String paramLabel, String parentMd5, boolean strict,
                           String jsonOuterKey, boolean jsonEncoded) {
        try {
            HttpRequest req;
            if (jsonOuterKey != null) {
                req = strict
                    ? builder.buildOrderBatchStrictJsonInParam(params, jsonOuterKey, jsonEncoded)
                    : builder.buildOrderBatchJsonInParam(params, jsonOuterKey, jsonEncoded);
            } else {
                req = strict ? builder.buildOrderBatchStrict(params) : builder.buildOrderBatch(params);
            }
            long start = System.currentTimeMillis();
            HttpRequestResponse reqResp = api.http().sendRequest(req);
            HttpResponse resp = reqResp.response();
            int reqTime = (int)(System.currentTimeMillis() - start);
            byte[] reqBytes = req.toByteArray().getBytes();
            byte[] respBytes = resp.toByteArray().getBytes();
            String respBody = resp.bodyToString();
            int bodyLen = respBody.length();
            int statusCode = resp.statusCode();

            log("[排序] " + paramLabel + "-" + stepName +
                " → 长度" + bodyLen + " 用时" + reqTime + "ms 状态码" + statusCode);

            LogEntry entry = new LogEntry(paramLabel, stepName, stepName + "已发送",
                bodyLen, reqTime, String.valueOf(statusCode), "",
                reqBytes, respBytes, builder.getOriginalBytes(), null, parentMd5, 0,
                builder.getHttpService().host(), builder.getHttpService().port(), builder.getHttpService().secure());
            entry.setColorLevel(0);
            return entry;
        } catch (Exception e) {
            log("[错误] 排序注入 " + paramLabel + "-" + stepName + ": " + e.getMessage());
            return null;
        }
    }

    // =========================================================================
    // Normalized comparison
    // =========================================================================

    /** Normalize both bodies by removing param names and payload values, then compare. */
    private boolean normalizedEq(String bodyA, String bodyB, Set<String> oiNames,
                                  Set<String> extraKeys, String... payloadValues) {
        Set<String> keywords = new LinkedHashSet<>();
        keywords.addAll(oiNames);
        if (extraKeys != null) keywords.addAll(extraKeys);
        if (payloadValues != null) for (String v : payloadValues) keywords.add(v);

        String a = clean(bodyA, keywords);
        String b = clean(bodyB, keywords);
        return normalizer.normalize(a).equals(normalizer.normalize(b));
    }

    /** Remove all occurrences of each keyword from body. */
    private String clean(String body, Set<String> keywords) {
        if (body == null) return "";
        String result = body;
        for (String kw : keywords) {
            if (kw != null && !kw.isEmpty()) {
                result = result.replace(kw, "");
            }
        }
        return result;
    }

    private void markAllOrderInj(List<LogEntry> entries, String change, Set<String> oiNames) {
        String paramNames = String.join(",", oiNames);
        for (LogEntry entry : entries) {
            entry.setColorLevel(2);
            entry.setTestType("排序注入");
            entry.setChange(change + " 参数:" + paramNames);
        }
    }

    private static String extractBody(String rawHttp) {
        if (rawHttp == null) return "";
        int idx = rawHttp.indexOf("\r\n\r\n");
        return idx >= 0 ? rawHttp.substring(idx + 4) : rawHttp;
    }
}
