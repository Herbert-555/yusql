package com.yusql.module;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.yusql.compare.*;
import com.yusql.model.*;
import com.yusql.mutate.RequestBuilder;

import java.util.*;
import java.util.function.Consumer;

public class ErrorInjectionModule {
    private final MontoyaApi api;
    private final ResponseComparator comparator;
    private final List<String> errorPocs;
    private final int lengthDiffAbs;
    private final Normalizer normalizer;
    private final Consumer<String> logCb;

    public ErrorInjectionModule(MontoyaApi api, ResponseComparator comparator,
                                List<String> errorPocs, int lengthDiffAbs, Normalizer normalizer,
                                Consumer<String> logCb) {
        this.api = api;
        this.comparator = comparator;
        this.errorPocs = errorPocs != null ? errorPocs : new ArrayList<>();
        this.lengthDiffAbs = lengthDiffAbs;
        this.normalizer = normalizer;
        this.logCb = logCb;
    }

    private void log(String msg) {
        if (logCb != null) {
            try { logCb.accept(msg); } catch (Exception ignore) {}
        } else {
            api.logging().logToOutput(msg);
        }
    }

    /** Test a single test point with all custom error POCs. Returns list of LogEntry results. */
    public List<LogEntry> test(RequestBuilder builder, TestPoint tp, String parentMd5, int r0Length) {
        List<LogEntry> results = new ArrayList<>();
        if (errorPocs.isEmpty()) {
            return results;
        }

        String paramLabel = tp.displayPath();
        for (String poc : errorPocs) {
            try {
                HttpRequest req = builder.build(tp, poc);
                long start = System.currentTimeMillis();
                HttpRequestResponse reqResp = api.http().sendRequest(req);
                HttpResponse resp = reqResp.response();
                int reqTime = (int)(System.currentTimeMillis() - start);
                byte[] reqBytes = req.toByteArray().getBytes();
                byte[] respBytes = resp.toByteArray().getBytes();
                int statusCode = resp.statusCode();
                String respBody = resp.bodyToString();
                int bodyLen = respBody.length();

                // 1. Check SQL error regex
                List<String[]> errorHits = comparator.matchErrors(respBody);
                if (!errorHits.isEmpty()) {
                    LogEntry entry = new LogEntry(paramLabel, poc, "报错命中",
                        bodyLen, reqTime, String.valueOf(statusCode), "Err",
                        reqBytes, respBytes, builder.getOriginalBytes(), null, parentMd5, 0,
                        builder.getHttpService().host(), builder.getHttpService().port(), builder.getHttpService().secure());
                    entry.setColorLevel(3);
                    results.add(entry);
                    continue;
                }

                // 2. Check length diff
                int lenDiff = Math.abs(bodyLen - r0Length);
                if (lenDiff > lengthDiffAbs) {
                    String change = "长度" + (bodyLen > r0Length ? "+" : "") + (bodyLen - r0Length);
                    LogEntry entry = new LogEntry(paramLabel, poc, change,
                        bodyLen, reqTime, String.valueOf(statusCode), "Len",
                        reqBytes, respBytes, builder.getOriginalBytes(), null, parentMd5, 0,
                        builder.getHttpService().host(), builder.getHttpService().port(), builder.getHttpService().secure());
                    entry.setColorLevel(1);
                    results.add(entry);
                } else {
                    LogEntry entry = new LogEntry(paramLabel, poc, "无变化",
                        bodyLen, reqTime, String.valueOf(statusCode), "",
                        reqBytes, respBytes, builder.getOriginalBytes(), null, parentMd5, 0,
                        builder.getHttpService().host(), builder.getHttpService().port(), builder.getHttpService().secure());
                    entry.setColorLevel(0);
                    results.add(entry);
                }
            } catch (Exception e) {
                log("[错误] 报错注入 " + paramLabel + " payload=" + poc + ": " + e.getMessage());
            }
        }
        return results;
    }

    private static String truncate(String s) {
        if (s == null) return "";
        return s.length() > 50 ? s.substring(0, 47) + "..." : s;
    }
}
