package com.yusql.monitor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import com.yusql.config.YuSQLConfig;
import com.yusql.engine.ScanEngine;
import com.yusql.filter.FilterManager;

public class MonitorHandler implements HttpHandler {
    private final MontoyaApi api;
    private final ScanEngine engine;
    private final YuSQLConfig config;
    private final FilterManager filterManager;

    public MonitorHandler(MontoyaApi api, ScanEngine engine, YuSQLConfig config, FilterManager filterManager) {
        this.api = api;
        this.engine = engine;
        this.config = config;
        this.filterManager = filterManager;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        try {
            if (!requestToBeSent.toolSource().isFromTool(ToolType.REPEATER)) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            api.logging().logToOutput(
                "[YuSQL][Repeater] enter url=" + safeUrl(requestToBeSent)
            );

            if (!config.isMonitorRepeater()) {
                api.logging().logToOutput("[YuSQL][Repeater] skip: monitorRepeater=false");
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            if (!engine.isRunning()) {
                api.logging().logToOutput("[YuSQL][Repeater] skip: engine not running");
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            byte[] reqBytes = requestToBeSent.toByteArray().getBytes();
            String url = requestToBeSent.url();
            String filterReason = filterManager.checkRequest(url);
            if (filterReason != null) {
                api.logging().logToOutput("[YuSQL][Repeater] skip filter: " + filterReason + " url=" + url);
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            api.logging().logToOutput("[YuSQL][Repeater] matched, submit scan: " + url);

            engine.enqueue(reqBytes, requestToBeSent.httpService(), "Repeater");

            return RequestToBeSentAction.continueWith(requestToBeSent);
        } catch (Throwable e) {
            api.logging().logToError("[YuSQL][Repeater] handler error: " + e);
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private static String safeUrl(HttpRequestToBeSent r) {
        try { return r.url(); } catch (Exception e) { return "?"; }
    }
}
