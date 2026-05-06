package com.yusql.monitor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import com.yusql.config.YuSQLConfig;
import com.yusql.engine.ScanEngine;
import com.yusql.filter.FilterManager;

public class ProxyMonitorHandler implements ProxyRequestHandler {
    private final MontoyaApi api;
    private final ScanEngine engine;
    private final YuSQLConfig config;
    private final FilterManager filterManager;

    public ProxyMonitorHandler(MontoyaApi api, ScanEngine engine, YuSQLConfig config, FilterManager filterManager) {
        this.api = api;
        this.engine = engine;
        this.config = config;
        this.filterManager = filterManager;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        try {
            api.logging().logToOutput("[YuSQL][Proxy] enter url=" + safeUrl(interceptedRequest));

            if (!config.isMonitorProxy()) {
                api.logging().logToOutput("[YuSQL][Proxy] skip: monitorProxy=false");
                return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
            }

            if (!engine.isRunning()) {
                api.logging().logToOutput("[YuSQL][Proxy] skip: engine not running");
                return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
            }

            byte[] reqBytes = interceptedRequest.toByteArray().getBytes();
            String url = interceptedRequest.url();
            String filterReason = filterManager.checkRequest(url);
            if (filterReason != null) {
                api.logging().logToOutput("[YuSQL][Proxy] skip filter: " + filterReason + " url=" + url);
                return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
            }

            api.logging().logToOutput("[YuSQL][Proxy] matched, submit scan: " + url);

            engine.enqueue(reqBytes, interceptedRequest.httpService(), "Proxy");

            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        } catch (Throwable e) {
            api.logging().logToError("[YuSQL][Proxy] handler error: " + e);
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }
    }

    private static String safeUrl(InterceptedRequest r) {
        try { return r.url(); } catch (Exception e) { return "?"; }
    }
}
