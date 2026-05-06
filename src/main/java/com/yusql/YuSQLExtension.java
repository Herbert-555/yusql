package com.yusql;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.yusql.config.YuSQLConfig;
import com.yusql.engine.ScanEngine;
import com.yusql.filter.FilterManager;
import com.yusql.monitor.MonitorHandler;
import com.yusql.monitor.ProxyMonitorHandler;
import com.yusql.ui.ContextMenuProvider;
import com.yusql.ui.YuSQLTab;

public class YuSQLExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.logging().logToOutput("============================================");
        api.logging().logToOutput("  YuSQL V5 - SQL Injection Assistant");
        api.logging().logToOutput("  Montoya API  build=2026-05-02-1500");
        api.logging().logToOutput("============================================");

        // Initialize config
        YuSQLConfig config = new YuSQLConfig();
        api.logging().logToOutput("[YuSQL] 配置目录: " + config.getConfigDir());
        api.logging().logToOutput("[YuSQL] 已加载报错正则: " + config.getErrorPatterns().size() + " 条");
        api.logging().logToOutput("[YuSQL] 已加载追加参数: " + config.getAppendParams().size() + " 条");

        // Initialize filter manager
        FilterManager filterManager = new FilterManager(config);

        // Initialize scan engine
        ScanEngine engine = new ScanEngine(api, config, filterManager);

        // Build UI
        YuSQLTab ui = new YuSQLTab(api, engine, config, filterManager);

        // Register suite tab
        api.userInterface().registerSuiteTab("YuSQL", ui);

        // Register context menu
        api.userInterface().registerContextMenuItemsProvider(
            new ContextMenuProvider(api, engine, filterManager));

        // Register HTTP handler for Repeater traffic monitoring
        api.logging().logToOutput("[YuSQL] 注册 HTTP handler...");
        api.http().registerHttpHandler(new MonitorHandler(api, engine, config, filterManager));

        // Register Proxy handler for Proxy traffic monitoring
        api.logging().logToOutput("[YuSQL] 注册 Proxy request handler...");
        api.proxy().registerRequestHandler(new ProxyMonitorHandler(api, engine, config, filterManager));

        api.logging().logToOutput("[YuSQL] 插件初始化完成");
    }
}
