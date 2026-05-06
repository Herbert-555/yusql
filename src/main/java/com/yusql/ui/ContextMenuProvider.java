package com.yusql.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.*;
import com.yusql.engine.ScanEngine;
import com.yusql.filter.FilterManager;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class ContextMenuProvider implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final ScanEngine engine;
    private final FilterManager filterManager;

    public ContextMenuProvider(MontoyaApi api, ScanEngine engine, FilterManager filterManager) {
        this.api = api; this.engine = engine; this.filterManager = filterManager;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        List<HttpRequestResponse> messages = event.messageEditorRequestResponse()
            .map(editorResp -> List.of(editorResp.requestResponse()))
            .orElseGet(() -> event.selectedRequestResponses());

        if (messages == null || messages.isEmpty()) return items;

        JMenuItem sendItem = new JMenuItem("Send to YuSQL / 发送到YuSQL");
        sendItem.addActionListener(e -> {
            if (!engine.isRunning()) { engine.start(); api.logging().logToOutput("[YuSQL] 引擎已自动启动"); }
            int count = 0;
            for (HttpRequestResponse rr : messages) {
                try {
                    byte[] req = rr.request().toByteArray().getBytes();
                    String url = rr.request().url();
                    if (filterManager.checkRequest(url) != null) {
                        api.logging().logToOutput("[YuSQL] [过滤] " + url);
                        continue;
                    }
                    if (engine.enqueue(req, rr.httpService(), "右键菜单")) count++;
                } catch (Exception ex) {
                    api.logging().logToError("YuSQL 右键菜单: " + ex.getMessage());
                }
            }
            api.logging().logToOutput("[YuSQL] 已加入队列: " + count + " 个请求");
        });
        items.add(sendItem);

        JMenuItem forceItem = new JMenuItem("Force Rescan / 强制重新扫描");
        forceItem.addActionListener(e -> {
            if (!engine.isRunning()) { engine.start(); api.logging().logToOutput("[YuSQL] 引擎已自动启动"); }
            engine.getDedup().clearAll();
            int count = 0;
            for (HttpRequestResponse rr : messages) {
                try {
                    byte[] req = rr.request().toByteArray().getBytes();
                    if (engine.enqueue(req, rr.httpService(), "右键菜单-强制")) count++;
                } catch (Exception ex) {
                    api.logging().logToError("YuSQL 右键菜单: " + ex.getMessage());
                }
            }
            api.logging().logToOutput("[YuSQL] 强制重新扫描已加入: " + count + " 个请求");
        });
        items.add(forceItem);
        return items;
    }
}
