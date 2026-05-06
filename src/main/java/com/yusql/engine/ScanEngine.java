package com.yusql.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.yusql.compare.*;
import com.yusql.config.YuSQLConfig;
import com.yusql.filter.FilterManager;
import com.yusql.model.*;
import com.yusql.module.*;
import com.yusql.mutate.RequestBuilder;
import com.yusql.parser.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

public class ScanEngine {
    private final MontoyaApi api;
    private YuSQLConfig config;
    private final FilterManager filterManager;
    private final TaskQueue queue;
    private final DedupCache dedup;
    private final ScanState state = new ScanState();

    private Normalizer normalizer;
    private ResponseComparator comparator;
    private ErrorInjectionModule errorMod;
    private BooleanBlindModule booleanMod;
    private OrderTestModule orderMod;
    private OrderInjectionModule orderInjMod;

    private ExecutorService executor;
    private volatile boolean running;

    // Callbacks
    private Consumer<LogEntry> scanStartCb;     // Called when a scan entry is first created
    private Consumer<LogEntry> scanUpdateCb;    // Called to update an existing scan entry
    private Consumer<LogEntry> payloadResultCb; // Called for each payload test result
    private Consumer<LogEntry> scanCompleteCb;  // Called when scan is finished
    private Consumer<String> logCb;

    public ScanEngine(MontoyaApi api, YuSQLConfig config, FilterManager fm) {
        this.api = api;
        this.config = config;
        this.filterManager = fm;
        this.queue = new TaskQueue(config.getMaxQueueSize());
        this.dedup = new DedupCache();
        syncConfig();
    }

    public void setScanStartCallback(Consumer<LogEntry> cb) { scanStartCb = cb; }
    public void setScanUpdateCallback(Consumer<LogEntry> cb) { scanUpdateCb = cb; }
    public void setPayloadResultCallback(Consumer<LogEntry> cb) { payloadResultCb = cb; }
    public void setScanCompleteCallback(Consumer<LogEntry> cb) { scanCompleteCb = cb; }
    public void setLogCallback(Consumer<String> cb) { logCb = cb; }

    private void syncConfig() {
        normalizer = new Normalizer();
        normalizer.setNoise(config.getNoisePatterns());
        normalizer.setRemoveWs(config.isRemoveWhitespace());
        comparator = new ResponseComparator(normalizer, config.getErrorPatterns(),
            config.getSimilarityThreshold(), config.getLengthDiffRatio(), config.getLengthDiffAbs());
        errorMod = new ErrorInjectionModule(api, comparator, config.getErrorPocs(),
            config.getLengthDiffAbs(), normalizer);
        booleanMod = new BooleanBlindModule(api, comparator, normalizer, config.getLengthDiffAbs());
        orderMod = new OrderTestModule(api, comparator, config.getAppendParams(),
            config.getAppendParamGroups(), config.getLengthDiffAbs(), normalizer);
        orderInjMod = new OrderInjectionModule(api, normalizer,
            config.getOrderInjectionParams());
        queue.setMax(config.getMaxQueueSize());
    }

    /**
     * Enqueue a request for scanning. Creates scan entry IMMEDIATELY in the UI.
     */
    public boolean enqueue(byte[] request, HttpService httpService, String source) {
        if (!running) {
            log("[跳过] 引擎未启动");
            return false;
        }

        // Extract URL early for filtering and display
        String[] urlMethod = extractUrlAndMethod(request);
        String url = urlMethod[0];
        String method = urlMethod[1];

        // Quick URL-based filter check (domain/URL blacklist)
        String filterReason = filterManager.checkRequest(url);
        if (filterReason != null) {
            log("[跳过] " + filterReason + ": " + url);
            state.incSkipped();
            return false;
        }

        // Request-level dedup (exact duplicate bytes)
        if (config.isDeduplicateTasks() && dedup.isDupReq(request, source)) {
            log("[跳过] 请求级去重命中: " + url);
            state.incSkipped();
            return false;
        }

        // Queue capacity check
        if (queue.size() >= config.getMaxQueueSize()) {
            log("[跳过] 队列已满 (" + config.getMaxQueueSize() + "): " + url);
            state.incSkipped();
            return false;
        }

        // Create scan entry immediately with "执行中" status
        LogEntry scanEntry = createScanEntry(url, source, "执行中", request, httpService);
        String dataMd5 = scanEntry.getDataMd5();

        // Show in UI immediately
        if (scanStartCb != null) scanStartCb.accept(scanEntry);
        log("[入队] " + source + " → " + url);

        // Add to queue
        ScanTask task = new ScanTask(request, httpService, source, dataMd5);
        if (queue.offer(task)) {
            return true;
        } else {
            state.incSkipped();
            log("[跳过] 入队失败(队列满): " + url);
            return false;
        }
    }

    private LogEntry createScanEntry(String url, String source, String state,
                                      byte[] request, HttpService httpService) {
        String timestamp = java.time.LocalDateTime.now()
            .format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss"));
        int toolFlag = getToolFlag(source);
        LogEntry entry = new LogEntry(url, state, 0, timestamp,
            request, null, toolFlag,
            httpService.host(), httpService.port(), httpService.secure());
        entry.setResponseLength(0);
        entry.setColorLevel(0);
        return entry;
    }

    /**
     * Extract URL and method from raw HTTP request bytes.
     * Returns [url, method]. URL is reconstructed as scheme://host:port/path?query
     */
    private String[] extractUrlAndMethod(byte[] request) {
        try {
            String raw = new String(request, StandardCharsets.UTF_8);
            String[] lines = raw.split("\r\n");
            if (lines.length == 0) return new String[]{"unknown", "GET"};

            String[] reqLine = lines[0].split(" ", 3);
            String method = reqLine.length > 0 ? reqLine[0] : "GET";
            String path = reqLine.length > 1 ? reqLine[1] : "/";

            // Try to get Host from headers
            String host = "";
            for (int i = 1; i < lines.length; i++) {
                if (lines[i].isEmpty()) break;
                if (lines[i].toLowerCase().startsWith("host:")) {
                    host = lines[i].substring(5).strip();
                    break;
                }
            }

            String url;
            if (!host.isEmpty()) {
                url = "https://" + host + path;
            } else {
                url = path;
            }
            return new String[]{url, method};
        } catch (Exception e) {
            return new String[]{"unknown", "GET"};
        }
    }

    public void start() {
        if (running) return;
        running = true;
        state.reset();
        syncConfig();
        executor = Executors.newFixedThreadPool(config.getThreadCount(), r -> {
            Thread t = new Thread(r, "YuSQL-w");
            t.setDaemon(true);
            return t;
        });
        log("[YuSQL] 已启动, 线程数: " + config.getThreadCount());
        for (int i = 0; i < config.getThreadCount(); i++) executor.submit(this::loop);
    }

    public void stop() {
        running = false;
        if (executor != null) executor.shutdownNow();
        log("[YuSQL] 已停止");
    }

    private void loop() {
        while (running || !queue.isEmpty()) {
            try {
                ScanTask task = queue.poll();
                if (task == null) { if (!running) break; Thread.sleep(100); continue; }
                process(task);
            } catch (InterruptedException e) { break; }
            catch (Exception e) { log("[错误] Worker: " + e.getMessage()); }
        }
    }

    private void process(ScanTask task) {
        try {
            RequestBuilder builder = new RequestBuilder(task.getRequest(), task.getHttpService());
            if (config.isEnableUrlEncodeChars()) {
                builder.setUrlEncodeChars(config.getUrlEncodeChars());
            }
            String url = builder.getUrl();
            String method = builder.getMethod();

            // Parse parameters
            ParameterParser pp = new ParameterParser(method, url, builder.getBody(),
                builder.getContentType(), config.isEnableJsonValue(), config.isEnableJsonInParam());
            List<TestPoint> points = filterManager.filter(pp.findAll());

            // Interface-level dedup
            List<String> paramKeys = new ArrayList<>();
            for (TestPoint tp : points) paramKeys.add(tp.dedupKey());
            String dedupKey = DedupCache.interfaceDedupKey(method, getPath(url), paramKeys);

            if (config.isDeduplicateTasks() && dedup.isDupKey(dedupKey)) {
                log("[跳过] 接口已测试, dedup=" + dedupKey + " → " + url);
                state.incSkipped();
                if (scanUpdateCb != null) scanUpdateCb.accept(buildUpdateEntry(task.getDataMd5(), "跳过", 0, 0));
                return;
            }

            // Send original request to get R0 response
            log("[R0] 发送原始请求: " + url);
            HttpRequest origReq = builder.getOriginalRequest();
            long start = System.currentTimeMillis();
            HttpRequestResponse origReqResp = api.http().sendRequest(origReq);
            HttpResponse origResp = origReqResp.response();
            int origTime = (int)(System.currentTimeMillis() - start);
            byte[] r0ReqBytes = task.getRequest();
            byte[] r0RespBytes = origResp.toByteArray().getBytes();
            String r0Body = origResp.bodyToString();
            int r0Len = r0Body.length();
            int r0Code = origResp.statusCode();

            log("[R0] " + url + " → 长度" + r0Len + " 用时" + origTime + "ms 状态码" + r0Code);

            // Update pre-created scan entry with R0 info (including response bytes)
            if (scanUpdateCb != null) {
                LogEntry r0Update = buildUpdateEntry(task.getDataMd5(), "执行中", r0Len, 0);
                r0Update.setResponse(r0RespBytes);
                scanUpdateCb.accept(r0Update);
            }

            // Execute per parameter: boolean → error
            boolean hasRed = false, hasYellow = false, hasBlue = false, hasOrderInj = false;

            for (TestPoint tp : points) {
                if (!running) break;

                String paramLabel = tp.displayPath();
                log("[参数] 开始测试: " + paramLabel + " (类型=" + tp.getParamType() + ")");

                // 1. Boolean blind (short-circuit flow)
                if (config.isEnableBoolean()) {
                    try {
                        List<LogEntry> boolResults = booleanMod.test(builder, tp,
                            task.getDataMd5(), r0ReqBytes, r0RespBytes, r0Len);
                        for (LogEntry r : boolResults) {
                            if (r != null) {
                                state.addSent(true);
                                if (payloadResultCb != null) payloadResultCb.accept(r);
                                int cl = r.getColorLevel();
                                if (cl >= 3) hasRed = true;
                                else if (cl >= 2) hasYellow = true;
                                else if (cl >= 1) hasBlue = true;

                                log("[布尔] " + paramLabel + " " + r.getChange() +
                                    " payload=" + r.getDisplayPayload() +
                                    " → 长度" + r.getResponseLength() +
                                    " 用时" + r.getResponseTime() + "ms" +
                                    " 状态码" + r.getStatusCode() +
                                    " 类型=" + r.getTestType());
                            }
                        }
                    } catch (Exception e) {
                        log("[错误] 布尔注入异常 " + paramLabel + ": " + e.getMessage());
                    }
                }

                // 2. Error injection (user custom POCs only)
                if (config.isEnableError()) {
                    try {
                        List<LogEntry> errResults = errorMod.test(builder, tp,
                            task.getDataMd5(), r0Len);
                        for (LogEntry r : errResults) {
                            if (r != null) {
                                state.addSent(true);
                                if (payloadResultCb != null) payloadResultCb.accept(r);
                                int cl = r.getColorLevel();
                                if (cl >= 3) hasRed = true;
                                else if (cl >= 1) hasBlue = true;

                                log("[报错] " + paramLabel + " " + r.getChange() +
                                    " payload=" + r.getDisplayPayload() +
                                    " → 长度" + r.getResponseLength() +
                                    " 用时" + r.getResponseTime() + "ms" +
                                    " 状态码" + r.getStatusCode() +
                                    " 类型=" + r.getTestType());
                            }
                        }
                    } catch (Exception e) {
                        log("[错误] 报错注入异常 " + paramLabel + ": " + e.getMessage());
                    }
                }
            }

            // 3. Single-param order injection: for append param keys that already exist
            //    in the original request, test each individually (other params stay unchanged)
            if (config.isEnableOrder() && config.isEnableOrderInjection()) {
                Set<String> origParamNames = new HashSet<>();
                for (TestPoint tp : points) origParamNames.add(tp.getParamName());
                // Build JSON-in-param mapping: inner field name → (outerParamName, jsonEncoded)
                Map<String, TestPoint> jsonInParamMap = new LinkedHashMap<>();
                for (TestPoint tp : points) {
                    if (tp.getParamType() == ParamType.JSON_IN_PARAM && !tp.getJsonPath().isEmpty()) {
                        String innerName = tp.getJsonPath().startsWith("$.")
                            ? tp.getJsonPath().substring(2) : tp.getJsonPath();
                        jsonInParamMap.putIfAbsent(innerName, tp);
                    }
                }
                for (var appendParam : config.getAppendParams()) {
                    String key = appendParam.getKey();
                    if (origParamNames.contains(key)) {
                        log("[排序-单独] 原始请求中存在参数 " + key + "，单独测试排序注入");
                        try {
                            List<LogEntry> singleResults = orderInjMod.testSingle(builder,
                                task.getDataMd5(), r0RespBytes, key, appendParam.getValue());
                            for (LogEntry r : singleResults) {
                                if (r != null) {
                                    state.addSent(true);
                                    if (payloadResultCb != null) payloadResultCb.accept(r);
                                    int cl = r.getColorLevel();
                                    if (cl >= 3) hasRed = true;
                                    else if (cl >= 2) { hasYellow = true; hasOrderInj = true; }
                                    else if (cl >= 1) hasBlue = true;

                                    log("[排序-单独] " + r.getParameter() +
                                        " payload=" + r.getDisplayPayload() +
                                        " " + r.getChange() +
                                        " → 长度" + r.getResponseLength() +
                                        " 用时" + r.getResponseTime() + "ms" +
                                        " 状态码" + r.getStatusCode() +
                                        " 类型=" + r.getTestType());
                                }
                            }
                        } catch (Exception e) {
                            log("[错误] 单独排序注入异常 " + key + ": " + e.getMessage());
                        }
                    } else if (jsonInParamMap.containsKey(key)) {
                        TestPoint tp = jsonInParamMap.get(key);
                        log("[排序-单独] JSON参数 " + tp.getParamName()
                            + " 内部字段 " + key + " 匹配，单独测试排序注入");
                        try {
                            List<LogEntry> singleResults = orderInjMod.testSingleJsonInParam(builder,
                                task.getDataMd5(), r0RespBytes, tp.getParamName(),
                                key, appendParam.getValue(), tp.isJsonEncoded());
                            for (LogEntry r : singleResults) {
                                if (r != null) {
                                    state.addSent(true);
                                    if (payloadResultCb != null) payloadResultCb.accept(r);
                                    int cl = r.getColorLevel();
                                    if (cl >= 3) hasRed = true;
                                    else if (cl >= 2) { hasYellow = true; hasOrderInj = true; }
                                    else if (cl >= 1) hasBlue = true;

                                    log("[排序-单独] " + r.getParameter() +
                                        " payload=" + r.getDisplayPayload() +
                                        " " + r.getChange() +
                                        " → 长度" + r.getResponseLength() +
                                        " 用时" + r.getResponseTime() + "ms" +
                                        " 状态码" + r.getStatusCode() +
                                        " 类型=" + r.getTestType());
                                }
                            }
                        } catch (Exception e) {
                            log("[错误] JSON排序注入异常 " + key + ": " + e.getMessage());
                        }
                    }
                }
            }

            // 4. Order test (append params, after all per-param tests)
            if (config.isEnableOrder()) {
                try {
                    List<LogEntry> orderResults = orderMod.test(builder,
                        task.getDataMd5(), r0ReqBytes, r0RespBytes, r0Len);
                    for (LogEntry r : orderResults) {
                        if (r != null) {
                            state.addSent(true);
                            if (payloadResultCb != null) payloadResultCb.accept(r);
                            int cl = r.getColorLevel();
                            if (cl >= 3) hasRed = true;
                            else if (cl >= 1) hasBlue = true;

                            log("[追加] " + r.getParameter() +
                                " payload=" + r.getDisplayPayload() +
                                " " + r.getChange() +
                                " → 长度" + r.getResponseLength() +
                                " 用时" + r.getResponseTime() + "ms" +
                                " 状态码" + r.getStatusCode() +
                                " 类型=" + r.getTestType());
                        }
                    }
                } catch (Exception e) {
                    log("[错误] 追加参数异常: " + e.getMessage());
                }
            }

            // 5. Order injection test (per group, after append test)
            if (config.isEnableOrder() && config.isEnableOrderInjection()) {
                try {
                    List<LogEntry> oiResults = orderInjMod.testAll(builder,
                        task.getDataMd5(), r0ReqBytes, r0RespBytes, r0Len,
                        config.getAppendParams(), config.getAppendParamGroups());
                    for (LogEntry r : oiResults) {
                        if (r != null) {
                            state.addSent(true);
                            if (payloadResultCb != null) payloadResultCb.accept(r);
                            int cl = r.getColorLevel();
                            if (cl >= 3) hasRed = true;
                            else if (cl >= 2) { hasYellow = true; hasOrderInj = true; }
                            else if (cl >= 1) hasBlue = true;

                            log("[排序] " + r.getParameter() +
                                " payload=" + r.getDisplayPayload() +
                                " " + r.getChange() +
                                " → 长度" + r.getResponseLength() +
                                " 用时" + r.getResponseTime() + "ms" +
                                " 状态码" + r.getStatusCode() +
                                " 类型=" + r.getTestType());
                        }
                    }
                } catch (Exception e) {
                    log("[错误] 排序注入异常: " + e.getMessage());
                }
            }

            // Finalize scan entry state and color
            String finalState;
            int finalColor;
            if (hasRed) {
                finalState = "报错命中";
                finalColor = 3;
            } else if (hasOrderInj) {
                finalState = "排序注入";
                finalColor = 2;
            } else if (hasYellow) {
                finalState = "布尔命中";
                finalColor = 2;
            } else if (hasBlue) {
                finalState = "疑似变化";
                finalColor = 1;
            } else {
                finalState = "已完成";
                finalColor = 0;
            }

            log("[状态] " + method + " " + url + " → " + finalState +
                (finalColor >= 3 ? " (红)" : finalColor >= 2 ? " (黄)" : finalColor >= 1 ? " (蓝)" : ""));

            if (scanUpdateCb != null)
                scanUpdateCb.accept(buildUpdateEntry(task.getDataMd5(), finalState, r0Len, finalColor));

            if (scanCompleteCb != null) {
                HttpService svc = task.getHttpService();
                LogEntry complete = new LogEntry(url, finalState, points.size(), "", task.getRequest(), r0RespBytes, getToolFlag(task.getSource()),
                    svc.host(), svc.port(), svc.secure());
                complete.setDataMd5(task.getDataMd5());
                complete.setResponseLength(r0Len);
                complete.setColorLevel(finalColor);
                scanCompleteCb.accept(complete);
            }

            state.incScanned();

        } catch (Exception e) {
            log("[错误] 处理异常: " + e.getMessage());
            state.incSkipped();
        }
    }

    /** Build a minimal LogEntry for updating an existing scan entry via dataMd5 */
    private LogEntry buildUpdateEntry(String dataMd5, String state, int responseLength, int colorLevel) {
        return new LogEntry(dataMd5, state, responseLength, colorLevel);
    }

    private void log(String msg) {
        api.logging().logToOutput(msg);
        if (logCb != null) logCb.accept(msg);
    }

    private String getPath(String url) {
        if (url == null) return "/";
        int qi = url.indexOf('?');
        return qi >= 0 ? url.substring(0, qi) : url;
    }

    private int getToolFlag(String source) {
        if (source == null) return 1024;
        return switch (source) {
            case "Proxy" -> 4;
            case "Repeater" -> 64;
            default -> 1024;
        };
    }

    public ScanState getState() { return state; }
    public TaskQueue getQueue() { return queue; }
    public DedupCache getDedup() { return dedup; }
    public boolean isRunning() { return running; }
    public void reloadConfig() { syncConfig(); }
}
