package com.yusql.model;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

public class LogEntry {
    private static int nextId = 1;
    private static int nextScanId = 1;

    // Common fields
    private final int id;
    private String dataMd5;  // Links payload entries to parent scan entry
    private final int toolFlag;    // Source: 64=Repeater, 4=Proxy, 1024=ContextMenu

    // Scan result fields (left table: #, 来源, URL, 返回包长度, 状态)
    private String url;
    private String state;
    private int responseLength;
    private int parameterCount;
    private String timestamp;

    // Payload detail fields (right table: 参数, payload, 返回包长度, 变化, 用时, 响应码, 测试类型)
    private String parameter;
    private String payload;
    private String change;
    private int responseTime;
    private String statusCode;
    private String similarity = "";
    private String testType;  // "Err", "Bool", "Len", "Err,Bool" or ""

    // HTTP message data
    private byte[] request;   // original request for scan entries; test request for payload entries
    private byte[] response;  // original response for scan entries; test response for payload entries
    private byte[] originalRequest;  // payload entries keep reference to original request
    private byte[] originalResponse; // payload entries keep reference to original response

    // Color level: 3=RED, 2=YELLOW, 1=BLUE, 0=DEFAULT
    private int colorLevel;

    // Target service info (for sending to Repeater with correct host/port)
    private String serviceHost;
    private int servicePort;
    private boolean serviceSecure;

    /** Constructor for scan result entries */
    public LogEntry(String url, String state, int parameterCount, String timestamp,
                    byte[] request, byte[] response, int toolFlag,
                    String serviceHost, int servicePort, boolean serviceSecure) {
        this.id = nextScanId++;
        this.url = url;
        this.state = state;
        this.parameterCount = parameterCount;
        this.timestamp = timestamp;
        this.request = request;
        this.response = response;
        this.toolFlag = toolFlag;
        this.responseLength = response != null ? response.length : 0;
        this.dataMd5 = md5(url + System.nanoTime());
        this.serviceHost = serviceHost;
        this.servicePort = servicePort;
        this.serviceSecure = serviceSecure;
    }

    /** Constructor for payload detail entries */
    public LogEntry(String parameter, String payload, String change, int responseLength,
                    int responseTime, String statusCode, String testType,
                    byte[] testRequest, byte[] testResponse,
                    byte[] originalRequest, byte[] originalResponse, String parentMd5, int toolFlag,
                    String serviceHost, int servicePort, boolean serviceSecure) {
        this.id = nextId++;
        this.parameter = parameter;
        this.payload = payload;
        this.change = change;
        this.responseLength = responseLength;
        this.responseTime = responseTime;
        this.statusCode = statusCode;
        this.testType = testType;
        this.request = testRequest;
        this.response = testResponse;
        this.originalRequest = originalRequest;
        this.originalResponse = originalResponse;
        this.dataMd5 = parentMd5;
        this.toolFlag = toolFlag;
        this.serviceHost = serviceHost;
        this.servicePort = servicePort;
        this.serviceSecure = serviceSecure;
    }

    /** Minimal constructor for update-only entries (used by scanUpdateCb) */
    public LogEntry(String dataMd5, String state, int responseLength, int colorLevel) {
        this.id = nextId++;
        this.dataMd5 = dataMd5;
        this.state = state;
        this.responseLength = responseLength;
        this.colorLevel = colorLevel;
        this.toolFlag = 0;
    }

    // Getters
    public int getId() { return id; }
    public String getDataMd5() { return dataMd5; }
    public int getToolFlag() { return toolFlag; }
    public String getUrl() { return url; }
    public String getState() { return state; }
    public int getResponseLength() { return responseLength; }
    public int getParameterCount() { return parameterCount; }
    public String getTimestamp() { return timestamp; }
    public String getParameter() { return parameter; }
    public String getPayload() { return payload; }
    public String getChange() { return change; }
    public int getResponseTime() { return responseTime; }
    public String getStatusCode() { return statusCode; }
    public String getSimilarity() { return similarity; }
    public String getTestType() { return testType; }
    public byte[] getRequest() { return request; }
    public byte[] getResponse() { return response; }
    public byte[] getOriginalRequest() { return originalRequest; }
    public byte[] getOriginalResponse() { return originalResponse; }
    public int getColorLevel() { return colorLevel; }
    public String getServiceHost() { return serviceHost; }
    public int getServicePort() { return servicePort; }
    public boolean isServiceSecure() { return serviceSecure; }

    // Setters for mutable fields
    public void setState(String s) { this.state = s; }
    public void setResponseLength(int l) { this.responseLength = l; }
    public void setChange(String c) { this.change = c; }
    public void setSimilarity(String s) { this.similarity = s != null ? s : ""; }
    public void setTestType(String t) { this.testType = t; }
    public void setColorLevel(int l) { this.colorLevel = l; }
    public void setRequest(byte[] r) { this.request = r; }
    public void setResponse(byte[] r) { this.response = r; }
    public void setDataMd5(String md5) { this.dataMd5 = md5; }

    public String getToolName() {
        return switch(toolFlag) {
            case 4 -> "Proxy";
            case 64 -> "Repeater";
            case 1024 -> "右键菜单";
            default -> "工具" + toolFlag;
        };
    }

    /** Display payload - truncates if too long */
    public String getDisplayPayload() {
        if (payload == null) return "";
        return payload.length() > 100 ? payload.substring(0, 97) + "..." : payload;
    }

    private static String md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { return Integer.toHexString(input.hashCode()); }
    }

    public static synchronized void resetIdCounter() { nextId = 1; nextScanId = 1; }
}
