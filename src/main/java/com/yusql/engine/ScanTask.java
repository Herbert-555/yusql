package com.yusql.engine;

import burp.api.montoya.http.HttpService;

public class ScanTask {
    private final byte[] request;
    private final HttpService httpService;
    private final String source;
    private final String dataMd5; // Links to pre-created scan entry

    public ScanTask(byte[] request, HttpService httpService, String source, String dataMd5) {
        this.request = request;
        this.httpService = httpService;
        this.source = source;
        this.dataMd5 = dataMd5;
    }

    public byte[] getRequest() { return request; }
    public HttpService getHttpService() { return httpService; }
    public String getSource() { return source; }
    public String getDataMd5() { return dataMd5; }
}
