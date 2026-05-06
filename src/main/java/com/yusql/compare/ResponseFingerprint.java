package com.yusql.compare;

import java.util.List;

public class ResponseFingerprint {
    private final int statusCode;
    private final int bodyLength;
    private final String title;
    private final String contentType;
    private final String rawBody;
    private final String normalizedBody;
    private final String normalizedBodyHash;
    private final int normalizedBodyLength;
    private final List<String[]> errorRegexHits;  // [regex, snippet] pairs
    private final List<String> noiseRegexHits;

    public ResponseFingerprint(int statusCode, int bodyLength, String title, String contentType,
                               String rawBody, String normalizedBody, String normalizedBodyHash,
                               int normalizedBodyLength, List<String[]> errorRegexHits,
                               List<String> noiseRegexHits) {
        this.statusCode = statusCode;
        this.bodyLength = bodyLength;
        this.title = title;
        this.contentType = contentType;
        this.rawBody = rawBody;
        this.normalizedBody = normalizedBody;
        this.normalizedBodyHash = normalizedBodyHash;
        this.normalizedBodyLength = normalizedBodyLength;
        this.errorRegexHits = errorRegexHits;
        this.noiseRegexHits = noiseRegexHits;
    }

    public int getStatusCode() { return statusCode; }
    public int getBodyLength() { return bodyLength; }
    public String getTitle() { return title; }
    public String getContentType() { return contentType; }
    public String getRawBody() { return rawBody; }
    public String getNormalizedBody() { return normalizedBody; }
    public String getNormalizedBodyHash() { return normalizedBodyHash; }
    public int getNormalizedBodyLength() { return normalizedBodyLength; }
    public List<String[]> getErrorRegexHits() { return errorRegexHits; }
    public List<String> getNoiseRegexHits() { return noiseRegexHits; }
    public boolean hasErrorHit() { return errorRegexHits != null && !errorRegexHits.isEmpty(); }
}
