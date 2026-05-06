package com.yusql.compare;

import burp.api.montoya.http.message.responses.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

public class ResponseComparator {
    private final Normalizer normalizer;
    private final List<Pattern> errorPatterns;
    private final double similarityThreshold;
    private final double lengthDiffRatio;
    private final int lengthDiffAbs;

    public ResponseComparator(Normalizer normalizer, List<Pattern> errorPatterns,
                              double similarityThreshold, double lengthDiffRatio, int lengthDiffAbs) {
        this.normalizer = normalizer;
        this.errorPatterns = errorPatterns != null ? errorPatterns : new ArrayList<>();
        this.similarityThreshold = similarityThreshold;
        this.lengthDiffRatio = lengthDiffRatio;
        this.lengthDiffAbs = lengthDiffAbs;
    }

    public ResponseFingerprint fingerprint(HttpResponse response) {
        if (response == null) return null;
        String rawBody = response.bodyToString();
        int statusCode = response.statusCode();
        int bodyLength = rawBody != null ? rawBody.length() : 0;
        String title = extractTitle(rawBody);
        String contentType = extractContentType(response);
        String normalizedBody = normalizer.normalize(rawBody);
        String hash = TextSimilarity.hash(normalizedBody);
        int normLen = normalizedBody != null ? normalizedBody.length() : 0;
        List<String[]> errorHits = matchErrors(rawBody);
        List<String> noiseHits = new ArrayList<>(); // simplified
        return new ResponseFingerprint(statusCode, bodyLength, title, contentType,
            rawBody, normalizedBody, hash, normLen, errorHits, noiseHits);
    }

    /** Match response body against all error patterns. Returns list of [regex, snippet] pairs. */
    public List<String[]> matchErrors(String body) {
        List<String[]> hits = new ArrayList<>();
        if (body == null || body.isEmpty()) return hits;
        for (Pattern p : errorPatterns) {
            Matcher m = p.matcher(body);
            if (m.find()) {
                int start = Math.max(0, m.start() - 80);
                int end = Math.min(body.length(), m.end() + 80);
                String snippet = body.substring(start, end);
                hits.add(new String[]{p.pattern(), snippet});
            }
        }
        return hits;
    }

    public boolean hasErrorHit(String body) {
        if (body == null || body.isEmpty()) return false;
        for (Pattern p : errorPatterns) {
            if (p.matcher(body).find()) return true;
        }
        return false;
    }

    public boolean isSameResponse(ResponseFingerprint f1, ResponseFingerprint f2) {
        if (f1 == null || f2 == null) return false;
        // Hash match is strongest
        if (f1.getNormalizedBodyHash().equals(f2.getNormalizedBodyHash())) return true;
        // Status code must match
        if (f1.getStatusCode() != f2.getStatusCode()) return false;
        // Length ratio check
        int len1 = f1.getNormalizedBodyLength(), len2 = f2.getNormalizedBodyLength();
        int maxLen = Math.max(len1, len2);
        if (maxLen > 0) {
            double ratio = (double)Math.abs(len1 - len2) / maxLen;
            if (ratio > lengthDiffRatio) return false;
        }
        // Absolute length diff
        if (Math.abs(len1 - len2) > lengthDiffAbs) return false;
        // Similarity check
        double sim = TextSimilarity.levenshteinRatio(f1.getNormalizedBody(), f2.getNormalizedBody());
        return sim >= similarityThreshold;
    }

    public boolean isDifferentResponse(ResponseFingerprint f1, ResponseFingerprint f2) {
        return !isSameResponse(f1, f2);
    }

    /** Get a human-readable change summary */
    public String getDiffSummary(ResponseFingerprint r0, ResponseFingerprint r1) {
        if (r0 == null || r1 == null) return "";
        int lenDiff = r1.getBodyLength() - r0.getBodyLength();
        StringBuilder sb = new StringBuilder();
        if (r1.hasErrorHit()) sb.append("报错命中");
        if (r0.getStatusCode() != r1.getStatusCode())
            sb.append(sb.isEmpty() ? "状态码变化" : "+状态码变化");
        if (lenDiff != 0)
            sb.append(sb.isEmpty() ? "" : ",").append(lenDiff > 0 ? "长度+" + lenDiff : "长度" + lenDiff);
        return sb.toString();
    }

    public int getLengthDiffAbs() { return lengthDiffAbs; }
    public Normalizer getNormalizer() { return normalizer; }

    private String extractTitle(String body) {
        if (body == null) return null;
        Pattern p = Pattern.compile("<title>(.*?)</title>", Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(body);
        return m.find() ? m.group(1) : null;
    }

    private String extractContentType(HttpResponse response) {
        return "text/html"; // simplified
    }
}
