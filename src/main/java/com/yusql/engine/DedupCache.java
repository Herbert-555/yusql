package com.yusql.engine;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class DedupCache {
    private final Set<String> reqCache = new HashSet<>();    // Byte-level dedup (exact duplicate requests)
    private final Set<String> ifaceCache = new HashSet<>(); // Interface-level dedup (method+path+params)

    /** Check if request-level dedup hits. Returns true if already seen. */
    public boolean isDupReq(byte[] request, String source) {
        String key = md5(new String(request, StandardCharsets.UTF_8));
        return !reqCache.add(key);
    }

    /** Check if interface-level dedup key is already seen. Returns true if duplicate. */
    public boolean isDupKey(String dedupKey) {
        return !ifaceCache.add(dedupKey);
    }

    /** Check test-point level dedup */
    public boolean isDupTp(String url, String method, String paramName, String paramType,
                           String jsonPath, String jsonTestType, String module) {
        String raw = method + "|" + url + "|" + paramName + "|" + paramType + "|" + jsonPath + "|" + module;
        return !reqCache.add(md5(raw));
    }

    public void clearAll() {
        reqCache.clear();
        ifaceCache.clear();
    }

    public int reqCacheSize() { return reqCache.size(); }
    public int ifaceCacheSize() { return ifaceCache.size(); }

    /** Generate interface-level dedup key: MD5(requestType + path + sorted_param_set) */
    public static String interfaceDedupKey(String method, String path, List<String> paramKeys) {
        List<String> sorted = new ArrayList<>(paramKeys);
        Collections.sort(sorted);
        String raw = method + "+" + path + "+" + String.join(",", sorted);
        return md5(raw);
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
}
