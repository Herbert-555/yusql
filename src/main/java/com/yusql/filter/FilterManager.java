package com.yusql.filter;

import com.yusql.config.YuSQLConfig;
import java.util.*;
import java.util.regex.Pattern;

public class FilterManager {
    private final YuSQLConfig config;

    public FilterManager(YuSQLConfig config) {
        this.config = config;
    }

    /** Check if a URL should be filtered BEFORE scanning. Returns reason or null if ok. */
    public String checkRequest(String url) {
        // 1. Domain blacklist
        if (config.isEnableDomainBl()) {
            String host = extractHost(url);
            if (host != null && matchesDomain(host, config.getDomainBlacklist())) return "域名黑名单";
        }
        // 2. Domain whitelist
        if (config.isEnableDomainWl() && !config.getDomainWhitelist().isEmpty()) {
            String host = extractHost(url);
            if (host != null && !matchesDomain(host, config.getDomainWhitelist())) return "域名白名单";
        }
        // 3. URL blacklist
        if (config.isEnableUrlBl()) {
            if (matchesAny(url, config.getUrlBlacklist())) return "URL黑名单";
        }
        return null; // pass
    }

    /** Filter test points by param name / jsonPath */
    public List<com.yusql.model.TestPoint> filter(List<com.yusql.model.TestPoint> points) {
        List<com.yusql.model.TestPoint> result = new ArrayList<>();
        for (com.yusql.model.TestPoint tp : points) {
            if (isBlocked(tp.getParamName(), tp.getJsonPath())) continue;
            result.add(tp);
        }
        return result;
    }

    private boolean isBlocked(String paramName, String jsonPath) {
        if (config.isEnableParamBl()) {
            if (matchesAnyParam(paramName, jsonPath, config.getParamBlacklist())) return true;
        }
        if (config.isEnableParamWl() && !config.getParamWhitelist().isEmpty()) {
            if (!matchesAnyParam(paramName, jsonPath, config.getParamWhitelist())) return true;
        }
        return false;
    }

    private boolean matchesAnyParam(String paramName, String jsonPath, List<Pattern> patterns) {
        for (Pattern p : patterns) {
            if (p.matcher(paramName).matches()) return true;
            if (jsonPath != null && !jsonPath.isEmpty() && p.matcher(jsonPath).matches()) return true;
        }
        return false;
    }

    private boolean matchesAny(String value, List<Pattern> patterns) {
        if (value == null) return false;
        // Also try without query string so that .*\\.mp4$ matches /a.mp4?X-Tos-Algorithm=...
        String noQuery = value.contains("?") ? value.substring(0, value.indexOf('?')) : null;
        for (Pattern p : patterns) {
            if (p.matcher(value).matches()) return true;
            if (noQuery != null && p.matcher(noQuery).matches()) return true;
        }
        return false;
    }

    /** Domain matching: supports exact string, *.example.com wildcards, and regex patterns */
    private boolean matchesDomain(String host, List<String> patterns) {
        if (host == null) return false;
        for (String p : patterns) {
            if (p == null) continue;
            // Exact match
            if (p.equalsIgnoreCase(host)) return true;
            // Regex pattern: starts with (?i) or contains regex metacharacters
            if (p.startsWith("(?i)") || p.contains("\\") || p.contains(".*") || p.contains("$")) {
                try {
                    if (Pattern.compile(p, Pattern.CASE_INSENSITIVE).matcher(host).matches()) return true;
                } catch (Exception e) { /* skip bad pattern */ }
                continue;
            }
            // Wildcard: *.example.com
            if (p.startsWith("*.")) {
                String suffix = p.substring(1); // .example.com
                if (host.endsWith(suffix)) return true;
                // Also match the apex domain: example.com
                if (host.equals(suffix.substring(1))) return true;
            }
        }
        return false;
    }

    private String extractHost(String url) {
        if (url == null) return null;
        try {
            String host = url;
            if (host.startsWith("https://")) host = host.substring(8);
            else if (host.startsWith("http://")) host = host.substring(7);
            int slash = host.indexOf('/');
            if (slash >= 0) host = host.substring(0, slash);
            int colon = host.indexOf(':');
            if (colon >= 0) host = host.substring(0, colon);
            return host;
        } catch (Exception e) { return null; }
    }
}
