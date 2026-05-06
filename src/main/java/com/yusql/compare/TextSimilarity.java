package com.yusql.compare;

public class TextSimilarity {
    public static double levenshteinRatio(String s1, String s2) {
        if (s1 == null || s2 == null) return 0.0;
        if (s1.isEmpty() && s2.isEmpty()) return 1.0;
        if (s1.isEmpty() || s2.isEmpty()) return 0.0;
        int d = levenshteinDistance(s1, s2);
        int maxLen = Math.max(s1.length(), s2.length());
        return 1.0 - ((double)d / maxLen);
    }

    private static int levenshteinDistance(String s1, String s2) {
        int[] prev = new int[s2.length() + 1];
        int[] curr = new int[s2.length() + 1];
        for (int j = 0; j <= s2.length(); j++) prev[j] = j;
        for (int i = 1; i <= s1.length(); i++) {
            curr[0] = i;
            for (int j = 1; j <= s2.length(); j++) {
                int cost = s1.charAt(i - 1) == s2.charAt(j - 1) ? 0 : 1;
                curr[j] = Math.min(Math.min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            int[] tmp = prev; prev = curr; curr = tmp;
        }
        return prev[s2.length()];
    }

    /** Quick check: MD5 hash of normalized body */
    public static String hash(String s) {
        if (s == null || s.isEmpty()) return "0";
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { return String.valueOf(s.hashCode()); }
    }
}
