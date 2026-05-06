package com.yusql.parser;

import java.util.*;

public class SimpleJson {
    public static Object parse(String json) {
        if (json == null || json.isBlank()) return null;
        json = json.trim();
        int[] pos = {0};
        try { return parseValue(json, pos); }
        catch (Exception e) { return null; }
    }

    private static Object parseValue(String json, int[] pos) {
        skipWs(json, pos);
        if (pos[0] >= json.length()) return null;
        char c = json.charAt(pos[0]);
        return switch(c) {
            case '{' -> parseObject(json, pos);
            case '[' -> parseArray(json, pos);
            case '"' -> parseString(json, pos);
            case 't', 'f' -> parseBool(json, pos);
            case 'n' -> parseNull(json, pos);
            default -> parseNumber(json, pos);
        };
    }

    private static Map<String,Object> parseObject(String json, int[] pos) {
        Map<String,Object> m = new LinkedHashMap<>();
        pos[0]++; // skip {
        skipWs(json, pos);
        if (json.charAt(pos[0]) == '}') { pos[0]++; return m; }
        while (true) {
            skipWs(json, pos);
            String key = parseString(json, pos);
            skipWs(json, pos);
            pos[0]++; // skip :
            Object value = parseValue(json, pos);
            m.put(key, value);
            skipWs(json, pos);
            if (json.charAt(pos[0]) == '}') { pos[0]++; return m; }
            pos[0]++; // skip ,
        }
    }

    private static List<Object> parseArray(String json, int[] pos) {
        List<Object> list = new ArrayList<>();
        pos[0]++; // skip [
        skipWs(json, pos);
        if (json.charAt(pos[0]) == ']') { pos[0]++; return list; }
        while (true) {
            list.add(parseValue(json, pos));
            skipWs(json, pos);
            if (json.charAt(pos[0]) == ']') { pos[0]++; return list; }
            pos[0]++; // skip ,
        }
    }

    private static String parseString(String json, int[] pos) {
        StringBuilder sb = new StringBuilder();
        pos[0]++; // skip opening "
        while (pos[0] < json.length()) {
            char c = json.charAt(pos[0]++);
            if (c == '"') return sb.toString();
            if (c == '\\') {
                char e = json.charAt(pos[0]++);
                switch(e) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'u':
                        String hex = json.substring(pos[0], pos[0]+4);
                        sb.append((char)Integer.parseInt(hex, 16));
                        pos[0] += 4;
                        break;
                    default: sb.append(e);
                }
            } else { sb.append(c); }
        }
        return sb.toString();
    }

    private static Boolean parseBool(String json, int[] pos) {
        if (json.startsWith("true", pos[0])) { pos[0] += 4; return Boolean.TRUE; }
        pos[0] += 5; return Boolean.FALSE;
    }

    private static Object parseNull(String json, int[] pos) {
        pos[0] += 4; return null;
    }

    @SuppressWarnings("unchecked")
    private static Object parseNumber(String json, int[] pos) {
        int start = pos[0];
        while (pos[0] < json.length() && "0123456789.-+eE".indexOf(json.charAt(pos[0])) >= 0) pos[0]++;
        String num = json.substring(start, pos[0]);
        try { return Long.parseLong(num); } catch(Exception e1) {}
        try { return Double.parseDouble(num); } catch(Exception e2) {}
        return num;
    }

    private static void skipWs(String json, int[] pos) {
        while (pos[0] < json.length() && Character.isWhitespace(json.charAt(pos[0]))) pos[0]++;
    }

    // --- Serialize ---
    public static String toJson(Object obj) {
        StringBuilder sb = new StringBuilder();
        write(sb, obj);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(StringBuilder sb, Object obj) {
        if (obj == null) { sb.append("null"); return; }
        if (obj instanceof String) {
            sb.append('"');
            for (char c : ((String)obj).toCharArray()) {
                switch(c) {
                    case '"': sb.append("\\\""); break;
                    case '\\': sb.append("\\\\"); break;
                    case '\n': sb.append("\\n"); break;
                    case '\r': sb.append("\\r"); break;
                    case '\t': sb.append("\\t"); break;
                    case '\b': sb.append("\\b"); break;
                    case '\f': sb.append("\\f"); break;
                    default:
                        if (c < 0x20) sb.append(String.format("\\u%04x", (int)c));
                        else sb.append(c);
                }
            }
            sb.append('"');
        } else if (obj instanceof Number || obj instanceof Boolean) {
            sb.append(obj.toString());
        } else if (obj instanceof Map) {
            Map<String,Object> m = (Map<String,Object>) obj;
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String,Object> e : m.entrySet()) {
                if (!first) sb.append(','); first = false;
                sb.append('"');
                for (char c : e.getKey().toCharArray()) {
                    if (c == '"') sb.append("\\\"");
                    else if (c == '\\') sb.append("\\\\");
                    else sb.append(c);
                }
                sb.append('"').append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
        } else if (obj instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object item : (List<Object>) obj) {
                if (!first) sb.append(','); first = false;
                write(sb, item);
            }
            sb.append(']');
        }
    }

    public static String esc(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch(c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }
}
