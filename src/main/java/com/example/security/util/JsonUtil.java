package com.example.security.util;

public final class JsonUtil {

    private JsonUtil() {}

    public static String extractObject(String str) {
        int start = str.indexOf('{');
        if (start < 0) return null;
        int depth = 0;
        for (int i = start; i < str.length(); i++) {
            if (str.charAt(i) == '"') {
                i = skipString(str, i);
                if (i < 0) return null;
                i--;
                continue;
            }
            if (str.charAt(i) == '{') depth++;
            else if (str.charAt(i) == '}') {
                depth--;
                if (depth == 0) return str.substring(start, i + 1);
            }
        }
        return null;
    }

    public static int skipString(String str, int from) {
        if (from >= str.length() || str.charAt(from) != '"') return from;
        for (int i = from + 1; i < str.length(); i++) {
            if (str.charAt(i) == '\\') { i++; continue; }
            if (str.charAt(i) == '"') return i + 1;
        }
        return -1;
    }
}
