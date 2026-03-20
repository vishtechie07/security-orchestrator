package com.example.security.util;

import java.nio.file.Path;

public final class DockerPathUtil {

    private static final boolean WINDOWS = System.getProperty("os.name", "").toLowerCase().contains("win");

    private DockerPathUtil() {}

    public static String toVolumePath(Path path) {
        String s = path.toAbsolutePath().normalize().toString();
        if (WINDOWS && s.length() >= 2 && s.charAt(1) == ':') {
            return "/" + s.substring(0, 1).toLowerCase() + s.substring(2).replace('\\', '/');
        }
        return s.replace('\\', '/');
    }
}
