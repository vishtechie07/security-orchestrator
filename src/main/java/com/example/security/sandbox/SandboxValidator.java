package com.example.security.sandbox;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.nio.file.Paths;

@Component
public class SandboxValidator {

    private final Path sandboxBase;

    public SandboxValidator(@Value("${security.sandbox.base-path:/tmp/security-sandbox}") String basePath) {
        this.sandboxBase = Paths.get(basePath).toAbsolutePath().normalize();
    }

    public Path validateAndResolve(String path) {
        if (path == null || path.isBlank()) {
            throw new SandboxViolationException("Path must not be null or blank");
        }
        Path resolved = Paths.get(path).toAbsolutePath().normalize();
        try {
            if (resolved.toFile().exists()) {
                resolved = resolved.toRealPath();
            }
        } catch (Exception e) {
            throw new SandboxViolationException("Invalid or inaccessible path: " + path, e);
        }
        Path baseCanonical = resolveBaseCanonical();
        if (!resolved.startsWith(baseCanonical)) {
            throw new SandboxViolationException(
                "Path is outside sandbox: " + resolved + " (sandbox: " + baseCanonical + ")");
        }
        return resolved;
    }

    private Path resolveBaseCanonical() {
        try {
            return sandboxBase.toFile().exists() ? sandboxBase.toRealPath() : sandboxBase;
        } catch (Exception e) {
            return sandboxBase;
        }
    }

    public boolean isAllowed(String path) {
        try {
            validateAndResolve(path);
            return true;
        } catch (SandboxViolationException e) {
            return false;
        }
    }

    public Path getSandboxBase() {
        return sandboxBase;
    }

    public static final class SandboxViolationException extends RuntimeException {
        public SandboxViolationException(String message) {
            super(message);
        }

        public SandboxViolationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
