package com.example.security.tools;

import com.example.security.sandbox.SandboxValidator;
import com.example.security.sandbox.SandboxValidator.SandboxViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import dev.langchain4j.agent.tool.Tool;

@Component
public class GitHubClonerTool {

    private static final Logger log = LoggerFactory.getLogger(GitHubClonerTool.class);
    private static final ThreadLocal<Path> lastClonedPath = new ThreadLocal<>();

    private final SandboxValidator sandboxValidator;
    private final long cloneTimeoutSeconds;

    public GitHubClonerTool(SandboxValidator sandboxValidator,
            @Value("${audit.clone-timeout-seconds:300}") int cloneTimeoutSeconds) {
        this.sandboxValidator = sandboxValidator;
        this.cloneTimeoutSeconds = Math.max(60, Math.min(cloneTimeoutSeconds, 600));
    }

    @Tool("Clones a public GitHub repository into the security sandbox. Returns the absolute path of the cloned directory. Use this path for runStaticScan. Input: the repo URL, e.g. https://github.com/org/repo")
    public String cloneRepo(String repoUrl) {
        if (repoUrl == null || repoUrl.isBlank()) {
            return "Error: repoUrl must not be empty.";
        }
        String url = repoUrl.trim();
        if (!isAllowedGitHubUrl(url)) {
            return "Error: Only https://github.com/org/repo (or .git) URLs are allowed.";
        }
        Path sandboxBase = sandboxValidator.getSandboxBase();
        Path cloneDir;
        try {
            Files.createDirectories(sandboxBase);
            Path reposDir = sandboxBase.resolve("repos");
            Files.createDirectories(reposDir);
            String uniqueId = UUID.randomUUID().toString();
            cloneDir = reposDir.resolve(uniqueId);
            sandboxValidator.validateAndResolve(cloneDir.toString());
        } catch (SandboxViolationException e) {
            log.warn("Sandbox violation: {}", e.getMessage());
            return "Error: " + e.getMessage();
        } catch (IOException e) {
            log.error("Failed to create sandbox dir", e);
            return "Error: Failed to create sandbox directory: " + e.getMessage();
        }

        ProcessBuilder pb = new ProcessBuilder("git", "clone", "--depth", "1", url, cloneDir.toAbsolutePath().toString());
        pb.redirectErrorStream(true);
        try {
            Process p = pb.start();
            boolean finished = p.waitFor(cloneTimeoutSeconds, TimeUnit.SECONDS);
            String out = new String(p.getInputStream().readAllBytes());
            if (!finished) {
                p.destroyForcibly();
                return "Error: Clone timed out after " + cloneTimeoutSeconds + " seconds. Repo may be too large.";
            }
            int exit = p.exitValue();
            if (exit != 0) {
                return "Clone failed (exit " + exit + "): " + out;
            }
            lastClonedPath.set(cloneDir);
            return "Cloned successfully to: " + cloneDir.toAbsolutePath();
        } catch (IOException e) {
            log.error("Clone IO error", e);
            return "Clone failed: " + e.getMessage();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Clone interrupted: " + e.getMessage();
        }
    }

    private static boolean isAllowedGitHubUrl(String s) {
        if (s.length() > 500) return false;
        String lower = s.toLowerCase();
        if (!lower.startsWith("https://github.com/") && !lower.startsWith("http://github.com/")) return false;
        String path = lower.startsWith("https://") ? s.substring(19) : s.substring(18);
        if (path.isEmpty() || path.contains("..") || path.contains(" ")) return false;
        return path.matches("[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(\\.git)?/?");
    }

    public static Path getLastClonedPath() {
        return lastClonedPath.get();
    }

    public static void clearLastClonedPath() {
        Path p = lastClonedPath.get();
        lastClonedPath.remove();
        if (p != null && p.toFile().exists()) {
            try {
                org.apache.commons.io.FileUtils.deleteDirectory(p.toFile());
            } catch (IOException e) {
                log.warn("Cleanup failed for {}: {}", p, e.getMessage());
            }
        }
    }
}
