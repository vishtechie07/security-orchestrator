package com.example.security.tools;

import com.example.security.model.FindingSummary;
import com.example.security.sandbox.SandboxValidator;
import com.example.security.util.DockerPathUtil;
import com.example.security.sandbox.SandboxValidator.SandboxViolationException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.langchain4j.agent.tool.Tool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Component
public class GitleaksTool {

    private static final String DO_NOT_RETRY = " Do not call runSecretScan again; use this in your report.";
    private static final Logger log = LoggerFactory.getLogger(GitleaksTool.class);
    private final SandboxValidator sandboxValidator;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final boolean dockerEnabled;
    private final String dockerImage;
    private final String dockerSandboxVolume;

    private static final ThreadLocal<List<FindingSummary>> LAST_GITLEAKS_FINDINGS = new ThreadLocal<>();

    public GitleaksTool(
            SandboxValidator sandboxValidator,
            @Value("${gitleaks.docker.enabled:true}") boolean dockerEnabled,
            @Value("${gitleaks.docker.image:zricethezav/gitleaks:latest}") String dockerImage,
            @Value("${docker.sandbox-volume:}") String dockerSandboxVolume) {
        this.sandboxValidator = sandboxValidator;
        this.dockerEnabled = dockerEnabled;
        this.dockerImage = dockerImage != null && !dockerImage.isBlank() ? dockerImage.trim() : "zricethezav/gitleaks:latest";
        this.dockerSandboxVolume = dockerSandboxVolume != null && !dockerSandboxVolume.isBlank() ? dockerSandboxVolume.trim() : "";
    }

    public static List<FindingSummary> getAndClearLastGitleaksFindings() {
        List<FindingSummary> list = LAST_GITLEAKS_FINDINGS.get();
        LAST_GITLEAKS_FINDINGS.remove();
        return list != null ? list : List.of();
    }

    @Tool("Scans a local directory for secrets (API keys, passwords, tokens) using Gitleaks. Input: the absolute path of the cloned repo (same path returned by cloneRepo). Call after cloneRepo and use the path from clone output.")
    public String runSecretScan(String localPath) {
        LAST_GITLEAKS_FINDINGS.remove();
        if (localPath == null || localPath.isBlank()) {
            return "Error: localPath must not be empty.";
        }
        Path targetDir;
        try {
            targetDir = sandboxValidator.validateAndResolve(localPath.trim());
            if (!Files.isDirectory(targetDir)) {
                return "Error: path is not a directory: " + targetDir;
            }
        } catch (SandboxViolationException e) {
            log.warn("Gitleaks sandbox violation: {}", e.getMessage());
            return "Error: " + e.getMessage() + DO_NOT_RETRY;
        }

        if (dockerEnabled && isDockerAvailable()) {
            return runViaDocker(targetDir);
        }
        return runViaCli(targetDir);
    }

    private boolean isDockerAvailable() {
        try {
            Process p = new ProcessBuilder("docker", "info").redirectErrorStream(true).start();
            boolean ok = p.waitFor(10, TimeUnit.SECONDS) && p.exitValue() == 0;
            if (!ok && p.isAlive()) p.destroyForcibly();
            return ok;
        } catch (Exception e) {
            log.debug("Docker not available for Gitleaks: {}", e.getMessage());
            return false;
        }
    }

    private String runViaDocker(Path targetDir) {
        String mountSpec;
        String sourcePath;
        if (!dockerSandboxVolume.isBlank()) {
            mountSpec = dockerSandboxVolume + ":/tmp/security-sandbox";
            sourcePath = targetDir.toAbsolutePath().normalize().toString().replace('\\', '/');
        } else {
            mountSpec = DockerPathUtil.toVolumePath(targetDir) + ":/src";
            sourcePath = "/src";
        }
        List<String> cmd = List.of(
                "docker", "run", "--rm", "-v", mountSpec,
                dockerImage,
                "detect", "--source", sourcePath, "--no-git", "--report-format", "json", "--report-path", "-"
        );
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        try {
            Process p = pb.start();
            String stdout = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int exit = p.waitFor(120, TimeUnit.SECONDS) ? p.exitValue() : -1;
            if (!stdout.isBlank()) {
                List<FindingSummary> findings = parseGitleaksJson(stdout);
                if (!findings.isEmpty()) {
                    LAST_GITLEAKS_FINDINGS.set(Collections.unmodifiableList(findings));
                    return "Gitleaks scan completed. " + findings.size() + " secret(s) found.";
                }
            }
            if (exit == 0 || findingsListEmpty(stdout)) return "Gitleaks scan completed. No secrets found.";
            return "Gitleaks (Docker) finished. Exit " + exit + ". " + (stdout.length() > 500 ? stdout.substring(0, 500) + "..." : stdout);
        } catch (IOException e) {
            return "Gitleaks Docker error: " + e.getMessage() + DO_NOT_RETRY;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Gitleaks interrupted.";
        }
    }

    private String runViaCli(Path targetDir) {
        List<String> cmd = List.of(
                "gitleaks", "detect", "--source", targetDir.toAbsolutePath().toString(),
                "--no-git", "--report-format", "json", "--report-path", "-"
        );
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        try {
            Process p = pb.start();
            String stdout = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int exit = p.waitFor(120, TimeUnit.SECONDS) ? p.exitValue() : -1;
            if (exit == 1 && !stdout.isBlank()) {
                List<FindingSummary> findings = parseGitleaksJson(stdout);
                if (!findings.isEmpty()) {
                    LAST_GITLEAKS_FINDINGS.set(Collections.unmodifiableList(findings));
                    return "Gitleaks scan completed. " + findings.size() + " secret(s) found.";
                }
            }
            if (exit == 0) return "Gitleaks scan completed. No secrets found.";
            return "Gitleaks failed (exit " + exit + "). Install Gitleaks or use Docker. " + (stdout.length() > 300 ? stdout.substring(0, 300) + "..." : stdout) + DO_NOT_RETRY;
        } catch (IOException e) {
            if (e.getMessage() != null && (e.getMessage().contains("Cannot run program") || e.getMessage().contains("error=2"))) {
                return "Gitleaks not found. Install from https://github.com/gitleaks/gitleaks or set gitleaks.docker.enabled=true and start Docker." + DO_NOT_RETRY;
            }
            return "Gitleaks error: " + e.getMessage() + DO_NOT_RETRY;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Gitleaks interrupted.";
        }
    }

    private static boolean findingsListEmpty(String json) {
        String t = json.trim();
        return t.equals("[]") || t.startsWith("[]");
    }

    private List<FindingSummary> parseGitleaksJson(String raw) {
        List<FindingSummary> out = new ArrayList<>();
        try {
            String trimmed = raw.trim();
            int start = trimmed.indexOf('[');
            if (start < 0) return out;
            int end = trimmed.lastIndexOf(']');
            if (end <= start) return out;
            JsonNode arr = objectMapper.readTree(trimmed.substring(start, end + 1));
            if (!arr.isArray()) return out;
            for (JsonNode node : arr) {
                String file = node.has("File") ? node.get("File").asText("") : "";
                String ruleId = node.has("RuleID") ? node.get("RuleID").asText("") : "";
                String desc = node.has("Description") ? node.get("Description").asText("") : "Secret detected";
                int line = node.has("StartLine") ? node.get("StartLine").asInt(0) : 0;
                out.add(new FindingSummary(file, ruleId, desc, "SECRET", line > 0 ? line : null, null, List.of(), List.of()));
            }
        } catch (Exception e) {
            log.debug("Gitleaks JSON parse failed: {}", e.getMessage());
        }
        return out;
    }
}
