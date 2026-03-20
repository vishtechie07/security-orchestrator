package com.example.security.tools;

import com.example.security.model.FindingSummary;
import com.example.security.sandbox.SandboxValidator;
import com.example.security.sandbox.SandboxValidator.SandboxViolationException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.langchain4j.agent.tool.Tool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

@Component
public class SCATool {

    private static final String DO_NOT_RETRY = " Do not call runSCAScan again; use this in your report.";
    private static final Logger log = LoggerFactory.getLogger(SCATool.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final ThreadLocal<List<FindingSummary>> LAST_SCA_FINDINGS = new ThreadLocal<>();

    private final SandboxValidator sandboxValidator;

    public SCATool(SandboxValidator sandboxValidator) {
        this.sandboxValidator = sandboxValidator;
    }

    public static List<FindingSummary> getAndClearLastSCAFindings() {
        List<FindingSummary> list = LAST_SCA_FINDINGS.get();
        LAST_SCA_FINDINGS.remove();
        return list != null ? list : List.of();
    }

    @Tool("Scans dependencies for known vulnerabilities (SCA). Runs npm audit when package.json exists and pip-audit when requirements.txt exists. Input: the absolute path of the cloned repo (same path from cloneRepo). Call after cloneRepo.")
    public String runSCAScan(String localPath) {
        LAST_SCA_FINDINGS.remove();
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
            log.warn("SCA sandbox violation: {}", e.getMessage());
            return "Error: " + e.getMessage() + DO_NOT_RETRY;
        }

        List<FindingSummary> all = new ArrayList<>();
        List<Path> dirsWithPackageJson = new ArrayList<>();
        List<Path> dirsWithRequirementsTxt = new ArrayList<>();
        if (Files.isRegularFile(targetDir.resolve("package.json"))) dirsWithPackageJson.add(targetDir);
        if (Files.isRegularFile(targetDir.resolve("requirements.txt"))) dirsWithRequirementsTxt.add(targetDir);
        try (Stream<Path> list = Files.list(targetDir)) {
            list.filter(Files::isDirectory)
                    .filter(p -> !p.getFileName().toString().startsWith("."))
                    .forEach(sub -> {
                        if (Files.isRegularFile(sub.resolve("package.json"))) dirsWithPackageJson.add(sub);
                        if (Files.isRegularFile(sub.resolve("requirements.txt"))) dirsWithRequirementsTxt.add(sub);
                    });
        } catch (IOException e) {
            log.debug("SCA list dir: {}", e.getMessage());
        }
        for (Path dir : dirsWithPackageJson) {
            all.addAll(runNpmAudit(dir));
        }
        for (Path dir : dirsWithRequirementsTxt) {
            all.addAll(runPipAudit(dir));
        }

        if (all.isEmpty() && dirsWithPackageJson.isEmpty() && dirsWithRequirementsTxt.isEmpty()) {
            return "SCA: No package.json or requirements.txt found in repo root or subdirectories. SCA skipped (not an error).";
        }
        if (all.isEmpty()) {
            return "SCA scan completed. No vulnerable dependencies found.";
        }
        LAST_SCA_FINDINGS.set(Collections.unmodifiableList(all));
        return "SCA scan completed. " + all.size() + " vulnerable dependency finding(s).";
    }

    private List<FindingSummary> runNpmAudit(Path dir) {
        List<FindingSummary> out = new ArrayList<>();
        ProcessBuilder pb = new ProcessBuilder("npm", "audit", "--json");
        pb.directory(dir.toFile());
        pb.redirectErrorStream(true);
        try {
            Process p = pb.start();
            String stdout = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            p.waitFor(90, java.util.concurrent.TimeUnit.SECONDS);
            JsonNode root = OBJECT_MAPPER.readTree(stdout);
            if (root == null || root.has("error") || !root.has("vulnerabilities")) return out;
            JsonNode vulns = root.get("vulnerabilities");
            vulns.fields().forEachRemaining(entry -> {
                String pkg = entry.getKey();
                JsonNode v = entry.getValue();
                String severity = v.has("severity") ? v.get("severity").asText("unknown") : "unknown";
                JsonNode via = v.has("via") ? v.get("via") : null;
                String cve = "";
                String msg = "Vulnerable dependency: " + pkg;
                if (via != null && via.isArray() && via.size() > 0) {
                    JsonNode first = via.get(0);
                    if (first.isObject()) {
                        if (first.has("cve")) cve = first.get("cve").asText("");
                        if (first.has("title")) msg = first.get("title").asText(msg);
                    } else if (first.isTextual()) {
                        cve = first.asText();
                    }
                }
                String checkId = cve.isEmpty() ? ("npm-" + pkg) : cve;
                out.add(new FindingSummary("package.json (" + pkg + ")", checkId, msg, severity, null, null, List.of(), List.of()));
            });
        } catch (IOException e) {
            log.debug("npm audit failed: {}", e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return out;
    }

    private List<FindingSummary> runPipAudit(Path dir) {
        List<FindingSummary> out = new ArrayList<>();
        ProcessBuilder pb = new ProcessBuilder("pip-audit", "-f", "json");
        pb.directory(dir.toFile());
        pb.redirectErrorStream(true);
        try {
            Process p = pb.start();
            String stdout = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            p.waitFor(60, java.util.concurrent.TimeUnit.SECONDS);
            JsonNode root = OBJECT_MAPPER.readTree(stdout);
            if (root == null) return out;
            JsonNode vulns = root.has("vulnerabilities") ? root.get("vulnerabilities") : null;
            if (vulns == null || !vulns.isArray()) return out;
            for (JsonNode v : vulns) {
                String name = v.has("name") ? v.get("name").asText("") : "";
                String vulnId = v.has("id") ? v.get("id").asText("") : "";
                String desc = v.has("description") ? v.get("description").asText("Vulnerable: " + name) : "Vulnerable: " + name;
                String severity = v.has("fix_versions") ? "high" : "medium";
                out.add(new FindingSummary("requirements.txt (" + name + ")", vulnId, desc, severity, null, null, List.of(), List.of()));
            }
        } catch (IOException e) {
            log.debug("pip-audit failed (may not be installed): {}", e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return out;
    }
}
