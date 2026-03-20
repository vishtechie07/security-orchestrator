package com.example.security.tools;

import com.example.security.sandbox.SandboxValidator;
import com.example.security.sandbox.SandboxValidator.SandboxViolationException;
import com.example.security.tools.semgrep.SemgrepOutput;
import com.example.security.tools.semgrep.SemgrepResult;
import com.example.security.util.DockerPathUtil;
import com.example.security.util.JsonUtil;
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
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Component
public class StaticScannerTool {

    private static final String DO_NOT_RETRY = " Do not call runStaticScan again; use this in your report.";
    private static final Logger log = LoggerFactory.getLogger(StaticScannerTool.class);
    private static final boolean WINDOWS = System.getProperty("os.name", "").toLowerCase().contains("win");

    private final SandboxValidator sandboxValidator;
    private final String semgrepCommand;
    private final String bundledDir;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final boolean dockerEnabled;
    private final String dockerImage;
    private final String dockerSandboxVolume;

    private static final ThreadLocal<List<SemgrepResult>> LAST_SEMGREP_RESULTS = new ThreadLocal<>();

    public StaticScannerTool(
            SandboxValidator sandboxValidator,
            @Value("${semgrep.command:semgrep}") String semgrepCommand,
            @Value("${semgrep.bundled-dir:}") String bundledDir,
            @Value("${semgrep.docker.enabled:true}") boolean dockerEnabled,
            @Value("${semgrep.docker.image:semgrep/semgrep:latest}") String dockerImage,
            @Value("${docker.sandbox-volume:}") String dockerSandboxVolume) {
        this.sandboxValidator = sandboxValidator;
        this.semgrepCommand = semgrepCommand != null && !semgrepCommand.isBlank() ? semgrepCommand.trim() : "semgrep";
        this.bundledDir = bundledDir != null && !bundledDir.isBlank() ? bundledDir.trim() : "";
        this.dockerEnabled = dockerEnabled;
        this.dockerImage = dockerImage != null && !dockerImage.isBlank() ? dockerImage.trim() : "semgrep/semgrep:latest";
        this.dockerSandboxVolume = dockerSandboxVolume != null && !dockerSandboxVolume.isBlank() ? dockerSandboxVolume.trim() : "";
    }

    private static final String DOCKER_HINT = " Start Docker Desktop and re-run the audit to use Semgrep via Docker, or run scripts/setup-semgrep.ps1 (Windows) / scripts/setup-semgrep.sh (Linux/macOS), or pip install semgrep.";

    private boolean isDockerAvailable() {
        String[] dockerCmd = resolveDockerCommand();
        for (String docker : dockerCmd) {
            if (docker == null || docker.isBlank()) continue;
            try {
                Process p = new ProcessBuilder(docker, "info").redirectErrorStream(true).start();
                boolean finished = p.waitFor(10, TimeUnit.SECONDS);
                if (!finished) {
                    p.destroyForcibly();
                    continue;
                }
                if (p.exitValue() != 0) continue;
                if (dockerCmd.length > 1) dockerCommandForRun = docker;
                return true;
            } catch (Exception ignored) { }
        }
        log.info("Semgrep: Docker not available (start Docker Desktop and ensure 'docker' is in PATH). Using local Semgrep.");
        return false;
    }

    private String dockerCommandForRun = "docker";

    private String[] resolveDockerCommand() {
        if (WINDOWS) {
            String pf = System.getenv("ProgramFiles");
            if (pf != null && !pf.isBlank()) {
                Path exe = Path.of(pf, "Docker", "Docker", "resources", "bin", "docker.exe");
                if (Files.isRegularFile(exe)) {
                    return new String[] { "docker", exe.toAbsolutePath().toString() };
                }
            }
        }
        return new String[] { "docker" };
    }

    private ScanResult runSemgrepViaDocker(Path targetDir) {
        String mountSpec;
        String scanPath;
        if (!dockerSandboxVolume.isBlank()) {
            mountSpec = dockerSandboxVolume + ":/tmp/security-sandbox";
            scanPath = targetDir.toAbsolutePath().normalize().toString().replace('\\', '/');
        } else {
            mountSpec = DockerPathUtil.toVolumePath(targetDir) + ":/src";
            scanPath = "/src";
        }
        List<String> cmd = new ArrayList<>();
        cmd.add(dockerCommandForRun);
        cmd.addAll(List.of("run", "--rm", "-v", mountSpec, dockerImage, "semgrep", "scan", "--json", scanPath));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        try {
            Process p = pb.start();
            String stdout = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int exit = p.waitFor();
            return ScanResult.success(parseSemgrepOutput(stdout, exit));
        } catch (IOException e) {
            log.warn("Semgrep via Docker failed: {}", e.getMessage());
            return ScanResult.failure("Semgrep (Docker): " + e.getMessage() + ". Set semgrep.docker.enabled=false to use local Semgrep." + DO_NOT_RETRY, false);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ScanResult.failure("Semgrep (Docker) interrupted.", false);
        }
    }

    private String resolveEffectiveCommand() {
        if (bundledDir.isBlank()) return semgrepCommand;
        Path base = Path.of(System.getProperty("user.dir", ".")).resolve(bundledDir).normalize();
        Path exe = base.resolve(WINDOWS ? "semgrep.exe" : "semgrep");
        if (Files.isRegularFile(exe)) {
            return exe.toAbsolutePath().toString();
        }
        return semgrepCommand;
    }

    @Tool("Runs static code analysis with Semgrep on a local directory path (must be under the security sandbox, e.g. a path returned by cloneRepo). Input: absolute path to the cloned repo directory.")
    public String runStaticScan(String localPath) {
        if (localPath == null || localPath.isBlank()) {
            return "Error: localPath must not be empty.";
        }
        Path validated;
        try {
            validated = sandboxValidator.validateAndResolve(localPath.trim());
        } catch (SandboxViolationException e) {
            log.warn("Sandbox violation: {}", e.getMessage());
            return "Error: " + e.getMessage();
        }
        if (!validated.toFile().isDirectory()) {
            return "Error: Path is not a directory: " + validated;
        }

        if (dockerEnabled && isDockerAvailable()) {
            log.info("Semgrep: running via Docker ({})", dockerImage);
            ScanResult dockerResult = runSemgrepViaDocker(validated);
            if (dockerResult.success()) {
                return dockerResult.output();
            }
            log.warn("Semgrep via Docker failed, falling back to local: {}", dockerResult.output());
        } else if (dockerEnabled) {
            log.info("Semgrep: Docker skipped (not available). Using local/bundled Semgrep.");
        }

        Path jsonOut = null;
        try {
            jsonOut = sandboxValidator.getSandboxBase().resolve("semgrep-" + UUID.randomUUID() + ".json");
            Files.createDirectories(sandboxValidator.getSandboxBase());
        } catch (IOException e) {
            log.warn("Could not create semgrep output path: {}", e.getMessage());
        }

        String effectiveCommand = resolveEffectiveCommand();
        List<String> primaryCommand = buildSemgrepCommand(effectiveCommand, jsonOut, validated);
        ScanResult result = runSemgrepCommand(primaryCommand, jsonOut, validated);
        if (result.success()) {
            return result.output();
        }
        if (result.notFound() && !effectiveCommand.contains("python") && !effectiveCommand.contains("py ")) {
            List<String> fallbackCommand = buildSemgrepCommand("python -m semgrep", jsonOut, validated);
            ScanResult fallback = runSemgrepCommand(fallbackCommand, jsonOut, validated);
            if (fallback.success()) return fallback.output();
            if (WINDOWS) {
                List<String> pyFallback = buildSemgrepCommand("py -m semgrep", jsonOut, validated);
                ScanResult pyResult = runSemgrepCommand(pyFallback, jsonOut, validated);
                if (pyResult.success()) return pyResult.output();
            }
        }
        return result.output();
    }

    private List<String> buildSemgrepCommand(String base, Path jsonOutputFile, Path targetDir) {
        List<String> cmd = new ArrayList<>(List.of(base.trim().split("\\s+")));
        cmd.add("scan");
        cmd.add("--json");
        if (jsonOutputFile != null) {
            cmd.add("--json-output=" + jsonOutputFile.toAbsolutePath());
        }
        cmd.add(targetDir.toAbsolutePath().toString());
        return cmd;
    }

    private ScanResult runSemgrepCommand(List<String> command, Path jsonOutputFile, Path targetDir) {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        try {
            Process p = pb.start();
            String stdout = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int exit = p.waitFor();

            if (jsonOutputFile != null && Files.isRegularFile(jsonOutputFile)) {
                try {
                    String fileContent = Files.readString(jsonOutputFile, StandardCharsets.UTF_8);
                    if (!fileContent.isBlank() && fileContent.trim().startsWith("{")) {
                        String result = parseSemgrepOutput(fileContent, exit);
                        return ScanResult.success(result);
                    }
                } catch (IOException e) {
                    log.warn("Could not read Semgrep JSON output file: {}", e.getMessage());
                } finally {
                    try { Files.deleteIfExists(jsonOutputFile); } catch (IOException ignored) { }
                }
            }

            if (exit != 0 && stdout.isBlank()) {
                return ScanResult.failure("Semgrep failed: exit " + exit + "." + DOCKER_HINT + DO_NOT_RETRY, false);
            }
            String parsed = parseSemgrepOutput(stdout, exit);
            if (exit != 0 && (stdout.contains("No module named semgrep") || stdout.contains("not installed"))) {
                return ScanResult.failure("Semgrep (local) failed: " + (parsed.length() > 500 ? parsed.substring(0, 500) + "..." : parsed) + "." + DOCKER_HINT + DO_NOT_RETRY, false);
            }
            return ScanResult.success(parsed);
        } catch (IOException e) {
            if (jsonOutputFile != null) {
                try { Files.deleteIfExists(jsonOutputFile); } catch (IOException ignored) { }
            }
            String msg = e.getMessage() != null ? e.getMessage() : "";
            boolean notFound = msg.contains("Cannot run program") || msg.contains("error=2") || msg.contains("No such file");
            log.warn("Semgrep executable error: {}", msg);
            if (notFound) {
                return ScanResult.failure("TOOL_UNAVAILABLE: Semgrep not on PATH (Docker was not used)." + DOCKER_HINT + DO_NOT_RETRY, true);
            }
            return ScanResult.failure("Semgrep error: " + msg + DOCKER_HINT + DO_NOT_RETRY, false);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ScanResult.failure("Semgrep interrupted: " + e.getMessage(), false);
        }
    }

    private record ScanResult(boolean success, String output, boolean notFound) {
        static ScanResult success(String output) { return new ScanResult(true, output, false); }
        static ScanResult failure(String output, boolean notFound) { return new ScanResult(false, output, notFound); }
    }

    public static List<SemgrepResult> getAndClearLastSemgrepResults() {
        List<SemgrepResult> list = LAST_SEMGREP_RESULTS.get();
        LAST_SEMGREP_RESULTS.remove();
        return list != null ? list : List.of();
    }

    private String parseSemgrepOutput(String raw, int exitCode) {
        LAST_SEMGREP_RESULTS.remove();
        String trimmed = raw != null ? raw.trim() : "";
        if (trimmed.isEmpty()) {
            return "Semgrep finished (exit " + exitCode + "). No output.";
        }
        String json = trimmed.startsWith("{") ? trimmed : JsonUtil.extractObject(trimmed);
        if (json == null) {
            return "Semgrep (exit " + exitCode + "): " + (trimmed.length() > 2500 ? trimmed.substring(0, 2500) + "..." : trimmed);
        }
        try {
            SemgrepOutput output = objectMapper.readValue(json, SemgrepOutput.class);
            if (output.results() == null || output.results().isEmpty()) {
                return "Semgrep finished (exit " + exitCode + "). No findings.";
            }
            LAST_SEMGREP_RESULTS.set(Collections.unmodifiableList(new ArrayList<>(output.results())));
            return "Semgrep scan completed. " + output.results().size() + " finding(s).";
        } catch (IOException e) {
            return "Semgrep (exit " + exitCode + "), output not valid JSON: " + (trimmed.length() > 1500 ? trimmed.substring(0, 1500) + "..." : trimmed);
        }
    }

}
