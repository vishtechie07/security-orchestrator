package com.example.security.service;

import com.example.security.agent.SecuritySupervisor;
import com.example.security.config.ChatModelFactory;
import com.example.security.sandbox.SandboxValidator;
import com.example.security.model.AuditResponse;
import com.example.security.model.AuditStep;
import com.example.security.model.FindingSummary;
import com.example.security.model.SecurityReport;
import com.example.security.tools.GitHubClonerTool;
import com.example.security.tools.GitleaksTool;
import com.example.security.tools.SCATool;
import com.example.security.tools.StaticScannerTool;
import com.example.security.tools.semgrep.SemgrepOutput;
import com.example.security.tools.semgrep.SemgrepResult;
import com.example.security.util.JsonUtil;
import com.fasterxml.jackson.databind.ObjectMapper;

import static com.example.security.tools.GitHubClonerTool.clearLastClonedPath;
import dev.langchain4j.model.chat.ChatLanguageModel;
import dev.langchain4j.service.AiServices;
import dev.langchain4j.service.Result;
import dev.langchain4j.service.tool.ToolExecution;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class SecurityOrchestratorService {

    private static final Logger log = LoggerFactory.getLogger(SecurityOrchestratorService.class);
    private final ChatModelFactory chatModelFactory;
    private final GitHubClonerTool githubClonerTool;
    private final StaticScannerTool staticScannerTool;
    private final GitleaksTool gitleaksTool;
    private final SCATool scaTool;
    private final SandboxValidator sandboxValidator;

    public SecurityOrchestratorService(
            ChatModelFactory chatModelFactory,
            GitHubClonerTool githubClonerTool,
            StaticScannerTool staticScannerTool,
            GitleaksTool gitleaksTool,
            SCATool scaTool,
            SandboxValidator sandboxValidator) {
        this.chatModelFactory = chatModelFactory;
        this.githubClonerTool = githubClonerTool;
        this.staticScannerTool = staticScannerTool;
        this.gitleaksTool = gitleaksTool;
        this.scaTool = scaTool;
        this.sandboxValidator = sandboxValidator;
    }

    public AuditResponse runAudit(String apiKey, String target) {
        List<AuditStep> steps = new ArrayList<>();
        try {
            ChatLanguageModel model = chatModelFactory.create(apiKey);
            SecuritySupervisor supervisor = AiServices.builder(SecuritySupervisor.class)
                    .chatLanguageModel(model)
                    .tools(githubClonerTool, staticScannerTool, gitleaksTool, scaTool)
                    .build();
            Result<SecurityReport> result = supervisor.audit(target);
            SecurityReport report = null;
            try {
                report = result != null ? result.content() : null;
            } catch (Exception e) {
                log.warn("Agent response could not be parsed as SecurityReport: {}", e.getMessage());
            }
            if (report == null) {
                report = new SecurityReport(0, List.of(), "Audit produced no report or response was not valid JSON.");
            }
            if (result != null) {
                try {
                    steps = mapToolExecutions(result.toolExecutions());
                } catch (Exception e) {
                    log.warn("Mapping tool executions failed: {}", e.getMessage());
                }
            }
            report = applyAffectedFilesFromFindings(report, steps);
            try {
                report = normalizeReportPaths(report);
            } catch (Exception e) {
                log.debug("Normalize report paths failed: {}", e.getMessage());
            }
            return new AuditResponse(report, steps);
        } catch (Exception e) {
            log.error("Audit failed for target {}: {}", target, e.getMessage(), e);
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            return new AuditResponse(
                    new SecurityReport(0, List.of(), "Audit failed: " + msg + ". Check logs and API key (Settings)."),
                    steps);
        } finally {
            try {
                clearLastClonedPath();
                StaticScannerTool.getAndClearLastSemgrepResults();
                GitleaksTool.getAndClearLastGitleaksFindings();
                SCATool.getAndClearLastSCAFindings();
            } catch (Exception e) {
                log.debug("Cleanup after audit: {}", e.getMessage());
            }
        }
    }

    private static final int RESULT_MAX_LENGTH = 4000;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private SecurityReport applyAffectedFilesFromFindings(SecurityReport report, List<AuditStep> steps) {
        if (report == null || steps == null) return report;
        List<String> paths = new ArrayList<>();
        for (AuditStep step : steps) {
            if (step.findings() != null) {
                for (FindingSummary f : step.findings()) {
                    if (f != null && f.path() != null && !f.path().isBlank())
                        paths.add(f.path().trim());
                }
            }
        }
        if (paths.isEmpty()) return report;
        SecurityReport withPaths = new SecurityReport(report.vulnerabilityScore(), paths, report.remediationSteps());
        return normalizeReportPaths(withPaths);
    }

    private SecurityReport normalizeReportPaths(SecurityReport report) {
        if (report == null || report.affectedFiles() == null || report.affectedFiles().isEmpty()) return report;
        String baseRaw = sandboxValidator.getSandboxBase().toAbsolutePath().normalize().toString().replace('\\', '/');
        final String base = baseRaw.endsWith("/") ? baseRaw : baseRaw + "/";
        List<String> normalized = report.affectedFiles().stream()
                .map(p -> {
                    String q = p == null ? "" : p.replace('\\', '/').trim();
                    if (q.isEmpty()) return q;
                    String r = (base.length() > 0 && q.startsWith(base)) ? q.substring(base.length()) : q;
                    String s = r.matches("repos/[^/]+/.*") ? r.replaceFirst("repos/[^/]+/", "") : r;
                    return s.isEmpty() ? p : s;
                })
                .distinct()
                .toList();
        return new SecurityReport(report.vulnerabilityScore(), normalized, report.remediationSteps());
    }

    private List<AuditStep> mapToolExecutions(List<ToolExecution> executions) {
        if (executions == null) return List.of();
        int lastStaticIdx = -1, lastSecretIdx = -1, lastSCAIdx = -1;
        for (int i = 0; i < executions.size(); i++) {
            String name = executions.get(i).request() != null ? executions.get(i).request().name() : "";
            if ("runStaticScan".equals(name)) lastStaticIdx = i;
            else if ("runSecretScan".equals(name)) lastSecretIdx = i;
            else if ("runSCAScan".equals(name)) lastSCAIdx = i;
        }
        List<AuditStep> out = new ArrayList<>();
        for (int i = 0; i < executions.size(); i++) {
            out.add(toAuditStep(executions.get(i), i == lastStaticIdx, i == lastSecretIdx, i == lastSCAIdx));
        }
        return out;
    }

    private AuditStep toAuditStep(ToolExecution exec, boolean useStoredStatic, boolean useStoredSecret, boolean useStoredSCA) {
        String toolName = exec.request() != null ? exec.request().name() : "?";
        String stepArgs = exec.request() != null ? exec.request().arguments() : "";
        String stepResult = exec.result() != null ? exec.result() : "";
        List<FindingSummary> stepFindings = null;
        if ("runStaticScan".equals(toolName)) {
            if (useStoredStatic) {
                List<SemgrepResult> stored = StaticScannerTool.getAndClearLastSemgrepResults();
                if (!stored.isEmpty()) {
                    stepFindings = stored.stream().limit(100).map(SecurityOrchestratorService::toFindingSummary).collect(Collectors.toList());
                }
            }
            if (stepFindings == null) stepFindings = parseSemgrepFindings(stepResult);
            if (stepFindings != null && stepResult.length() > RESULT_MAX_LENGTH) {
                stepResult = stepResult.substring(0, RESULT_MAX_LENGTH) + "\n... (truncated; " + stepFindings.size() + " findings in breakdown)";
            }
        } else if ("runSecretScan".equals(toolName) && useStoredSecret) {
            stepFindings = GitleaksTool.getAndClearLastGitleaksFindings();
            if (stepFindings != null && stepFindings.isEmpty()) stepFindings = null;
        } else if ("runSCAScan".equals(toolName) && useStoredSCA) {
            stepFindings = SCATool.getAndClearLastSCAFindings();
            if (stepFindings != null && stepFindings.isEmpty()) stepFindings = null;
        }
        return new AuditStep(toolName, stepArgs, stepResult, stepFindings);
    }

    private static List<FindingSummary> parseSemgrepFindings(String result) {
        if (result == null || result.isBlank()) return null;
        String normalized = result.replaceFirst("^Semgrep\\s*\\(exit\\s*\\d+\\)\\s*:?\\s*", "").trim();
        String json = JsonUtil.extractObject(normalized);
        if (json == null) json = JsonUtil.extractObject(result);
        if (json != null) {
            try {
                SemgrepOutput out = OBJECT_MAPPER.readValue(json, SemgrepOutput.class);
                if (out.results() != null && !out.results().isEmpty()) {
                    return out.results().stream()
                            .limit(100)
                            .map(SecurityOrchestratorService::toFindingSummary)
                            .collect(Collectors.toList());
                }
            } catch (Exception ignored) { }
        }
        return parseFormattedSemgrepLines(result);
    }

    private static final Pattern FORMATTED_LINE = Pattern.compile("path=(.+?)\\s+check_id=([^\\s]+)\\s+severity=([^\\s]+)\\s+message=(.+)");

    private static List<FindingSummary> parseFormattedSemgrepLines(String result) {
        if (result == null || !result.contains("Semgrep findings (")) return null;
        String[] lines = result.split("\n");
        List<FindingSummary> list = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            Matcher m = FORMATTED_LINE.matcher(lines[i].trim());
            if (m.matches()) {
                list.add(new FindingSummary(
                        m.group(1).trim(), m.group(2).trim(), m.group(4).trim(), m.group(3).trim(),
                        null, null, List.of(), List.of()));
            }
        }
        return list.isEmpty() ? null : list;
    }

    private static FindingSummary toFindingSummary(SemgrepResult r) {
        String path = r.path();
        String checkId = r.checkId();
        String message = r.extra() != null ? r.extra().message() : "";
        String severity = r.extra() != null ? r.extra().severity() : null;
        Integer line = r.start() != null ? r.start().line() : null;
        Integer col = r.start() != null ? r.start().col() : null;
        List<String> cwe = List.of();
        List<String> owasp = List.of();
        if (r.extra() != null && r.extra().metadata() != null) {
            cwe = r.extra().metadata().cwe();
            owasp = r.extra().metadata().owasp();
        }
        return new FindingSummary(path, checkId, message, severity, line, col, cwe, owasp);
    }
}
