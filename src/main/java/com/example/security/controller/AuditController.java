package com.example.security.controller;

import com.example.security.model.AuditResponse;
import com.example.security.model.ErrorResponse;
import com.example.security.model.SecurityReport;
import com.example.security.service.SecurityOrchestratorService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/v1")
public class AuditController {

    private static final String API_KEY_HEADER = "X-API-Key";

    private final SecurityOrchestratorService orchestratorService;

    public AuditController(SecurityOrchestratorService orchestratorService) {
        this.orchestratorService = orchestratorService;
    }

    @PostMapping("/audit")
    public ResponseEntity<?> audit(
            @RequestHeader(value = API_KEY_HEADER, required = false) String apiKey,
            @RequestBody AuditRequest request) {
        if (apiKey == null || apiKey.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).contentType(MediaType.APPLICATION_JSON)
                    .body(new ErrorResponse("Missing or invalid API key. Add it in Settings.", "MISSING_API_KEY"));
        }
        String target = request != null && request.target() != null ? request.target().trim() : "";
        if (target.isBlank()) {
            return ResponseEntity.badRequest().contentType(MediaType.APPLICATION_JSON)
                    .body(new ErrorResponse("Missing or empty 'target' in request body", "MISSING_TARGET"));
        }
        if (!isGitHubRepoUrl(target)) {
            return ResponseEntity.badRequest().contentType(MediaType.APPLICATION_JSON)
                    .body(new ErrorResponse("Only https://github.com/org/repo URLs are supported.", "INVALID_TARGET"));
        }
        try {
            AuditResponse response = orchestratorService.runAudit(apiKey, target);
            return ResponseEntity.ok(response);
        } catch (Throwable t) {
            org.slf4j.LoggerFactory.getLogger(AuditController.class).error("Audit request failed", t);
            String msg = t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName();
            return ResponseEntity.ok(new AuditResponse(
                    new SecurityReport(0, List.of(), "Audit failed: " + msg + ". Check API key (Settings) and backend logs."),
                    List.of()));
        }
    }

    public record AuditRequest(String target) {}

    private static boolean isGitHubRepoUrl(String s) {
        if (s == null || s.isBlank() || s.length() > 500) return false;
        String lower = s.toLowerCase();
        if (!lower.startsWith("https://github.com/") && !lower.startsWith("http://github.com/")) return false;
        String path = lower.startsWith("https://") ? s.substring(19) : s.substring(18);
        if (path.isEmpty() || path.contains("..") || path.contains(" ")) return false;
        return path.matches("[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(\\.git)?/?");
    }
}
