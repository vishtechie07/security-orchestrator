package com.example.security.controller;

import com.example.security.model.AuditResponse;
import com.example.security.model.SecurityReport;
import com.example.security.sandbox.SandboxValidator;
import com.example.security.service.SecurityOrchestratorService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuditController.class)
class AuditControllerTest {

    @Autowired
    MockMvc mvc;

    @MockBean
    SecurityOrchestratorService orchestratorService;

    @MockBean
    SandboxValidator sandboxValidator;

    @Test
    void audit_returns401_whenApiKeyMissing() throws Exception {
        mvc.perform(post("/v1/audit")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"https://github.com/org/repo\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").exists())
                .andExpect(jsonPath("$.code").value("MISSING_API_KEY"));
    }

    @Test
    void audit_returns401_whenApiKeyBlank() throws Exception {
        mvc.perform(post("/v1/audit")
                        .header("X-API-Key", "   ")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"https://github.com/org/repo\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("MISSING_API_KEY"));
    }

    @Test
    void audit_returns400_whenTargetMissing() throws Exception {
        mvc.perform(post("/v1/audit")
                        .header("X-API-Key", "sk-test")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MISSING_TARGET"));
    }

    @Test
    void audit_returns400_whenTargetNotGitHubUrl() throws Exception {
        mvc.perform(post("/v1/audit")
                        .header("X-API-Key", "sk-test")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"https://example.com\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_TARGET"));
    }

    @Test
    void audit_returns400_whenTargetHasPathTraversal() throws Exception {
        mvc.perform(post("/v1/audit")
                        .header("X-API-Key", "sk-test")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"https://github.com/org/../evil\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_TARGET"));
    }

    @Test
    void audit_returns200_withReport_whenValidRequest() throws Exception {
        AuditResponse response = new AuditResponse(
                new SecurityReport(50, List.of("file.js"), "Fix issues."),
                List.of());
        when(orchestratorService.runAudit(anyString(), anyString())).thenReturn(response);

        mvc.perform(post("/v1/audit")
                        .header("X-API-Key", "sk-test")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"https://github.com/org/repo\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.report.vulnerabilityScore").value(50))
                .andExpect(jsonPath("$.report.affectedFiles[0]").value("file.js"))
                .andExpect(jsonPath("$.auditSteps").isArray());
    }
}
