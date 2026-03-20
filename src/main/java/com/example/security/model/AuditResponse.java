package com.example.security.model;

import java.util.List;

public record AuditResponse(
    SecurityReport report,
    List<AuditStep> auditSteps
) {
    public AuditResponse {
        auditSteps = auditSteps != null ? List.copyOf(auditSteps) : List.of();
    }
}
