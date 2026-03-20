package com.example.security.model;

import java.util.List;

public record AuditStep(
    String toolName,
    String arguments,
    String result,
    List<FindingSummary> findings
) {
    public AuditStep(String toolName, String arguments, String result) {
        this(toolName, arguments, result, null);
    }
}
