package com.example.security.model;

import java.util.List;

public record SecurityReport(
    int vulnerabilityScore,
    List<String> affectedFiles,
    String remediationSteps
) {
    public SecurityReport {
        affectedFiles = affectedFiles != null ? List.copyOf(affectedFiles) : List.of();
    }
}
