package com.example.security.model;

import java.util.List;

public record FindingSummary(
    String path,
    String checkId,
    String message,
    String severity,
    Integer line,
    Integer col,
    List<String> cwe,
    List<String> owasp
) {
    public FindingSummary {
        cwe = cwe != null ? List.copyOf(cwe) : List.of();
        owasp = owasp != null ? List.copyOf(owasp) : List.of();
    }
}
