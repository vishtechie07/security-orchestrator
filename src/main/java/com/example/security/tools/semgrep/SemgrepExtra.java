package com.example.security.tools.semgrep;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SemgrepExtra(
    @JsonProperty("message") String message,
    @JsonProperty("severity") String severity,
    @JsonProperty("metadata") SemgrepMetadata metadata
) {
    public SemgrepExtra {
        message = message != null ? message : "";
        severity = severity != null ? severity : "";
        metadata = metadata != null ? metadata : new SemgrepMetadata(List.of(), List.of());
    }
}
