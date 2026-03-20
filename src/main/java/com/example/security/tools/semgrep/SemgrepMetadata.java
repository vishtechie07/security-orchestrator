package com.example.security.tools.semgrep;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SemgrepMetadata(
    @JsonProperty("cwe") List<String> cwe,
    @JsonProperty("owasp") List<String> owasp
) {
    public SemgrepMetadata {
        cwe = cwe != null ? cwe : List.of();
        owasp = owasp != null ? owasp : List.of();
    }
}
