package com.example.security.tools.semgrep;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SemgrepOutput(
    @JsonProperty("results") List<SemgrepResult> results,
    @JsonProperty("errors") List<Object> errors
) {
    @JsonCreator
    public SemgrepOutput {
        results = results != null ? results : List.of();
        errors = errors != null ? errors : List.of();
    }
}
