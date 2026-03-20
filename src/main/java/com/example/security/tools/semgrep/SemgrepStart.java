package com.example.security.tools.semgrep;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SemgrepStart(
    @JsonProperty("line") Integer line,
    @JsonProperty("col") Integer col
) {}
