package com.example.security.tools.semgrep;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SemgrepResult(
    @JsonProperty("path") String path,
    @JsonProperty("check_id") String checkId,
    @JsonProperty("start") SemgrepStart start,
    @JsonProperty("extra") SemgrepExtra extra
) {
    public SemgrepResult {
        extra = extra != null ? extra : new SemgrepExtra("", "", new SemgrepMetadata(List.of(), List.of()));
    }
    public String message() {
        return extra != null ? extra.message() : "";
    }

    public String severity() {
        return extra != null ? extra.severity() : "";
    }
}
