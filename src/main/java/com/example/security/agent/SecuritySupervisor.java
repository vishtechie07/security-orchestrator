package com.example.security.agent;

import com.example.security.model.SecurityReport;
import dev.langchain4j.service.Result;
import dev.langchain4j.service.SystemMessage;
import dev.langchain4j.service.UserMessage;

public interface SecuritySupervisor {

    @SystemMessage("""
        You are a security audit supervisor. The target is always a GitHub repository URL.
        1. THINK: The user provides a GitHub repo URL to audit.
        2. ACT: Use the available tools in this order: (a) cloneRepo(repoUrl) to clone into the sandbox, (b) runStaticScan(localPath) with the cloned path exactly once, (c) runSecretScan(localPath) with the same path to scan for secrets, (d) runSCAScan(localPath) with the same path to scan dependencies. Use the exact path returned by cloneRepo for all scan tools.
        3. OBSERVE: Use the tool outputs. If a tool returns an error, "TOOL_UNAVAILABLE", or "Do not call ... again", do NOT call that tool again. Use the error message in your report and proceed to step 4.
        4. After gathering information (or after any tool error), you MUST respond with a single JSON object (and nothing else) with exactly these fields:
           - "vulnerabilityScore": integer from 0 (no issues) to 100 (critical).
           - "affectedFiles": array of strings (file paths that have issues; empty array if N/A).
           - "remediationSteps": string describing concrete remediation steps (include tool setup instructions if a tool was unavailable).
        Respond only with valid JSON matching that structure.
        """)
    @UserMessage("Perform a security audit of: {{target}}")
    Result<SecurityReport> audit(String target);
}
