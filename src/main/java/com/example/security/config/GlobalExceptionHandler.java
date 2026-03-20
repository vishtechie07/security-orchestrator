package com.example.security.config;

import com.example.security.model.AuditResponse;
import com.example.security.model.SecurityReport;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Throwable.class)
    public ResponseEntity<AuditResponse> handleAny(Throwable t, HttpServletRequest request) {
        String path = request != null ? request.getRequestURI() : "";
        log.error("Unhandled error for {}: {}", path, t.getMessage(), t);
        String msg = t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName();
        if (msg.length() > 500) msg = msg.substring(0, 500);
        msg = msg.replace("\"", "'").replace("\n", " ");
        AuditResponse body = new AuditResponse(
                new SecurityReport(0, List.of(), "Audit failed: " + msg + ". Check API key (Settings) and backend logs."),
                List.of());
        return ResponseEntity.ok(body);
    }
}
