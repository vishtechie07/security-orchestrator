package com.example.security.config;

import com.example.security.model.AuditResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GlobalExceptionHandlerTest {

    @Mock
    HttpServletRequest request;

    final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handleAny_returns200WithAuditResponse() {
        when(request.getRequestURI()).thenReturn("/v1/audit");
        ResponseEntity<AuditResponse> res = handler.handleAny(new RuntimeException("test error"), request);
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(res.getBody()).isNotNull();
        assertThat(res.getBody().report().remediationSteps()).contains("Audit failed");
        assertThat(res.getBody().report().remediationSteps()).contains("test error");
    }

    @Test
    void handleAny_handlesNullMessage() {
        when(request.getRequestURI()).thenReturn("/v1/audit");
        ResponseEntity<AuditResponse> res = handler.handleAny(new NullPointerException(), request);
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(res.getBody().report().remediationSteps()).contains("NullPointerException");
    }
}
