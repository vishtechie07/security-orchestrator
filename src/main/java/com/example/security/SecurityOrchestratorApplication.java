package com.example.security;

import com.example.security.sandbox.SandboxValidator;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.nio.file.Files;

@SpringBootApplication
public class SecurityOrchestratorApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityOrchestratorApplication.class, args);
    }

    @Bean
    ApplicationRunner ensureSandboxExists(SandboxValidator sandboxValidator) {
        return args -> {
            try {
                Files.createDirectories(sandboxValidator.getSandboxBase());
            } catch (Exception ignored) {}
        };
    }
}
