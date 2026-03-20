package com.example.security.sandbox;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class SandboxValidatorTest {

    @TempDir
    Path tempDir;

    SandboxValidator validator;

    @BeforeEach
    void setUp() {
        validator = new SandboxValidator(tempDir.toAbsolutePath().toString());
    }

    @Test
    void validateAndResolve_throwsWhenPathNull() {
        assertThrows(SandboxValidator.SandboxViolationException.class,
                () -> validator.validateAndResolve(null));
    }

    @Test
    void validateAndResolve_throwsWhenPathBlank() {
        assertThrows(SandboxValidator.SandboxViolationException.class,
                () -> validator.validateAndResolve("   "));
    }

    @Test
    void validateAndResolve_acceptsPathInsideSandbox() throws Exception {
        Path child = tempDir.resolve("repos").resolve("abc");
        Files.createDirectories(child);
        Path resolved = validator.validateAndResolve(child.toAbsolutePath().toString());
        assertNotNull(resolved);
        assertTrue(resolved.startsWith(tempDir.toAbsolutePath().normalize()));
    }

    @Test
    void getSandboxBase_returnsConfiguredBase() {
        Path base = validator.getSandboxBase();
        assertEquals(tempDir.toAbsolutePath().normalize(), base);
    }

    @Test
    void isAllowed_returnsFalseForPathOutsideSandbox() {
        boolean allowed = validator.isAllowed("/etc/passwd");
        assertFalse(allowed);
    }

    @Test
    void isAllowed_returnsTrueForPathInsideSandbox() throws Exception {
        Path child = tempDir.resolve("repos").resolve("x");
        Files.createDirectories(child);
        assertTrue(validator.isAllowed(child.toAbsolutePath().toString()));
    }
}
