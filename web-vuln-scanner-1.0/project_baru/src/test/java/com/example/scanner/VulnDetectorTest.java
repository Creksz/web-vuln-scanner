package com.example.scanner;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class VulnDetectorTest {
    private VulnDetector detector;

    @BeforeEach
    public void setUp() {
        detector = new VulnDetector();
    }

    @Test
    public void testDetectSQLiError() {
        String response = "SQL syntax error near ' OR 1=1--'";
        VulnResult result = detector.detectSQLi(response);
        assertEquals("SQLi", result.getType());
        assertEquals("High", result.getSeverity());
    }

    @Test
    public void testDetectSQLiNoVuln() {
        String response = "Normal page content";
        VulnResult result = detector.detectSQLi(response);
        assertEquals("None", result.getType());
    }

    @Test
    public void testDetectXSSReflected() {
        String payload = "<script>alert('XSS')</script>";
        String response =" This is" + payload;
        VulnResult result = detector.detectXSS(response, payload);
        assertEquals("XSS", result.getType());
    }

    @Test
    public void testDetectXSSNoVuln() {
        String payload = "normal input";
        String response = "Hello normal input";
        VulnResult result = detector.detectXSS(response, payload);
        assertEquals("None", result.getType());
    }
}