package com.example.scanner;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import java.util.regex.Pattern;

public class VulnDetector {
    // Patterns for SQLi detection
    private static final Pattern SQL_ERROR_PATTERN = Pattern.compile(
        "SQL.*error|mysql_fetch|ORA-\\d+|warning.*mysql|PostgreSQL.*error|syntax error.*near",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SQL_SUCCESS_PATTERN = Pattern.compile(
        "admin|password|username|user|root|\\b[0-9a-f]{32}\\b",  
        Pattern.CASE_INSENSITIVE
    );

    // Patterns for XSS: Malicious payload indicators
    private static final Pattern XSS_MALICIOUS_PAYLOAD = Pattern.compile(
        "<script|alert\\$|onload=|onerror=|javascript:|svg|img.*onerror|body.*onload",
        Pattern.CASE_INSENSITIVE
    );

    // Patterns untuk XSS execution response
    private static final Pattern XSS_EXECUTION_PATTERN = Pattern.compile(
        "<script.*>.*alert|onload=.*alert|onerror=.*alert|javascript:.*alert",
        Pattern.CASE_INSENSITIVE
    );

    /**
     * ).
     * @param response
     * @return 
     */
    public VulnResult detectSQLi(String response) {
        if (response == null || response.isEmpty()) {
            return new VulnResult("None", "Low");
        }

        // Cek error patterns (high severity)
        if (SQL_ERROR_PATTERN.matcher(response).find()) {
            return new VulnResult("SQLi", "High");
        }

       
        if (SQL_SUCCESS_PATTERN.matcher(response).find()) {
            return new VulnResult("SQLi", "Medium");
        }

        // No vuln
        return new VulnResult("None", "Low");
    }

    /**
     * 
     * @param response 
     * @param payload 
     * @return 
     */
    public VulnResult detectXSS(String response, String payload) {
        if (response == null || response.isEmpty() || payload == null) {
            return new VulnResult("None", "Low");
        }

        // Parse HTML dengan Jsoup
        Document doc = Jsoup.parse(response);
        String bodyText = doc.body().text();  // Clean text
        String bodyHtml = doc.body().html();  // Raw HTML

        // Step 1: Cek jika payload malicious (berisi indicators XSS)
        boolean isMaliciousPayload = XSS_MALICIOUS_PAYLOAD.matcher(payload).find();

        // Step 2: Cek refleksi payload di response
        boolean isReflected = bodyText.contains(payload) || bodyHtml.contains(payload);

        // Step 3: Cek execution patterns di response (independen dari payload)
        boolean hasExecution = XSS_EXECUTION_PATTERN.matcher(bodyHtml).find();

        // Logic deteksi:
        if (isMaliciousPayload && isReflected) {
            // Malicious payload reflected → High XSS (clear vuln)
            return new VulnResult("XSS", "High");
        } else if (hasExecution) {
            // Execution code di response (e.g., alert muncul) → Medium (potential)
            return new VulnResult("XSS", "Medium");
        } else if (isReflected && !isMaliciousPayload) {
            // Benign input reflected → No vuln (normal echo, seperti di test)
            return new VulnResult("None", "Low");
        }

        // No vuln
        return new VulnResult("None", "Low");
    }


}