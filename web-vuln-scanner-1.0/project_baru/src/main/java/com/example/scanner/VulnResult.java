package com.example.scanner;

/**
 * Model class untuk hasil deteksi vulnerability.
 */
public class VulnResult {
    private String type;      // e.g., "SQLi", "XSS", "None"
    private String severity;  // e.g., "High", "Medium", "Low"

    /**
     * Constructor.
     * @param type Tipe vulnerability.
     * @param severity Level severity.
     */
    public VulnResult(String type, String severity) {
        this.type = type;
        this.severity = severity;
    }

    // Getters (dipanggil di ReportGenerator dan console)
    public String getType() {
        return type;
    }

    public String getSeverity() {
        return severity;
    }

    // toString untuk debug (opsional)
    @Override
    public String toString() {
        return "VulnResult{type='" + type + "', severity='" + severity + "'}";
    }
}