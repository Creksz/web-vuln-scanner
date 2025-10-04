package com.example.scanner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;

public class ReportGenerator {
    private static final String REPORT_FILE = "scan-report.html";

    /**
     * 
     * @param results
     * @throws IOException
     */
    public void generateHTMLReport(List<VulnResult> results) throws IOException {
        if (results == null || results.isEmpty()) {
            System.out.println("No results to report.");
            return;
        }

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head>");
        html.append("<title>Web Vulnerability Scan Report</title>");
        html.append("<style>table {border-collapse: collapse; width: 100%;} th, td {border: 1px solid #ddd; padding: 8px; text-align: left;} th {background-color: #f2f2f2;} .high {color: red;} .medium {color: orange;} .low {color: green;}</style>");
        html.append("</head><body>");
        html.append("<h1>Web Vulnerability Scan Report</h1>");
        html.append("<p>Generated on: ").append(new java.util.Date()).append("</p>");
        html.append("<p>Total vulnerabilities detected: ").append(results.size()).append("</p>");

        // Table results
        html.append("<table>");
        html.append("<tr><th>Payload</th><th>Vulnerability Type</th><th>Severity</th><th>Status</th></tr>");

        int highCount = 0, mediumCount = 0, lowCount = 0;
        for (VulnResult result : results) {
            String severityClass = "";
            String status = "None";
            if ("High".equals(result.getSeverity())) {
                severityClass = " class='high'";
                highCount++;
                status = "Vulnerable!";
            } else if ("Medium".equals(result.getSeverity())) {
                severityClass = " class='medium'";
                mediumCount++;
            } else if ("Low".equals(result.getSeverity())) {
                severityClass = " class='low'";
                lowCount++;
            }

            html.append("<tr>");
            html.append("<td>").append(escapeHtml(result.getType())) // Placeholder payload; sesuaikan jika butuh
                .append("</td>");
            html.append("<td>").append(result.getType()).append("</td>");
            html.append("<td").append(severityClass).append(">").append(result.getSeverity()).append("</td>");
            html.append("<td>").append(status).append("</td>");
            html.append("</tr>");
        }
        html.append("</table>");

        // Summary
        html.append("<h2>Summary</h2>");
        html.append("<ul><li>High: ").append(highCount).append("</li>");
        html.append("<li>Medium: ").append(mediumCount).append("</li>");
        html.append("<li>Low/None: ").append(lowCount).append("</li></ul>");

        html.append("</body></html>");

       
        Files.write(Paths.get(REPORT_FILE), html.toString().getBytes(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        System.out.println("Report saved to: " + REPORT_FILE);
    }

    // Helper: Escape HTML untuk aman (hindari XSS di report)
    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

}