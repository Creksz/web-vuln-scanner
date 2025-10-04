package com.example.scanner;

import java.util.*;
import java.util.concurrent.*;

public class ScannerMain {
    public static void main(String[] args) {
        Scanner inputScanner = new Scanner(System.in);
        System.out.print("Enter target URL (e.g., http://localhost/dvwa/vulnerabilities/sqli/): ");
        String baseUrl = inputScanner.nextLine();
        System.out.print("Vuln type (SQLi or XSS): ");
        String vulnType = inputScanner.nextLine().toUpperCase();

        try {
            
            final HttpClientWrapper http = new HttpClientWrapper();
            final PayloadManager payloads = new PayloadManager();
            final VulnDetector detector = new VulnDetector();
            final ReportGenerator reporter = new ReportGenerator();
            List<VulnResult> results = Collections.synchronizedList(new ArrayList<>());

            List<String> payloadList = payloads.getPayloads(vulnType);
            if (payloadList.isEmpty()) {
                System.out.println("No payloads for type: " + vulnType);
                return;
            }

            ExecutorService executor = Executors.newFixedThreadPool(5);  
            List<Future<VulnResult>> futures = new ArrayList<>();
            for (final String payload : payloadList) { 
                futures.add(executor.submit(new ScanTask(http, baseUrl, payload, vulnType, detector)));
            }

            for (Future<VulnResult> future : futures) {
                try {
                    VulnResult result = future.get(10, TimeUnit.SECONDS); 
                    if (result != null) {
                        results.add(result);
                        System.out.println("Payload: " + payloads + " | Result: " + result.getType() + " (" + result.getSeverity() + ")");
                    }
                } catch (TimeoutException e) {
                    System.err.println("Task timeout: " + e.getMessage());
                } catch (ExecutionException | InterruptedException e) {
                    System.err.println("Thread error: " + e.getMessage());
                    e.printStackTrace();
                }
            }

            executor.shutdown();
            try {
                if (!executor.awaitTermination(30, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
            }

            if (!results.isEmpty()) {
                reporter.generateHTMLReport(results);
            } else {
                System.out.println("No results found.");
            }

        } catch (Exception e) {
            System.err.println("Main error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            inputScanner.close();
        }
    }

  
    private static class ScanTask implements Callable<VulnResult> {
        private final HttpClientWrapper http;
        private final String baseUrl;
        private final String payload;
        private final String vulnType;
        private final VulnDetector detector;

        public ScanTask(HttpClientWrapper http, String baseUrl, String payload, String vulnType, VulnDetector detector) {
            this.http = http;
            this.baseUrl = baseUrl;
            this.payload = payload;
            this.vulnType = vulnType;
            this.detector = detector;
        }

        @Override
        public VulnResult call() throws Exception {
            try {
                String response;
                Map<String, String> params = new HashMap<>();
                params.put("Submit", "Submit");

                if ("SQLI".equals(vulnType)) {
                    
                    params.put("id", "1" + payload);
                    response = http.sendGet(baseUrl, params);
                } else if ("XSS".equals(vulnType)) {
                    
                    params.put("name", payload); 
                    response = http.sendPost(baseUrl, params);
                } else {
                    throw new IllegalArgumentException("Unsupported vuln type: " + vulnType);
                }

            
                VulnResult result;
                if ("SQLI".equals(vulnType)) {
                    result = detector.detectSQLi(response);
                } else {
                    result = detector.detectXSS(response, payload);
                }
                return result;

            } catch (Exception e) {
                System.err.println("Scan task error for payload '" + payload + "': " + e.getMessage());
                return new VulnResult("Error", "High"); 
            }
        }
    }
}