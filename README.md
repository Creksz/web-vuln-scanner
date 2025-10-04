# Web Vulnerability Scanner

A simple, educational web vulnerability scanner built with Java 8, Maven, Apache HttpClient, and Jsoup. It detects SQL Injection (SQLi) and Cross-Site Scripting (XSS) vulnerabilities by sending payloads to a target URL and analyzing HTTP responses. Designed for learning and testing on vulnerable apps like DVWA (Damn Vulnerable Web Application). **For educational purposes only—do not use on production sites without permission.**

![Java](https://img.shields.io/badge/Java-8-blue) ![Maven](https://img.shields.io/badge/Maven-3.6%2B-orange) ![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen)

## Features
- **Vulnerability Detection**: SQLi (error/success patterns) and XSS (malicious payload reflection/execution).
- **Payload Management**: Pre-defined payloads for SQLi (e.g., `' OR 1=1--`) and XSS (e.g., `<script>alert('XSS')</script>`).
- **HTTP Client**: Supports GET/POST requests with multithreading (up to 5 threads for parallel scanning).
- **Reporting**: Console output + HTML report (`scan-report.html`) with severity levels (High/Medium/Low).
- **Testing**: Unit tests with JUnit 5 and Mockito; Code coverage with JaCoCo (>80%).
- **Executable JAR**: Fat JAR (via Maven Shade) for easy distribution—no external dependencies needed.
- **DVWA Integration**: Optimized for testing on localhost DVWA (Low security level).

## Prerequisites
- **Java 8+**: Check with `java -version`.
- **Maven 3.6+**: Check with `mvn -version`. Download from [maven.apache.org](https://maven.apache.org/).
- **DVWA (for Testing)**: Vulnerable web app.
  - Install XAMPP (Apache + MySQL).
  - Download DVWA from [dvwa.co.uk](https://dvwa.co.uk/) > Extract to `C:\xampp\htdocs\dvwa`.
  - Setup: http://localhost/dvwa/setup.php > Create Database > Login (admin/password) > Set Security to "Low".
- **VS Code (Optional)**: With "Extension Pack for Java" for editing/debugging.

## Installation & Setup
1. Clone or download the project to a folder (e.g., `..`).
2. Open in VS Code: File > Open Folder > Select project root.
3. Verify structure: 

## Building the Project
Use Maven in the project root terminal (VS Code Terminal):
```bash
mvn clean          # Clean previous builds
mvn compile        # Compile source code
mvn test           # Run unit tests (expect 5 tests passing)
mvn package        # Build executable fat JAR (target/web-vuln-scanner-1.0-SNAPSHOT.jar)

project_baru/
├
├── pom.xml                    # Maven configuration (dependencies, plugins)
├── src/
│   ├── main/
│   │   └── java/
│   │       └── com/
│   │           └── example/
│   │               └── scanner/
│   │                   ├── ScannerMain.java      # Main entry point (CLI input, threading)
│   │                   ├── HttpClientWrapper.java # HTTP client (GET/POST, cookies)
│   │                   ├── PayloadManager.java   # Payload lists for SQLi/XSS
│   │                   ├── VulnDetector.java     # Vulnerability detection logic
│   │                   └── VulnResult.java       # Result object (type, severity)
│   └── test/
│       └── java/
│           └── com/
│               └── example/
│                   └── scanner/
│                       └── VulnDetectorTest.java # Unit tests (JUnit 5, Mockito)
├── target/                    # Build artifacts (after mvn package)
│   ├── web-vuln-scanner-1.0-SNAPSHOT.jar  # Executable fat JAR
│   ├── surefire-reports/      # Test reports
│   └── site/jacoco/           # JaCoCo coverage reports
└── scan-report.html           # Generated report (after running scanner)
