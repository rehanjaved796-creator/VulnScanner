  VulnScanner — Automated Web Penetration Testing Framework

![Java](https://img.shields.io/badge/Java-17-orange?style=for-the-badge&logo=java)
![JavaFX](https://img.shields.io/badge/JavaFX-21-blue?style=for-the-badge)
![Maven](https://img.shields.io/badge/Maven-3.11-red?style=for-the-badge&logo=apachemaven)
![iTextPDF](https://img.shields.io/badge/iTextPDF-5.5-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-yellow?style=for-the-badge)

>  Disclaimer: This tool is developed strictly for educational purposes and authorized penetration testing only. Never use it against systems you do not own or have explicit written permission to test.

 About The Project

VulnScanner is a project a fully automated web vulnerability assessment framework built in Java. It scans target web applications for common security vulnerabilities and generates a detailed professional PDF report with findings and remediation advice.

---

 Features

| Feature | Description |

|  SQL Injection Scanner | Detects SQL injection vulnerabilities using multiple payloads |
|  XSS Scanner | Finds reflected Cross-Site Scripting vulnerabilities |
|  Security Header Checker | Detects missing HTTP security headers |
|  Port Scanner | Identifies dangerous open ports |
|  Directory Scanner | Discovers exposed sensitive directories |
|  PDF Report Generator | Generates a professional, color-coded PDF report |
|  JavaFX GUI | Full dark-theme dashboard with charts and live scan log |


 Screenshots

 Dashboard — Scan Panel
> URL input, module selection, live scan log, progress bar

 Results Tab
> Color-coded vulnerability table with severity levels

 PDF Report
> Professional report with Executive Summary and Vulnerability Details

 Tech Stack

- Language: Java 17
- GUI Framework: JavaFX 21
- PDF Generation: iTextPDF 5.5
- HTTP Requests: Java HttpClient + Jsoup
- Build Tool: Maven 3.11
- IDE: IntelliJ IDEA

 Project Structure

VulnScanner/
├── src/main/java/com/vulnscanner/
│   ├── MainApp.java                  # JavaFX Entry Point
│   ├── MainDashboard.java            # Full GUI Dashboard
│   ├── engine/
│   │   └── ScanEngine.java           # Core Scan Orchestrator
│   ├── scanner/
│   │   ├── BaseScanner.java          # Abstract Base Class
│   │   ├── SQLScanner.java           # SQL Injection Module
│   │   ├── XSSScanner.java           # XSS Module
│   │   ├── HeaderScanner.java        # Security Headers Module
│   │   ├── PortScanner.java          # Port Scanning Module
│   │   └── DirectoryScanner.java     # Directory Traversal Module
│   ├── model/
│   │   ├── Vulnerability.java        # Vulnerability Model
│   │   ├── ScanReport.java           # Scan Report Model
│   │   └── Target.java               # Target URL Model
│   └── report/
│       └── ReportGenerator.java      # PDF Report Generator
├── src/main/resources/styles/
│   └── dark-theme.css                # Dark Hacker Theme
├── module-info.java
└── pom.xml
```


 How To Run

 Prerequisites
- Java 17 or higher
- Maven 3.8+
- IntelliJ IDEA (recommended)

 Steps

1. Clone the repository
```bash
git clone https://github.com/your-username/VulnScanner.git
cd VulnScanner
```

2. Install dependencies
```bash
mvn clean install
```

3. Run the GUI
```bash
mvn javafx:run
```

4. Or run from IntelliJ
- Open project in IntelliJ IDEA
- Let Maven import dependencies
- Run `MainApp.java`

---

 Sample PDF Report

The scanner automatically generates a professional PDF report containing:

-  Target information (URL, Domain, Protocol)
-  Executive Summary with severity counts
-  Detailed vulnerability findings
-  Evidence and payloads used
- Fix / Remediation recommendations
-  Timestamp and Report ID


  Vulnerability Detection

| Vulnerability | Severity | Detection Method |
|---|---|---|
| SQL Injection | CRITICAL | Error-based payload injection |
| Reflected XSS | HIGH | Payload reflection detection |
| Missing Security Headers | MEDIUM | HTTP response header analysis |
| Dangerous Open Ports | HIGH | TCP socket connection test |
| Exposed Directories | HIGH/MEDIUM | HTTP status code analysis |



  Author

Rehan javed
Second Semester  Student — Cyber Security
-  [LinkedIn](https://www.linkedin.com/in/rehan-javed-46b470289?utm_source=share_via&utm_content=profile&utm_medium=member_android)
-  [GitHub](https://github.com/rehanjaved796-creater)


 License

This project is developed for **educational purposes only as a Project.
Unauthorized use against systems without permission is illegal and unethical.

If you found this project useful, please give it a star!
