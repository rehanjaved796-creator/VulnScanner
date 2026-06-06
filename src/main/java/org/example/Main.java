package org.example;

import com.vulnscanner.engine.ScanEngine;
import com.vulnscanner.model.ScanReport;
import com.vulnscanner.report.ReportGenerator;

import java.util.Scanner;

public class Main {

    public static void main(String[] args) {

        Scanner input = new Scanner(System.in);

        System.out.println("=".repeat(50));
        System.out.println("  VulnScanner v1.0");
        System.out.println("  Automated Web Vulnerability Scanner");
        System.out.println("=".repeat(50));

        System.out.print("\n  Enter Target URL\n"
                + "  (e.g. http://localhost/dvwa): ");

        String targetUrl = input.nextLine().trim();

        if (targetUrl.isEmpty()) {
            System.out.println("[-] URL cannot be empty. Exiting.");
            return;
        }

        try {
            // Run full scan
            ScanEngine engine = new ScanEngine(targetUrl);
            ScanReport report = engine.runFullScan();

            // Generate PDF report
            System.out.println("[*] Generating PDF report...");
            ReportGenerator generator = new ReportGenerator();
            String pdfPath = generator.generatePDF(report);

            System.out.println("[+] Scan complete!");
            System.out.println("[+] PDF saved to: " + pdfPath);

        } catch (Exception e) {
            System.out.println("[-] Error: " + e.getMessage());
            e.printStackTrace();
        }

        input.close();
    }
}
