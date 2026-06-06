package com.vulnscanner.engine;

import com.vulnscanner.model.ScanReport;
import com.vulnscanner.model.Target;
import com.vulnscanner.model.Vulnerability;
import com.vulnscanner.scanner.*;

import java.util.ArrayList;
import java.util.List;

/**
 * ScanEngine — Orchestrates all scanner modules.
 * Runs each module in sequence and compiles the final report.
 */
public class ScanEngine {

    private final Target   target;
    private final ScanReport report;

    public ScanEngine(String targetUrl) {
        this.target  = new Target(targetUrl);
        this.report  = new ScanReport(target);
    }

    public ScanReport runFullScan() {
        String url = target.getUrl();

        printBanner(url);

        List<BaseScanner> scanners = new ArrayList<>();
        scanners.add(new SQLScanner(url));
        scanners.add(new XSSScanner(url));
        scanners.add(new HeaderScanner(url));
        scanners.add(new PortScanner(url));
        scanners.add(new DirectoryScanner(url));

        for (BaseScanner scanner : scanners) {
            String name = scanner.getClass().getSimpleName();
            System.out.println("\n" + "─".repeat(50));
            System.out.println("  MODULE: " + name);
            System.out.println("─".repeat(50));

            try {
                List<Vulnerability> found = scanner.scan();
                report.addVulnerabilities(found);
                System.out.println("  Result: " + found.size() + " issues found");
            } catch (Exception e) {
                System.out.println("  [-] " + name + " error: " + e.getMessage());
            }
        }

        report.finalizeScan();
        printSummary();
        return report;
    }

    private void printBanner(String url) {
        System.out.println("\n" + "=".repeat(50));
        System.out.println("  VulnScanner v1.0 — Scan Starting");
        System.out.println("  Target : " + url);
        System.out.println("  Domain : " + target.getDomain());
        System.out.println("=".repeat(50));
    }

    private void printSummary() {
        System.out.println("\n" + "=".repeat(50));
        System.out.println("  SCAN COMPLETE");
        System.out.println("=".repeat(50));
        System.out.printf("  %-12s : %d%n", "CRITICAL", report.getCritical().size());
        System.out.printf("  %-12s : %d%n", "HIGH",     report.getHigh().size());
        System.out.printf("  %-12s : %d%n", "MEDIUM",   report.getMedium().size());
        System.out.printf("  %-12s : %d%n", "LOW",      report.getLow().size());
        System.out.printf("  %-12s : %d%n", "TOTAL",    report.getTotalCount());
        System.out.println("=".repeat(50) + "\n");
    }

    public ScanReport getReport() { return report; }
    public Target     getTarget() { return target; }
}
