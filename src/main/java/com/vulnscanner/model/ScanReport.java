package com.vulnscanner.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class ScanReport {

    private String              reportId;
    private Target              target;
    private List<Vulnerability> vulnerabilities;
    private String              startTime;
    private String              endTime;
    private String              scannerVersion = "VulnScanner v1.0";

    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // ── Constructors ──

    public ScanReport(Target target) {
        this.target          = target;
        this.vulnerabilities = new ArrayList<>();
        this.reportId        = "RPT-" + System.currentTimeMillis();
        this.startTime       = LocalDateTime.now().format(FMT);
    }

    public ScanReport(String url) {
        this(new Target(url));
    }

    // ── Add Vulnerabilities ──

    public void addVulnerability(Vulnerability v) {
        if (v != null) vulnerabilities.add(v);
    }

    /** Used by ScanEngine */
    public void addVulnerabilities(List<Vulnerability> list) {
        if (list != null) vulnerabilities.addAll(list);
    }

    /** Kept for backward compatibility with old ScanEngine code */
    public void addAll(List<Vulnerability> list) {
        addVulnerabilities(list);
    }

    /** Called when scan finishes */
    public void finalizeScan() {
        this.endTime = LocalDateTime.now().format(FMT);
    }

    /** Kept for backward compatibility */
    public void finalize_report() {
        finalizeScan();
    }

    // ── Severity Filters ──

    public List<Vulnerability> getCritical() {
        return filter(Vulnerability.Severity.CRITICAL);
    }

    public List<Vulnerability> getHigh() {
        return filter(Vulnerability.Severity.HIGH);
    }

    public List<Vulnerability> getMedium() {
        return filter(Vulnerability.Severity.MEDIUM);
    }

    public List<Vulnerability> getLow() {
        return filter(Vulnerability.Severity.LOW);
    }

    public List<Vulnerability> getInfo() {
        return filter(Vulnerability.Severity.INFO);
    }

    private List<Vulnerability> filter(Vulnerability.Severity s) {
        return vulnerabilities.stream()
                .filter(v -> v.getSeverity() == s)
                .collect(Collectors.toList());
    }

    public int    getTotalCount()    { return vulnerabilities.size(); }

    public String getRiskLevel() {
        if (!getCritical().isEmpty()) return "CRITICAL";
        if (!getHigh().isEmpty())     return "HIGH";
        if (!getMedium().isEmpty())   return "MEDIUM";
        if (!getLow().isEmpty())      return "LOW";
        return "NONE";
    }

    // ── Getters ──

    public String              getReportId()        { return reportId; }
    public Target              getTarget()           { return target; }
    public List<Vulnerability> getVulnerabilities() { return vulnerabilities; }
    public String              getStartTime()        { return startTime; }
    public String              getEndTime()          { return endTime != null ? endTime : "In Progress"; }
    public String              getScannerVersion()   { return scannerVersion; }

    // ── Setters ──

    public void setTarget(Target target)                     { this.target = target; }
    public void setScannerVersion(String v)                  { this.scannerVersion = v; }
    public void setVulnerabilities(List<Vulnerability> list) { this.vulnerabilities = list; }

    @Override
    public String toString() {
        return String.format("ScanReport[id=%s, target=%s, findings=%d, risk=%s]",
                reportId,
                target != null ? target.getUrl() : "N/A",
                getTotalCount(), getRiskLevel());
    }
}
