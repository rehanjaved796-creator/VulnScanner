package com.vulnscanner.report;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;
import com.vulnscanner.model.ScanReport;
import com.vulnscanner.model.Vulnerability;

import java.io.FileOutputStream;
import java.util.List;

public class ReportGenerator {

    // Colors
    private static final BaseColor NAVY =
            new BaseColor(31, 56, 100);
    private static final BaseColor BLUE =
            new BaseColor(47, 117, 182);
    private static final BaseColor LBLUE =
            new BaseColor(214, 228, 247);
    private static final BaseColor RED =
            new BaseColor(192, 0, 0);
    private static final BaseColor ORANGE =
            new BaseColor(197, 90, 17);
    private static final BaseColor GREEN =
            new BaseColor(55, 86, 35);
    private static final BaseColor LGREEN =
            new BaseColor(226, 239, 218);
    private static final BaseColor WHITE =
            BaseColor.WHITE;

    // Fonts
    private static Font titleFont;
    private static Font headFont;
    private static Font subFont;
    private static Font bodyFont;
    private static Font boldFont;
    private static Font whiteFont;
    private static Font critFont;

    static {
        try {
            titleFont = new Font(
                    Font.FontFamily.HELVETICA,
                    20, Font.BOLD, WHITE);
            headFont  = new Font(
                    Font.FontFamily.HELVETICA,
                    14, Font.BOLD, NAVY);
            subFont   = new Font(
                    Font.FontFamily.HELVETICA,
                    11, Font.BOLD, BLUE);
            bodyFont  = new Font(
                    Font.FontFamily.HELVETICA,
                    10, Font.NORMAL,
                    BaseColor.BLACK);
            boldFont  = new Font(
                    Font.FontFamily.HELVETICA,
                    10, Font.BOLD,
                    BaseColor.BLACK);
            whiteFont = new Font(
                    Font.FontFamily.HELVETICA,
                    10, Font.BOLD, WHITE);
            critFont  = new Font(
                    Font.FontFamily.HELVETICA,
                    10, Font.BOLD, RED);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String generatePDF(ScanReport report)
            throws Exception {
        String filename = "VulnReport_"
                + report.getTarget().getDomain()
                + "_"
                + System.currentTimeMillis()
                + ".pdf";

        Document doc = new Document(PageSize.A4,
                40, 40, 50, 50);
        PdfWriter.getInstance(
                doc, new FileOutputStream(filename));
        doc.open();

        // Cover page
        addCover(doc, report);

        // Summary section
        addSummary(doc, report);

        // Vulnerabilities
        addVulnerabilities(doc, report);

        doc.close();
        System.out.println(
                "[+] Report saved: " + filename);
        return filename;
    }

    private void addCover(
            Document doc, ScanReport report)
            throws Exception {

        // Header table
        PdfPTable header = new PdfPTable(1);
        header.setWidthPercentage(100);

        PdfPCell titleCell = new PdfPCell();
        titleCell.setBackgroundColor(NAVY);
        titleCell.setPadding(20);
        titleCell.setBorder(Rectangle.NO_BORDER);
        titleCell.addElement(new Paragraph(
                "Web Vulnerability Assessment Report",
                titleFont));
        titleCell.addElement(new Paragraph(
                "Automated Penetration Testing Framework",
                new Font(Font.FontFamily.HELVETICA,
                        12, Font.NORMAL,
                        new BaseColor(180, 200, 230))));
        header.addCell(titleCell);
        doc.add(header);
        doc.add(new Paragraph(" "));

        // Info table
        PdfPTable info = new PdfPTable(2);
        info.setWidthPercentage(100);
        info.setWidths(new float[]{1f, 2f});

        addInfoRow(info, "Target URL",
                report.getTarget().getUrl());
        addInfoRow(info, "Domain",
                report.getTarget().getDomain());
        addInfoRow(info, "Protocol",
                report.getTarget().getProtocol());
        addInfoRow(info, "Report ID",
                report.getReportId());
        addInfoRow(info, "Scan Started",
                report.getStartTime());
        addInfoRow(info, "Scan Ended",
                report.getEndTime());
        addInfoRow(info, "Scanner Version",
                report.getScannerVersion());
        addInfoRow(info, "Total Issues",
                String.valueOf(
                        report.getTotalCount()));

        doc.add(info);
        doc.add(new Paragraph(" "));
    }

    private void addInfoRow(
            PdfPTable table,
            String label, String value) {

        PdfPCell labelCell = new PdfPCell(
                new Phrase(label, boldFont));
        labelCell.setBackgroundColor(LBLUE);
        labelCell.setPadding(6);
        table.addCell(labelCell);

        PdfPCell valueCell = new PdfPCell(
                new Phrase(value != null
                        ? value : "N/A", bodyFont));
        valueCell.setPadding(6);
        table.addCell(valueCell);
    }

    private void addSummary(
            Document doc, ScanReport report)
            throws Exception {

        doc.add(new Paragraph(
                "Executive Summary", headFont));
        doc.add(new Paragraph(" "));

        PdfPTable table = new PdfPTable(2);
        table.setWidthPercentage(60);
        table.setHorizontalAlignment(
                Element.ALIGN_LEFT);

        addSummaryRow(table,
                "CRITICAL",
                report.getCritical().size(),
                RED);
        addSummaryRow(table,
                "HIGH",
                report.getHigh().size(),
                ORANGE);
        addSummaryRow(table,
                "MEDIUM",
                report.getMedium().size(),
                new BaseColor(255, 192, 0));
        addSummaryRow(table,
                "LOW",
                report.getLow().size(),
                GREEN);
        addSummaryRow(table,
                "TOTAL",
                report.getTotalCount(),
                NAVY);

        doc.add(table);
        doc.add(new Paragraph(" "));
    }

    private void addSummaryRow(
            PdfPTable table,
            String severity, int count,
            BaseColor color) {

        PdfPCell s = new PdfPCell(
                new Phrase(severity, whiteFont));
        s.setBackgroundColor(color);
        s.setPadding(6);
        table.addCell(s);

        PdfPCell c = new PdfPCell(
                new Phrase(String.valueOf(count),
                        boldFont));
        c.setPadding(6);
        table.addCell(c);
    }

    private void addVulnerabilities(
            Document doc, ScanReport report)
            throws Exception {

        doc.add(new Paragraph(
                "Vulnerability Details", headFont));
        doc.add(new Paragraph(" "));

        List<Vulnerability> vulns =
                report.getVulnerabilities();

        if (vulns.isEmpty()) {
            doc.add(new Paragraph(
                    "No vulnerabilities found!",
                    new Font(Font.FontFamily.HELVETICA,
                            12, Font.BOLD, GREEN)));
            return;
        }

        int count = 1;
        for (Vulnerability v : vulns) {

            // Vuln header
            PdfPTable header = new PdfPTable(1);
            header.setWidthPercentage(100);
            PdfPCell hCell = new PdfPCell(
                    new Phrase(
                            count + ". " + v.getName()
                                    + "  [" + v.getSeverity() + "]",
                            whiteFont));
            hCell.setBackgroundColor(
                    getSeverityColor(v.getSeverity()));
            hCell.setPadding(8);
            header.addCell(hCell);
            doc.add(header);

            // Vuln details
            PdfPTable details = new PdfPTable(2);
            details.setWidthPercentage(100);
            details.setWidths(new float[]{1f, 3f});

            addDetailRow(details,
                    "Type",
                    v.getType().toString());
            addDetailRow(details,
                    "URL", v.getUrl());
            addDetailRow(details,
                    "Payload", v.getPayload());
            addDetailRow(details,
                    "Evidence", v.getEvidence());
            addDetailRow(details,
                    "Description",
                    v.getDescription());
            addDetailRow(details,
                    "Fix / Recommendation",
                    v.getRecommendation());
            addDetailRow(details,
                    "Discovered At",
                    v.getDiscoveredAt());

            doc.add(details);
            doc.add(new Paragraph(" "));
            count++;
        }
    }

    private void addDetailRow(
            PdfPTable table,
            String label, String value) {

        PdfPCell l = new PdfPCell(
                new Phrase(label, boldFont));
        l.setBackgroundColor(
                new BaseColor(242, 242, 242));
        l.setPadding(5);
        table.addCell(l);

        PdfPCell v = new PdfPCell(
                new Phrase(value != null
                        ? value : "N/A", bodyFont));
        v.setPadding(5);
        table.addCell(v);
    }

    private BaseColor getSeverityColor(
            Vulnerability.Severity s) {
        return switch (s) {
            case CRITICAL -> RED;
            case HIGH     -> ORANGE;
            case MEDIUM   ->
                    new BaseColor(255, 192, 0);
            case LOW      -> GREEN;
            default       -> NAVY;
        };
    }
}