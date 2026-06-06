package com.vulnscanner.gui;

import com.vulnscanner.engine.ScanEngine;
import com.vulnscanner.model.ScanReport;
import com.vulnscanner.model.Vulnerability;
import com.vulnscanner.report.ReportGenerator;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.PieChart;
import javafx.scene.chart.XYChart;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;

import java.util.List;

public class MainDashboard {

    private final BorderPane root = new BorderPane();
    private VBox sidebar;
    private StackPane contentArea;
    private Node scanPane, resultsPane, chartsPane, aboutPane;

    private TextField urlField;
    private CheckBox chkSQL, chkXSS, chkHeader, chkPort, chkDir;
    private Button btnScan, btnStop;
    private ProgressBar progressBar;
    private Label progressLabel;
    private TextArea logArea;

    private TableView<VulnRow> resultsTable;
    private ObservableList<VulnRow> tableData = FXCollections.observableArrayList();
    private Label lblTotal, lblCritical, lblHigh, lblMedium, lblLow;

    private PieChart pieChart;
    private BarChart<String, Number> barChart;

    private ScanReport lastReport;
    private Task<?> currentScanTask;

    public MainDashboard() { buildUI(); }

    public Node getRoot() { return root; }

    // ─────────────────────────────────────────────
    //  BUILD UI
    // ─────────────────────────────────────────────

    private void buildUI() {
        root.getStyleClass().add("root-pane");
        sidebar     = buildSidebar();
        root.setLeft(sidebar);
        root.setTop(buildTopBar());

        scanPane    = buildScanPane();
        resultsPane = buildResultsPane();
        chartsPane  = buildChartsPane();
        aboutPane   = buildAboutPane();

        contentArea = new StackPane(scanPane);
        contentArea.getStyleClass().add("content-area");
        root.setCenter(contentArea);
    }

    // ─────────────────────────────────────────────
    //  TOP BAR
    // ─────────────────────────────────────────────

    private Node buildTopBar() {
        HBox bar = new HBox(12);
        bar.getStyleClass().add("top-bar");
        bar.setAlignment(Pos.CENTER_LEFT);
        bar.setPadding(new Insets(0, 20, 0, 20));

        Circle dot = new Circle(5, Color.web("#00ff88"));
        dot.getStyleClass().add("status-dot");

        Label title = new Label("VulnScanner  |  Web Penetration Testing Framework");
        title.getStyleClass().add("top-bar-title");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Label version = new Label("v1.0.0  •  For authorized testing only");
        version.getStyleClass().add("top-bar-version");

        bar.getChildren().addAll(dot, title, spacer, version);
        return bar;
    }

    // ─────────────────────────────────────────────
    //  SIDEBAR
    // ─────────────────────────────────────────────

    private VBox buildSidebar() {
        VBox sb = new VBox(4);
        sb.getStyleClass().add("sidebar");
        sb.setPrefWidth(200);
        sb.setPadding(new Insets(20, 12, 20, 12));

        Label logo = new Label("🔒 VulnScanner");
        logo.getStyleClass().add("sidebar-logo");
        VBox.setMargin(logo, new Insets(0, 0, 24, 0));

        Button btnDashboard = sidebarButton("🏠  Dashboard", true);
        Button btnResults   = sidebarButton("📋  Results",   false);
        Button btnCharts    = sidebarButton("📊  Charts",    false);
        Button btnAbout     = sidebarButton("ℹ️   About",     false);

        btnDashboard.setOnAction(e -> switchTab(scanPane,    btnDashboard, btnResults, btnCharts, btnAbout));
        btnResults.setOnAction(e   -> switchTab(resultsPane, btnResults,   btnDashboard, btnCharts, btnAbout));
        btnCharts.setOnAction(e    -> switchTab(chartsPane,  btnCharts,    btnDashboard, btnResults, btnAbout));
        btnAbout.setOnAction(e     -> switchTab(aboutPane,   btnAbout,     btnDashboard, btnResults, btnCharts));

        Region spacer = new Region();
        VBox.setVgrow(spacer, Priority.ALWAYS);

        Label footer = new Label("© 2024 VulnScanner\nFor educational use");
        footer.getStyleClass().add("sidebar-footer");

        sb.getChildren().addAll(logo, btnDashboard, btnResults, btnCharts, btnAbout, spacer, footer);
        return sb;
    }

    private Button sidebarButton(String text, boolean active) {
        Button btn = new Button(text);
        btn.getStyleClass().add("sidebar-btn");
        if (active) btn.getStyleClass().add("sidebar-btn-active");
        btn.setMaxWidth(Double.MAX_VALUE);
        return btn;
    }

    private void switchTab(Node pane, Button active, Button... others) {
        contentArea.getChildren().setAll(pane);
        active.getStyleClass().add("sidebar-btn-active");
        for (Button b : others) b.getStyleClass().remove("sidebar-btn-active");
    }

    // ─────────────────────────────────────────────
    //  SCAN PANE
    // ─────────────────────────────────────────────

    private Node buildScanPane() {
        VBox pane = new VBox(20);
        pane.getStyleClass().add("tab-pane");
        pane.setPadding(new Insets(28));

        Label title = new Label("New Scan");
        title.getStyleClass().add("section-title");

        HBox urlRow = new HBox(12);
        urlRow.setAlignment(Pos.CENTER_LEFT);

        Label urlLabel = new Label("Target URL:");
        urlLabel.getStyleClass().add("field-label");
        urlLabel.setPrefWidth(100);

        urlField = new TextField();
        urlField.setPromptText("http://localhost/DVWA-master");
        urlField.getStyleClass().add("url-field");
        HBox.setHgrow(urlField, Priority.ALWAYS);

        btnScan = new Button("▶  Start Scan");
        btnScan.getStyleClass().add("btn-scan");

        btnStop = new Button("■  Stop");
        btnStop.getStyleClass().add("btn-stop");
        btnStop.setDisable(true);

        urlRow.getChildren().addAll(urlLabel, urlField, btnScan, btnStop);

        Label modLabel = new Label("Scan Modules");
        modLabel.getStyleClass().add("field-label");

        HBox modules = new HBox(20);
        chkSQL    = styledCheckbox("SQL Injection", true);
        chkXSS    = styledCheckbox("XSS",           true);
        chkHeader = styledCheckbox("Headers",       true);
        chkPort   = styledCheckbox("Port Scan",     true);
        chkDir    = styledCheckbox("Directories",   true);
        modules.getChildren().addAll(chkSQL, chkXSS, chkHeader, chkPort, chkDir);

        progressBar = new ProgressBar(0);
        progressBar.getStyleClass().add("progress-bar-custom");
        progressBar.setMaxWidth(Double.MAX_VALUE);

        progressLabel = new Label("Ready to scan...");
        progressLabel.getStyleClass().add("progress-label");

        Label logLabel = new Label("Scan Log");
        logLabel.getStyleClass().add("field-label");

        logArea = new TextArea();
        logArea.getStyleClass().add("log-area");
        logArea.setEditable(false);
        logArea.setWrapText(true);
        logArea.setPrefHeight(220);
        VBox.setVgrow(logArea, Priority.ALWAYS);

        btnScan.setOnAction(e -> startScan());
        btnStop.setOnAction(e -> stopScan());

        pane.getChildren().addAll(title, urlRow, modLabel, modules,
                progressBar, progressLabel, logLabel, logArea);
        return pane;
    }

    // ─────────────────────────────────────────────
    //  RESULTS PANE
    // ─────────────────────────────────────────────

    private Node buildResultsPane() {
        VBox pane = new VBox(16);
        pane.getStyleClass().add("tab-pane");
        pane.setPadding(new Insets(28));

        Label title = new Label("Scan Results");
        title.getStyleClass().add("section-title");

        HBox cards = new HBox(16);
        lblTotal    = statCard("Total",    "0", "#94a3b8");
        lblCritical = statCard("Critical", "0", "#dc2626");
        lblHigh     = statCard("High",     "0", "#ea580c");
        lblMedium   = statCard("Medium",   "0", "#d97706");
        lblLow      = statCard("Low",      "0", "#16a34a");
        cards.getChildren().addAll(lblTotal, lblCritical, lblHigh, lblMedium, lblLow);

        resultsTable = buildResultsTable();
        VBox.setVgrow(resultsTable, Priority.ALWAYS);

        // ✅ Fixed: Only PDF export — matches ReportGenerator.generatePDF()
        HBox exportRow = new HBox(12);
        Button btnExportPDF = new Button("⬇  Export PDF Report");
        btnExportPDF.getStyleClass().add("btn-export");
        btnExportPDF.setOnAction(e -> exportPDF());
        exportRow.getChildren().add(btnExportPDF);

        pane.getChildren().addAll(title, cards, resultsTable, exportRow);
        return pane;
    }

    @SuppressWarnings("unchecked")
    private TableView<VulnRow> buildResultsTable() {
        TableView<VulnRow> table = new TableView<>();
        table.getStyleClass().add("results-table");
        table.setItems(tableData);
        // ✅ Fixed: CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN — not deprecated
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.setPlaceholder(new Label("No scan results yet. Run a scan first."));

        TableColumn<VulnRow, String> colSev = new TableColumn<>("Severity");
        colSev.setCellValueFactory(new PropertyValueFactory<>("severity"));
        colSev.setPrefWidth(90);
        colSev.setCellFactory(col -> new TableCell<>() {
            @Override protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) { setText(null); setStyle(""); return; }
                setText(item);
                String color = switch (item) {
                    case "CRITICAL" -> "#dc2626";
                    case "HIGH"     -> "#ea580c";
                    case "MEDIUM"   -> "#d97706";
                    case "LOW"      -> "#16a34a";
                    default         -> "#2563eb";
                };
                setStyle("-fx-text-fill:" + color + ";-fx-font-weight:bold;");
            }
        });

        TableColumn<VulnRow, String> colType = new TableColumn<>("Vulnerability");
        colType.setCellValueFactory(new PropertyValueFactory<>("type"));
        colType.setPrefWidth(160);

        TableColumn<VulnRow, String> colUrl = new TableColumn<>("Affected URL");
        colUrl.setCellValueFactory(new PropertyValueFactory<>("url"));
        colUrl.setPrefWidth(260);

        TableColumn<VulnRow, String> colDesc = new TableColumn<>("Description");
        colDesc.setCellValueFactory(new PropertyValueFactory<>("description"));

        table.getColumns().addAll(colSev, colType, colUrl, colDesc);
        return table;
    }

    // ─────────────────────────────────────────────
    //  CHARTS PANE
    // ─────────────────────────────────────────────

    private Node buildChartsPane() {
        VBox pane = new VBox(20);
        pane.getStyleClass().add("tab-pane");
        pane.setPadding(new Insets(28));

        Label title = new Label("Vulnerability Analytics");
        title.getStyleClass().add("section-title");

        pieChart = new PieChart();
        pieChart.setTitle("Severity Distribution");
        pieChart.getStyleClass().add("dark-chart");
        pieChart.setPrefHeight(280);
        pieChart.setLegendVisible(true);
        updatePieChart(0, 0, 0, 0, 0);

        CategoryAxis xAxis = new CategoryAxis();
        NumberAxis   yAxis = new NumberAxis();
        xAxis.setLabel("Severity Level");
        yAxis.setLabel("Count");

        barChart = new BarChart<>(xAxis, yAxis);
        barChart.setTitle("Vulnerabilities by Severity");
        barChart.getStyleClass().add("dark-chart");
        barChart.setPrefHeight(260);
        barChart.setLegendVisible(false);
        updateBarChart(0, 0, 0, 0, 0);

        HBox chartRow = new HBox(20, pieChart, barChart);
        HBox.setHgrow(pieChart, Priority.ALWAYS);
        HBox.setHgrow(barChart, Priority.ALWAYS);
        VBox.setVgrow(chartRow, Priority.ALWAYS);

        pane.getChildren().addAll(title, chartRow);
        return pane;
    }

    // ─────────────────────────────────────────────
    //  ABOUT PANE
    // ─────────────────────────────────────────────

    private Node buildAboutPane() {
        VBox pane = new VBox(16);
        pane.getStyleClass().add("tab-pane");
        pane.setPadding(new Insets(40));
        pane.setAlignment(Pos.TOP_CENTER);

        Label logo = new Label("🔒");
        logo.setStyle("-fx-font-size:52px;");

        Label name = new Label("VulnScanner");
        name.getStyleClass().add("about-title");

        Label sub = new Label("Automated Web Vulnerability Assessment & Penetration Testing Framework");
        sub.getStyleClass().add("about-sub");
        sub.setWrapText(true);
        sub.setTextAlignment(javafx.scene.text.TextAlignment.CENTER);

        Separator sep = new Separator();
        sep.setMaxWidth(400);

        Label[] info = {
                infoLabel("Version",  "1.0.0"),
                infoLabel("Language", "Java 17+ with JavaFX 21"),
                infoLabel("Modules",  "SQL Injection • XSS • Headers • Port Scanner • Directory Traversal"),
                infoLabel("Target",   "DVWA / Owned Systems Only"),
                infoLabel("Author",   "Rehan — Final Year Project"),
        };

        Label warn = new Label("⚠  This tool is for authorized and educational use only.\n"
                + "Never test systems without explicit written permission.");
        warn.getStyleClass().add("about-warning");
        warn.setWrapText(true);
        warn.setTextAlignment(javafx.scene.text.TextAlignment.CENTER);

        pane.getChildren().addAll(logo, name, sub, sep);
        for (Label l : info) pane.getChildren().add(l);
        pane.getChildren().add(warn);
        return pane;
    }

    // ─────────────────────────────────────────────
    //  SCAN LOGIC
    // ─────────────────────────────────────────────

    private void startScan() {
        String url = urlField.getText().trim();
        if (url.isEmpty()) {
            showAlert("Missing URL", "Please enter a target URL before scanning.");
            return;
        }
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            showAlert("Invalid URL", "URL must start with http:// or https://");
            return;
        }

        tableData.clear();
        logArea.clear();
        progressBar.setProgress(0);
        progressLabel.setText("Initializing scan...");
        btnScan.setDisable(true);
        btnStop.setDisable(false);

        log("[*] Starting scan on: " + url);
        log("[*] Modules: " + getSelectedModules());

        currentScanTask = new Task<Void>() {
            @Override
            protected Void call() throws Exception {
                // ✅ Fixed: ScanEngine(url) — correct constructor
                ScanEngine engine = new ScanEngine(url);

                String[] steps = {
                        "Resolving host...",
                        "Running SQL Injection scan...",
                        "Running XSS scan...",
                        "Checking security headers...",
                        "Running port scan...",
                        "Scanning directories...",
                        "Compiling results..."
                };

                for (int i = 0; i < steps.length; i++) {
                    if (isCancelled()) return null;
                    final double progress = (double)(i + 1) / steps.length;
                    final String msg = steps[i];
                    Platform.runLater(() -> {
                        progressBar.setProgress(progress);
                        progressLabel.setText(msg);
                        log("[~] " + msg);
                    });
                    Thread.sleep(400);
                }

                if (!isCancelled()) {
                    // ✅ Fixed: runFullScan() — correct method name
                    lastReport = engine.runFullScan();
                    Platform.runLater(() -> onScanComplete(lastReport));
                }
                return null;
            }
        };

        currentScanTask.setOnFailed(e -> Platform.runLater(() -> {
            log("[!] Scan failed: " + currentScanTask.getException().getMessage());
            resetScanButtons();
        }));

        Thread thread = new Thread(currentScanTask);
        thread.setDaemon(true);
        thread.start();
    }

    private void stopScan() {
        if (currentScanTask != null) currentScanTask.cancel();
        log("[!] Scan stopped by user.");
        progressLabel.setText("Scan stopped.");
        progressBar.setProgress(0);
        resetScanButtons();
    }

    private void onScanComplete(ScanReport report) {
        List<Vulnerability> vulns = report.getVulnerabilities();

        // ✅ Fixed: Severity is enum — compare with == not string
        long critical = vulns.stream().filter(v -> v.getSeverity() == Vulnerability.Severity.CRITICAL).count();
        long high     = vulns.stream().filter(v -> v.getSeverity() == Vulnerability.Severity.HIGH).count();
        long medium   = vulns.stream().filter(v -> v.getSeverity() == Vulnerability.Severity.MEDIUM).count();
        long low      = vulns.stream().filter(v -> v.getSeverity() == Vulnerability.Severity.LOW).count();
        long info     = vulns.stream().filter(v -> v.getSeverity() == Vulnerability.Severity.INFO).count();

        for (Vulnerability v : vulns) {
            tableData.add(new VulnRow(
                    v.getSeverity().name(),      // ✅ enum.name() = "CRITICAL" string
                    v.getType().toString(),       // ✅ Type.toString() = "SQL INJECTION"
                    v.getUrl(),
                    v.getDescription()
            ));
        }

        updateStatCard(lblTotal,    String.valueOf(vulns.size()));
        updateStatCard(lblCritical, String.valueOf(critical));
        updateStatCard(lblHigh,     String.valueOf(high));
        updateStatCard(lblMedium,   String.valueOf(medium));
        updateStatCard(lblLow,      String.valueOf(low));

        updatePieChart(critical, high, medium, low, info);
        updateBarChart(critical, high, medium, low, info);

        progressBar.setProgress(1.0);
        progressLabel.setText("Scan complete — " + vulns.size() + " vulnerabilities found.");
        log("[✓] Scan complete! Total findings: " + vulns.size());
        log("[✓] Go to Results or Charts tab to view details.");
        resetScanButtons();
    }

    // ─────────────────────────────────────────────
    //  EXPORT — ✅ Fixed: uses generatePDF()
    // ─────────────────────────────────────────────

    private void exportPDF() {
        if (lastReport == null) {
            showAlert("No Report", "Please run a scan first before exporting.");
            return;
        }
        try {
            ReportGenerator gen = new ReportGenerator();
            String path = gen.generatePDF(lastReport);
            log("[✓] PDF exported: " + path);
            showInfo("Export Successful", "PDF saved to:\n" + path);
        } catch (Exception e) {
            showAlert("Export Failed", "Could not generate PDF:\n" + e.getMessage());
        }
    }

    // ─────────────────────────────────────────────
    //  CHART HELPERS
    // ─────────────────────────────────────────────

    private void updatePieChart(long c, long h, long m, long l, long i) {
        ObservableList<PieChart.Data> data = FXCollections.observableArrayList();
        if (c > 0) data.add(new PieChart.Data("Critical (" + c + ")", c));
        if (h > 0) data.add(new PieChart.Data("High ("     + h + ")", h));
        if (m > 0) data.add(new PieChart.Data("Medium ("   + m + ")", m));
        if (l > 0) data.add(new PieChart.Data("Low ("      + l + ")", l));
        if (i > 0) data.add(new PieChart.Data("Info ("     + i + ")", i));
        if (data.isEmpty()) data.add(new PieChart.Data("No Data", 1));
        pieChart.setData(data);
    }

    private void updateBarChart(long c, long h, long m, long l, long i) {
        XYChart.Series<String, Number> series = new XYChart.Series<>();
        series.getData().add(new XYChart.Data<>("Critical", c));
        series.getData().add(new XYChart.Data<>("High",     h));
        series.getData().add(new XYChart.Data<>("Medium",   m));
        series.getData().add(new XYChart.Data<>("Low",      l));
        series.getData().add(new XYChart.Data<>("Info",     i));
        barChart.getData().setAll(series);
    }

    // ─────────────────────────────────────────────
    //  UI HELPERS
    // ─────────────────────────────────────────────

    private CheckBox styledCheckbox(String label, boolean selected) {
        CheckBox cb = new CheckBox(label);
        cb.setSelected(selected);
        cb.getStyleClass().add("scan-checkbox");
        return cb;
    }

    private Label statCard(String label, String value, String color) {
        VBox card = new VBox(4);
        card.getStyleClass().add("stat-card");
        card.setAlignment(Pos.CENTER);
        card.setPrefWidth(100);

        Label valLabel = new Label(value);
        valLabel.setStyle("-fx-font-size:26px;-fx-font-weight:bold;-fx-text-fill:" + color + ";");

        Label nameLabel = new Label(label);
        nameLabel.setStyle("-fx-font-size:11px;-fx-text-fill:#94a3b8;-fx-font-weight:600;");

        card.getChildren().addAll(valLabel, nameLabel);

        Label proxy = new Label();
        proxy.setGraphic(card);
        proxy.setUserData(valLabel);
        return proxy;
    }

    private void updateStatCard(Label proxy, String newValue) {
        if (proxy.getUserData() instanceof Label valLabel) {
            valLabel.setText(newValue);
        }
    }

    private Label infoLabel(String key, String value) {
        Label l = new Label(key + ":  " + value);
        l.getStyleClass().add("about-info");
        return l;
    }

    private void log(String msg) {
        Platform.runLater(() -> logArea.appendText(msg + "\n"));
    }

    private void resetScanButtons() {
        btnScan.setDisable(false);
        btnStop.setDisable(true);
    }

    private String getSelectedModules() {
        StringBuilder sb = new StringBuilder();
        if (chkSQL.isSelected())    sb.append("SQL ");
        if (chkXSS.isSelected())    sb.append("XSS ");
        if (chkHeader.isSelected()) sb.append("Headers ");
        if (chkPort.isSelected())   sb.append("Ports ");
        if (chkDir.isSelected())    sb.append("Directories ");
        return sb.toString().trim();
    }

    private void showAlert(String title, String msg) {
        Alert a = new Alert(Alert.AlertType.WARNING);
        a.setTitle(title);
        a.setHeaderText(null);
        a.setContentText(msg);
        a.showAndWait();
    }

    private void showInfo(String title, String msg) {
        Alert a = new Alert(Alert.AlertType.INFORMATION);
        a.setTitle(title);
        a.setHeaderText(null);
        a.setContentText(msg);
        a.showAndWait();
    }

    // ─────────────────────────────────────────────
    //  TABLE ROW MODEL
    // ─────────────────────────────────────────────

    public static class VulnRow {
        private final String severity, type, url, description;

        public VulnRow(String severity, String type, String url, String description) {
            this.severity    = severity;
            this.type        = type;
            this.url         = url;
            this.description = description;
        }

        public String getSeverity()    { return severity; }
        public String getType()        { return type; }
        public String getUrl()         { return url; }
        public String getDescription() { return description; }
    }
}
