module com.vulnscanner {
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.graphics;
    requires javafx.base;
    requires java.net.http;
    requires itextpdf;

    exports com.vulnscanner;
    exports com.vulnscanner.gui;
    exports com.vulnscanner.model;
    exports com.vulnscanner.engine;
    exports com.vulnscanner.scanner;
    exports com.vulnscanner.report;
}
