package com.vulnscanner;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;
import com.vulnscanner.gui.MainDashboard;

public class MainApp extends Application {

    @Override
    public void start(Stage primaryStage) {
        MainDashboard dashboard = new MainDashboard();

        // ✅ Fixed: cast to BorderPane — no unnecessary Parent cast
        Scene scene = new Scene((BorderPane) dashboard.getRoot(), 1100, 720);

        // ✅ CSS path matches: src/main/resources/styles/dark-theme.css
        scene.getStylesheets().add(
                getClass().getResource("/styles/dark-theme.css").toExternalForm()
        );

        primaryStage.setTitle("VulnScanner — Web Penetration Testing Framework");
        primaryStage.setScene(scene);
        primaryStage.setMinWidth(900);
        primaryStage.setMinHeight(600);
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
