package com.threatdetect;

import com.threatdetect.rules.RuleBasedEvaluator;
import com.threatdetect.service.ThreatAnalysisService;
import com.threatdetect.ui.MainView;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class App extends Application {

    private static final int POOL_SIZE = 4;
    private static final long TIMEOUT_MS = 10_000;

    // Artificial delay per item so progress bars are visible during the demo.
    // The local rules finish in microseconds. Set to 0 for the final version.
    private static final long DEMO_LATENCY_MS = 1500;

    private MainView view;

    @Override
    public void start(Stage stage) {
        ThreatAnalysisService service = new ThreatAnalysisService(
                new RuleBasedEvaluator(DEMO_LATENCY_MS), POOL_SIZE, TIMEOUT_MS);
        view = new MainView(service);

        stage.setTitle("Threat Detector");
        stage.setScene(new Scene(view.getRoot(), 1150, 700));
        stage.setMinWidth(900);
        stage.setMinHeight(520);
        stage.show();
    }

    @Override
    public void stop() {
        if (view != null) view.shutdown();   // stop worker threads when the window closes
    }

    public static void main(String[] args) {
        launch(args);
    }
}