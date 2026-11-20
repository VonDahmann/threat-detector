package threatdetect;

import javafx.application.Application;

/** Plain main class: avoids the "JavaFX runtime components are missing" error in some IDEs and jars. */
public final class Launcher {
    public static void main(String[] args) {
        Application.launch(ThreatDetectionApp.class, args);
    }
}
