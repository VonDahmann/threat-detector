# Threat Detector

Multi-threaded threat detection desktop app (Java + JavaFX), Concurrency Programming mini-project 2026-2027.
Sprint 1: user interface + backend foundations (rule-based detection).

## Run
    mvn clean javafx:run
Tests: `mvn clean test`

## Structure
- `model/`      data classes (InputType, RiskLevel, ScanItem, ScanResult)
- `service/`    analyzers, CSV parser, ScanService
- `controller/` ScanController (no JavaFX imports)
- `ui/`         JavaFX user interface
- `data/`       sample CSV files

The backend (model, service, controller) never imports JavaFX.
Anything that cannot be verified is reported as NOT_VERIFIED, never LOW.

## Team workflow
One branch per task, Pull Request, review by Person 1, merge into `main`.

In IntelliJ, run the Launcher class (not Main). A JavaFX "unsupported configuration" warning
in the console is normal. Or use: mvn clean javafx:run