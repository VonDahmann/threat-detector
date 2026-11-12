package com.threatdetect.ui;

import com.threatdetect.model.AnalysisResult;
import com.threatdetect.model.InputItem;
import com.threatdetect.model.InputType;
import com.threatdetect.model.InvalidInputException;
import com.threatdetect.model.RiskLevel;
import com.threatdetect.model.Status;
import com.threatdetect.service.AnalysisListener;
import com.threatdetect.service.CsvParseResult;
import com.threatdetect.service.CsvParserService;
import com.threatdetect.service.InputFactory;
import com.threatdetect.service.RowError;
import com.threatdetect.service.ThreatAnalysisService;
import javafx.application.Platform;
import javafx.beans.binding.Bindings;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.cell.ProgressBarTableCell;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;

import java.io.File;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class MainView {

    private final ThreatAnalysisService service;
    private final CsvParserService csvParser = new CsvParserService();

    private final ObservableList<ResultRow> rows = FXCollections.observableArrayList();
    private final Map<Integer, ResultRow> rowById = new HashMap<>();   // JavaFX thread only

    private final BorderPane root = new BorderPane();
    private final TableView<ResultRow> table = new TableView<>(rows);
    private final ComboBox<String> typeBox = new ComboBox<>();
    private final TextField inputField = new TextField();
    private final Button addBtn = new Button("Add");
    private final Button browseBtn = new Button("Load CSV…");
    private final Button analyzeBtn = new Button("Analyze");
    private final Button cancelBtn = new Button("Cancel");
    private final Button clearBtn = new Button("Clear all");
    private final TextArea detailsArea = new TextArea();
    private final Label summaryLabel = new Label();
    private final Label messageLabel = new Label();
    private final ProgressBar overallBar = new ProgressBar(0);

    private ThreatAnalysisService.BatchHandle currentBatch;
    private boolean running = false;
    private int batchTotal = 0;
    private int batchDone = 0;

    public MainView(ThreatAnalysisService service) {
        this.service = service;
        buildTable();
        buildLayout();
        wireEvents();
        updateButtons();
        updateSummary();
        showInfo("Ready. Add an input or load a CSV file, then click Analyze.");
    }

    public Parent getRoot() {
        return root;
    }

    public void shutdown() {
        service.shutdown();
    }

    // ================================================================= layout

    private void buildLayout() {
        Label title = new Label("Threat Detector");
        title.setStyle("-fx-font-size: 22px; -fx-font-weight: bold;");
        Label subtitle = new Label("Check URLs and text messages (email/SMS) for security threats, one by one or in batches.");
        subtitle.setStyle("-fx-text-fill: #6b7280;");

        typeBox.getItems().addAll("Auto-detect", "URL", "Message");
        typeBox.getSelectionModel().selectFirst();
        inputField.setPromptText("Paste a URL or type a message, then press Enter");
        HBox.setHgrow(inputField, Priority.ALWAYS);
        HBox inputRow = new HBox(8, typeBox, inputField, addBtn);
        inputRow.setAlignment(Pos.CENTER_LEFT);

        analyzeBtn.setStyle("-fx-base: #2563eb; -fx-text-fill: white; -fx-font-weight: bold;");
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        HBox actionRow = new HBox(8, browseBtn, analyzeBtn, cancelBtn, spacer, clearBtn);
        actionRow.setAlignment(Pos.CENTER_LEFT);

        VBox top = new VBox(10, title, subtitle, inputRow, actionRow);
        top.setPadding(new Insets(14, 14, 10, 14));
        root.setTop(top);

        BorderPane.setMargin(table, new Insets(0, 14, 0, 14));
        root.setCenter(table);

        detailsArea.setEditable(false);
        detailsArea.setWrapText(true);
        detailsArea.setPrefRowCount(5);
        detailsArea.setPromptText("Select a row to see the full input and the reasons behind its result.");

        summaryLabel.setStyle("-fx-font-weight: bold;");
        overallBar.setPrefWidth(220);
        HBox.setHgrow(messageLabel, Priority.ALWAYS);
        messageLabel.setMaxWidth(Double.MAX_VALUE);
        HBox statusBar = new HBox(10, messageLabel, overallBar);
        statusBar.setAlignment(Pos.CENTER_LEFT);

        VBox bottom = new VBox(8, detailsArea, summaryLabel, statusBar);
        bottom.setPadding(new Insets(10, 14, 12, 14));
        root.setBottom(bottom);
    }

    @SuppressWarnings("unchecked")
    private void buildTable() {
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.setPlaceholder(new Label("No inputs yet. Add a URL or message above, or load a CSV file."));

        TableColumn<ResultRow, Integer> idCol = new TableColumn<>("#");
        idCol.setCellValueFactory(c -> new ReadOnlyObjectWrapper<>(c.getValue().getItem().getId()));
        idCol.setPrefWidth(50);

        TableColumn<ResultRow, String> typeCol = new TableColumn<>("Type");
        typeCol.setCellValueFactory(c -> new ReadOnlyStringWrapper(c.getValue().getItem().getType().name()));
        typeCol.setPrefWidth(90);

        TableColumn<ResultRow, String> inputCol = new TableColumn<>("Input");
        inputCol.setCellValueFactory(c ->
                new ReadOnlyStringWrapper(c.getValue().getItem().getContent().replace('\n', ' ')));
        inputCol.setPrefWidth(340);

        TableColumn<ResultRow, Status> statusCol = new TableColumn<>("Status");
        statusCol.setCellValueFactory(c -> c.getValue().statusProperty());
        statusCol.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(Status s, boolean empty) {
                super.updateItem(s, empty);
                if (empty || s == null) {
                    setText(null);
                    setStyle("");
                } else {
                    setText(statusLabel(s));
                    setStyle("-fx-font-weight: bold; -fx-text-fill: " + statusColor(s) + ";");
                }
            }
        });
        statusCol.setPrefWidth(120);

        TableColumn<ResultRow, RiskLevel> riskCol = new TableColumn<>("Risk");
        riskCol.setCellValueFactory(c -> c.getValue().riskProperty());
        riskCol.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(RiskLevel r, boolean empty) {
                super.updateItem(r, empty);
                if (empty) {
                    setText(null);
                    setStyle("");
                } else if (r == null) {
                    setText("—");
                    setStyle("-fx-text-fill: #9ca3af;");
                } else {
                    setText(riskLabel(r));
                    setStyle("-fx-font-weight: bold; -fx-text-fill: " + riskColor(r) + ";");
                }
            }
        });
        riskCol.setPrefWidth(95);

        TableColumn<ResultRow, String> scoreCol = new TableColumn<>("Score");
        scoreCol.setCellValueFactory(c -> {
            ResultRow row = c.getValue();
            return Bindings.createStringBinding(
                    () -> row.getStatus() == Status.DONE ? String.valueOf(row.getScore()) : "—",
                    row.statusProperty(), row.scoreProperty());
        });
        scoreCol.setPrefWidth(65);

        TableColumn<ResultRow, Double> progCol = new TableColumn<>("Progress");
        progCol.setCellValueFactory(c -> c.getValue().progressProperty().asObject());
        progCol.setCellFactory(ProgressBarTableCell.forTableColumn());
        progCol.setPrefWidth(120);

        TableColumn<ResultRow, String> detailsCol = new TableColumn<>("Summary");
        detailsCol.setCellValueFactory(c -> {
            ResultRow row = c.getValue();
            return Bindings.createStringBinding(
                    () -> row.getDetails().replace("\n", "; "), row.detailsProperty());
        });
        detailsCol.setPrefWidth(320);

        table.getColumns().addAll(idCol, typeCol, inputCol, statusCol, riskCol, scoreCol, progCol, detailsCol);
    }

    private void wireEvents() {
        addBtn.setOnAction(e -> onAdd());
        inputField.setOnAction(e -> onAdd());
        browseBtn.setOnAction(e -> onBrowse());
        analyzeBtn.setOnAction(e -> onAnalyze());
        cancelBtn.setOnAction(e -> onCancel());
        clearBtn.setOnAction(e -> onClear());
        table.getSelectionModel().selectedItemProperty().addListener((o, a, b) -> refreshDetails());
    }

    // ================================================================= actions

    private void onAdd() {
        try {
            InputItem item = InputFactory.single(inputField.getText(), selectedType());
            addRows(List.of(item));
            inputField.clear();
            showInfo("Added 1 item (" + item.getType() + "). Click Analyze to check it.");
        } catch (InvalidInputException e) {
            showError(e.getMessage());
        }
        inputField.requestFocus();
    }

    private void onBrowse() {
        FileChooser fc = new FileChooser();
        fc.setTitle("Select a CSV file");
        fc.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("CSV files", "*.csv", "*.txt"),
                new FileChooser.ExtensionFilter("All files", "*.*"));
        File start = new File(System.getProperty("user.dir"));
        if (start.isDirectory()) {
            fc.setInitialDirectory(start);
        }
        File file = fc.showOpenDialog(root.getScene().getWindow());
        if (file != null) {
            loadCsvAsync(file.toPath());
        }
    }

    /** File reading and parsing happen on a background thread so the UI never freezes. */
    private void loadCsvAsync(Path path) {
        Task<CsvParseResult> task = new Task<>() {
            @Override
            protected CsvParseResult call() throws Exception {
                return csvParser.parse(path);
            }
        };
        browseBtn.setDisable(true);
        showInfo("Reading " + path.getFileName() + "…");

        task.setOnSucceeded(e -> {
            browseBtn.setDisable(false);
            CsvParseResult r = task.getValue();
            addRows(r.items());
            showInfo("Loaded " + r.items().size() + " item(s) from " + path.getFileName()
                    + (r.errors().isEmpty() ? "." : " (" + r.errors().size() + " row(s) skipped)."));
            if (!r.errors().isEmpty()) {
                showCsvErrors(r);
            }
        });
        task.setOnFailed(e -> {
            browseBtn.setDisable(false);
            Throwable ex = task.getException();
            showError(ex instanceof InvalidInputException
                    ? ex.getMessage()
                    : "Could not load file: " + ex.getMessage());
        });

        Thread t = new Thread(task, "csv-loader");
        t.setDaemon(true);
        t.start();
    }

    private void onAnalyze() {
        List<InputItem> pending = rows.stream()
                .filter(r -> r.getStatus() == Status.PENDING)
                .map(ResultRow::getItem)
                .collect(Collectors.toList());
        if (pending.isEmpty()) {
            showError("Nothing to analyze. Add an input or load a CSV file first.");
            return;
        }
        running = true;
        batchTotal = pending.size();
        batchDone = 0;
        overallBar.setProgress(0);
        updateButtons();
        showInfo("Analyzing " + batchTotal + " item(s)…");

        currentBatch = service.submit(pending, new FxListener());   // returns immediately
    }

    private void onCancel() {
        if (currentBatch != null) {
            currentBatch.cancel();
            cancelBtn.setDisable(true);
            showInfo("Cancelling… items not yet verified will be marked as Not verified.");
        }
    }

    private void onClear() {
        rows.clear();
        rowById.clear();
        overallBar.setProgress(0);
        refreshDetails();
        updateSummary();
        updateButtons();
        showInfo("Cleared.");
    }

    // ================================================ worker thread -> UI thread

    /** Every callback arrives on a WORKER thread, so each one hops to the JavaFX thread first. */
    private final class FxListener implements AnalysisListener {
        @Override
        public void onStarted(InputItem item) {
            Platform.runLater(() -> {
                ResultRow row = rowById.get(item.getId());
                if (row != null) {
                    row.setStatus(Status.RUNNING);
                    row.setProgress(0.0);
                    row.setDetails("Analysis in progress…");
                }
            });
        }

        @Override
        public void onProgress(InputItem item, int percent) {
            Platform.runLater(() -> {
                ResultRow row = rowById.get(item.getId());
                if (row != null && row.getStatus() == Status.RUNNING) {
                    row.setProgress(percent / 100.0);
                }
            });
        }

        @Override
        public void onCompleted(InputItem item, AnalysisResult result) {
            Platform.runLater(() -> applyResult(item, result));
        }

        @Override
        public void onBatchFinished() {
            Platform.runLater(MainView.this::batchFinished);
        }
    }

    private void applyResult(InputItem item, AnalysisResult result) {
        ResultRow row = rowById.get(item.getId());
        if (row == null) return;

        row.setStatus(result.status());
        row.setRisk(result.riskLevel());
        row.setScore(result.score());
        row.setDetails(String.join("\n", result.reasons()));
        if (result.status() == Status.DONE) {
            row.setProgress(1.0);
        }

        batchDone++;
        overallBar.setProgress((double) batchDone / batchTotal);
        refreshDetails();
        updateSummary();
    }

    private void batchFinished() {
        boolean cancelled = currentBatch != null && currentBatch.isCancelled();
        running = false;
        currentBatch = null;
        overallBar.setProgress(1.0);
        updateButtons();
        showInfo(cancelled ? "Analysis cancelled." : "Analysis finished.");
    }

    // ================================================================= helpers

    private void addRows(List<InputItem> items) {
        for (InputItem item : items) {
            ResultRow row = new ResultRow(item);
            rows.add(row);
            rowById.put(item.getId(), row);
        }
        if (!rows.isEmpty()) {
            table.scrollTo(rows.size() - 1);
        }
        updateSummary();
        updateButtons();
    }

    private InputType selectedType() {
        return switch (typeBox.getSelectionModel().getSelectedIndex()) {
            case 1 -> InputType.URL;
            case 2 -> InputType.MESSAGE;
            default -> null;   // auto-detect
        };
    }

    private void updateButtons() {
        long pending = rows.stream().filter(r -> r.getStatus() == Status.PENDING).count();
        analyzeBtn.setDisable(running || pending == 0);
        cancelBtn.setDisable(!running);
        clearBtn.setDisable(running || rows.isEmpty());
    }

    private void updateSummary() {
        long pending = countStatus(Status.PENDING) + countStatus(Status.RUNNING);
        summaryLabel.setText(String.format(
                "Total: %d   |   Waiting: %d   |   High: %d   |   Medium: %d   |   Low: %d   |   Not verified: %d   |   Errors: %d",
                rows.size(), pending,
                countRisk(RiskLevel.HIGH), countRisk(RiskLevel.MEDIUM), countRisk(RiskLevel.LOW),
                countStatus(Status.NOT_VERIFIED), countStatus(Status.ERROR)));
        updateButtons();
    }

    private long countStatus(Status s) {
        return rows.stream().filter(r -> r.getStatus() == s).count();
    }

    private long countRisk(RiskLevel level) {
        return rows.stream().filter(r -> r.getStatus() == Status.DONE && r.getRisk() == level).count();
    }

    private void refreshDetails() {
        ResultRow row = table.getSelectionModel().getSelectedItem();
        if (row == null) {
            detailsArea.clear();
            return;
        }
        detailsArea.setText("Input:\n" + row.getItem().getContent() + "\n\nResult:\n" + row.getDetails());
    }

    private void showInfo(String msg) {
        messageLabel.setStyle("-fx-text-fill: #374151;");
        messageLabel.setText(msg);
    }

    private void showError(String msg) {
        messageLabel.setStyle("-fx-text-fill: #b91c1c; -fx-font-weight: bold;");
        messageLabel.setText(msg);
    }

    private void showCsvErrors(CsvParseResult r) {
        String text = r.errors().stream()
                .limit(200)
                .map((RowError e) -> "Line " + e.line() + ": " + e.reason())
                .collect(Collectors.joining("\n"));
        if (r.errors().size() > 200) {
            text += "\n… and " + (r.errors().size() - 200) + " more";
        }
        TextArea area = new TextArea(text);
        area.setEditable(false);
        area.setWrapText(true);
        area.setPrefRowCount(10);

        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle("CSV loaded with problems");
        alert.setHeaderText(r.items().size() + " row(s) loaded, " + r.errors().size() + " row(s) skipped");
        alert.setContentText("Invalid rows were skipped and the rest were loaded.");
        alert.getDialogPane().setExpandableContent(area);
        alert.getDialogPane().setExpanded(true);
        alert.initOwner(root.getScene().getWindow());
        alert.show();
    }

    private static String statusLabel(Status s) {
        return switch (s) {
            case PENDING -> "Pending";
            case RUNNING -> "Running…";
            case DONE -> "Done";
            case NOT_VERIFIED -> "Not verified";
            case ERROR -> "Error";
        };
    }

    private static String statusColor(Status s) {
        return switch (s) {
            case PENDING -> "#6b7280";
            case RUNNING -> "#7c3aed";
            case DONE -> "#2563eb";
            case NOT_VERIFIED -> "#d97706";
            case ERROR -> "#b91c1c";
        };
    }

    private static String riskLabel(RiskLevel r) {
        return switch (r) {
            case LOW -> "Low";
            case MEDIUM -> "Medium";
            case HIGH -> "High";
            case UNKNOWN -> "Unknown";
        };
    }

    private static String riskColor(RiskLevel r) {
        return switch (r) {
            case LOW -> "#15803d";
            case MEDIUM -> "#d97706";
            case HIGH -> "#b91c1c";
            case UNKNOWN -> "#6b7280";
        };
    }
}