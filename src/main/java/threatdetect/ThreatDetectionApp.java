package threatdetect;

import javafx.animation.FadeTransition;
import javafx.animation.Interpolator;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.ParallelTransition;
import javafx.animation.PauseTransition;
import javafx.animation.SequentialTransition;
import javafx.animation.Timeline;
import javafx.animation.TranslateTransition;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.Observable;
import javafx.beans.binding.Bindings;
import javafx.beans.property.*;
import javafx.beans.value.ChangeListener;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.collections.transformation.SortedList;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.NodeOrientation;
import javafx.geometry.Pos;
import javafx.geometry.Rectangle2D;
import javafx.scene.Group;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.SnapshotParameters;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.image.WritableImage;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyCodeCombination;
import javafx.scene.input.KeyCombination;
import javafx.scene.input.KeyEvent;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.paint.CycleMethod;
import javafx.scene.paint.LinearGradient;
import javafx.scene.paint.Stop;
import javafx.scene.shape.Rectangle;
import javafx.scene.shape.SVGPath;
import javafx.scene.shape.StrokeLineCap;
import javafx.scene.shape.StrokeLineJoin;
import javafx.scene.transform.Transform;
import javafx.stage.FileChooser;
import javafx.stage.Screen;
import javafx.stage.Stage;
import javafx.util.Duration;

import java.io.File;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.prefs.Preferences;
import java.util.stream.Collectors;

/**
 * Threat Detection - user interface.
 *
 * Features: English / French / Arabic (with right-to-left layout), light and dark themes,
 * smooth animations, search and filters, CSV import and export, details panel, per-row timing.
 *
 * All backend work goes through ThreatAnalysisService and runs on a thread pool, so the
 * window never freezes. Every UI update happens on the JavaFX thread (Task callbacks).
 */
public class ThreatDetectionApp extends Application {

    /** The name of the application. Change this one line to rename it everywhere. */
    private static final String BRAND = "Diakrisis";
    /** The logo: a shield with a check mark (drawn on a 30 x 34 grid). */
    private static final String SHIELD_PATH =
            "M15 1 L27 5.5 V16.5 C27 24.8 21.7 30 15 33 C8.3 30 3 24.8 3 16.5 V5.5 Z";
    private static final String CHECK_PATH = "M9.5 16.8 L13.8 21.2 L21.5 12.5";

    private static final String PREF_DARK = "darkMode";
    private static final String PREF_LANG = "language";
    private static final String PREF_WORKERS = "workers";
    private static final String PREF_WIDTH = "windowWidth";
    private static final String PREF_HEIGHT = "windowHeight";
    private static final String PREF_DIR = "lastDirectory";
    private static final int[] WORKER_CHOICES = {1, 2, 4, 8};

    // ---- Backend hook: teammates replace the mock with the real service here ----
    private final ThreatAnalysisService service = new MockThreatAnalysisService();

    // ---- Data (JavaFX thread only) ----
    private final ObservableList<ScanItem> items = FXCollections.observableArrayList(
            item -> new Observable[]{item.riskProperty(), item.statusProperty(),
                    item.detailProperty(), item.elapsedMsProperty()});
    private final FilteredList<ScanItem> filtered = new FilteredList<>(items, i -> true);
    private final SortedList<ScanItem> sortedItems = new SortedList<>(filtered);

    private final Map<ScanItem, Task<AnalysisResult>> activeTasks = new HashMap<>();
    private final Set<ScanItem> runningItems = new HashSet<>();
    private final ThreadPoolExecutor pool = new ThreadPoolExecutor(4, 4, 0L, TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>(), r -> {
        Thread t = new Thread(r, "scan-worker");
        t.setDaemon(true);
        return t;
    });

    private final BooleanProperty busy = new SimpleBooleanProperty(false);
    private final BooleanProperty darkProp = new SimpleBooleanProperty(false);
    private final IntegerProperty batchTotal = new SimpleIntegerProperty(0);
    private final IntegerProperty batchDone = new SimpleIntegerProperty(0);
    private final IntegerProperty runningCount = new SimpleIntegerProperty(0);
    private final IntegerProperty unverifiedCount = new SimpleIntegerProperty(0);
    private final ObjectProperty<InputType> selectedType = new SimpleObjectProperty<>(InputType.URL);
    private final ObjectProperty<RiskLevel> riskFilter = new SimpleObjectProperty<>(null); // null = All
    private final Preferences prefs = Preferences.userNodeForPackage(ThreatDetectionApp.class);

    private int nextId = 1;
    private int workers = 4;
    private boolean cancelling = false;
    private long batchStartNanos;
    private Path lastDirectory;
    private String csvName;
    private int csvCount;
    private String statusKey = "msg.ready";
    private Object[] statusArgs = new Object[0];

    // ---- Controls ----
    private Stage stage;
    private StackPane appRoot;
    private BorderPane content;
    private Label toast;
    private SequentialTransition toastAnim;
    private ToggleButton themeToggle;
    private TextArea inputArea;
    private Label inputError;
    private Label csvLabel;
    private Label statusLabel;
    private TableView<ScanItem> table;
    private RiskBar riskBar;

    // responsive layout: panels side by side in wide windows, stacked in narrow ones
    private boolean narrow;
    private boolean layoutReady;
    private Node sideNode;
    private Node resultsNode;
    private ScrollPane bodyScroll;
    private HBox wideBody;
    private VBox narrowBody;
    private StackPane headerBox;
    private HBox headerWide;
    private VBox headerNarrow;
    private HBox brandBox;
    private HBox controlsBox;
    private Region headerSpacer;
    private final Map<RiskLevel, IntegerProperty> shownCounts = new EnumMap<>(RiskLevel.class);
    private final Map<RiskLevel, Timeline> countAnims = new EnumMap<>(RiskLevel.class);

    // filter bar
    private TextField searchField;
    private ToggleGroup filterGroup;
    private Label resultCount;

    // details panel
    private VBox detailsContent;
    private Label detailsHint;
    private Label detailsRisk;
    private Label detailsStatus;
    private Label detailsTime;
    private Label detailsReason;
    private TextArea detailsInput;

    // =====================================================================
    //  Start / stop
    // =====================================================================

    @Override
    public void start(Stage primaryStage) {
        this.stage = primaryStage;
        loadPreferences();

        Node header = buildHeader();
        Node side = buildSidePanel();
        Node results = buildResultsPanel();
        Node statusBar = buildStatusBar();

        sideNode = side;
        resultsNode = results;

        // Two arrangements of the same panels: side by side (wide window) or stacked (narrow window).
        wideBody = new HBox(18);
        wideBody.getStyleClass().add("body-box");
        narrowBody = new VBox(16);
        narrowBody.getStyleClass().add("body-box");

        // The middle part scrolls when the window is small, so the header and the
        // status bar always stay visible and reachable.
        bodyScroll = new ScrollPane();
        bodyScroll.setFitToWidth(true);
        bodyScroll.getStyleClass().add("body-scroll");

        content = new BorderPane();
        content.setTop(header);
        content.setCenter(bodyScroll);
        content.setBottom(statusBar);

        toast = new Label();
        toast.getStyleClass().add("toast");
        toast.setWrapText(true);
        toast.setMaxWidth(560);
        toast.setMouseTransparent(true);
        toast.setVisible(false);
        StackPane.setAlignment(toast, Pos.BOTTOM_CENTER);
        StackPane.setMargin(toast, new Insets(0, 0, 64, 0));

        appRoot = new StackPane(content, toast);
        StackPane.setAlignment(content, Pos.TOP_CENTER);
        appRoot.getStyleClass().add("app-root");
        applyThemeClass();
        applyOrientation();

        items.addListener((ListChangeListener<ScanItem>) c -> {
            updateChips();
            refreshDetails();
        });
        sortedItems.addListener((ListChangeListener<ScanItem>) c -> updateResultCount());
        table.getSelectionModel().getSelectedItems()
                .addListener((ListChangeListener<ScanItem>) c -> refreshDetails());
        I18n.langProperty().addListener((o, a, b) -> onLanguageChanged());
        updateChips();
        updateResultCount();
        refreshDetails();
        renderCsvLabel();

        // Remembered window size, never bigger than the screen
        Rectangle2D screen = Screen.getPrimary().getVisualBounds();
        double w = Math.min(Math.max(prefs.getDouble(PREF_WIDTH, 1280), 320), screen.getWidth());
        double h = Math.min(Math.max(prefs.getDouble(PREF_HEIGHT, 840), 240), screen.getHeight());

        Scene scene = new Scene(appRoot, w, h);
        var css = getClass().getResource("style.css");
        if (css != null) scene.getStylesheets().add(css.toExternalForm());
        installDragAndDrop(scene);
        installShortcuts(scene);
        applyLayoutMode(w);
        scene.widthProperty().addListener((o, a, b) -> applyLayoutMode(b.doubleValue()));

        stage.setTitle(windowTitle());
        Image appIcon = createAppIcon();
        if (appIcon != null) stage.getIcons().add(appIcon);
        stage.setScene(scene);

        // Gentle entrance: each block fades in and glides up a little after the previous one
        animateIn(header, 0);
        animateIn(side, 90);
        animateIn(results, 180);
        animateIn(statusBar, 270);
        stage.show();
    }

    @Override
    public void stop() {
        if (stage != null && stage.getScene() != null && !stage.isMaximized() && !stage.isIconified()) {
            prefs.putDouble(PREF_WIDTH, stage.getScene().getWidth());
            prefs.putDouble(PREF_HEIGHT, stage.getScene().getHeight());
        }
        pool.shutdownNow();
    }

    private void loadPreferences() {
        darkProp.set(prefs.getBoolean(PREF_DARK, false));

        String saved = prefs.get(PREF_LANG, null);
        String code = saved != null ? saved : Locale.getDefault().getLanguage();
        I18n.setLang(I18n.Lang.fromCode(code, I18n.Lang.EN));

        setWorkers(normalizeWorkers(prefs.getInt(PREF_WORKERS, 4)), false);

        String dir = prefs.get(PREF_DIR, null);
        if (dir != null) {
            try {
                Path p = Path.of(dir);
                if (Files.isDirectory(p)) lastDirectory = p;
            } catch (RuntimeException ignored) {
                // invalid saved path: start without a remembered folder
            }
        }
    }

    private void installShortcuts(Scene scene) {
        var acc = scene.getAccelerators();
        acc.put(new KeyCodeCombination(KeyCode.F5), this::analyze);
        acc.put(new KeyCodeCombination(KeyCode.ESCAPE), this::cancelAll);
        acc.put(new KeyCodeCombination(KeyCode.O, KeyCombination.SHORTCUT_DOWN), this::chooseCsv);
        acc.put(new KeyCodeCombination(KeyCode.E, KeyCombination.SHORTCUT_DOWN), this::exportCsv);
        acc.put(new KeyCodeCombination(KeyCode.F, KeyCombination.SHORTCUT_DOWN), () -> {
            searchField.requestFocus();
            searchField.selectAll();
        });
    }

    // =====================================================================
    //  Theme, language, animations
    // =====================================================================

    private void applyThemeClass() {
        appRoot.getStyleClass().remove("dark");
        if (darkProp.get()) appRoot.getStyleClass().add("dark");
    }

    private void applyOrientation() {
        appRoot.setNodeOrientation(I18n.lang().rtl()
                ? NodeOrientation.RIGHT_TO_LEFT
                : NodeOrientation.LEFT_TO_RIGHT);
    }

    private void setDark(boolean dark) {
        crossFade(() -> {
            darkProp.set(dark);
            applyThemeClass();
            prefs.putBoolean(PREF_DARK, dark);
        });
    }

    private void setLanguage(I18n.Lang lang) {
        crossFade(() -> I18n.setLang(lang));
    }

    private void onLanguageChanged() {
        prefs.put(PREF_LANG, I18n.lang().code());
        applyOrientation();
        stage.setTitle(windowTitle());
        inputError.setText("");
        renderStatus();
        renderCsvLabel();
        updateResultCount();
        refreshDetails();
        table.refresh();
    }

    /**
     * Smooth switch: take a picture of the window, apply the change underneath,
     * then fade the picture away. Used for theme and language changes.
     */
    private void crossFade(Runnable change) {
        if (appRoot == null || !stage.isShowing() || appRoot.getWidth() <= 0 || appRoot.getHeight() <= 0) {
            change.run();
            return;
        }
        SnapshotParameters params = new SnapshotParameters();
        params.setTransform(Transform.scale(stage.getRenderScaleX(), stage.getRenderScaleY()));
        WritableImage picture = appRoot.snapshot(params, null);

        ImageView overlay = new ImageView(picture);
        overlay.setFitWidth(appRoot.getWidth());
        overlay.setFitHeight(appRoot.getHeight());
        overlay.setPreserveRatio(false);
        overlay.setMouseTransparent(true);
        appRoot.getChildren().add(overlay);

        change.run();

        FadeTransition fade = new FadeTransition(Duration.millis(420), overlay);
        fade.setFromValue(1);
        fade.setToValue(0);
        fade.setInterpolator(Interpolator.EASE_BOTH);
        fade.setOnFinished(e -> appRoot.getChildren().remove(overlay));
        fade.play();
    }

    private static void animateIn(Node node, double delayMs) {
        node.setOpacity(0);
        node.setTranslateY(18);
        FadeTransition fade = new FadeTransition(Duration.millis(500), node);
        fade.setFromValue(0);
        fade.setToValue(1);
        TranslateTransition slide = new TranslateTransition(Duration.millis(500), node);
        slide.setFromY(18);
        slide.setToY(0);
        slide.setInterpolator(Interpolator.EASE_OUT);
        ParallelTransition both = new ParallelTransition(fade, slide);
        both.setDelay(Duration.millis(delayMs));
        both.play();
    }

    private void showToast(String message) {
        if (toastAnim != null) toastAnim.stop();
        toast.setText(message);
        toast.setVisible(true);
        toast.setOpacity(0);
        toast.setTranslateY(14);

        FadeTransition in = new FadeTransition(Duration.millis(240), toast);
        in.setToValue(1);
        TranslateTransition up = new TranslateTransition(Duration.millis(240), toast);
        up.setToY(0);
        up.setInterpolator(Interpolator.EASE_OUT);
        PauseTransition stay = new PauseTransition(Duration.millis(2600));
        FadeTransition out = new FadeTransition(Duration.millis(380), toast);
        out.setToValue(0);

        toastAnim = new SequentialTransition(new ParallelTransition(in, up), stay, out);
        toastAnim.setOnFinished(e -> toast.setVisible(false));
        toastAnim.play();
    }

    // =====================================================================
    //  Layout: header
    // =====================================================================

    private Node buildHeader() {
        Node logo = createLogo();

        Label title = new Label(BRAND);
        title.getStyleClass().add("app-title");
        Label subtitle = new Label();
        subtitle.textProperty().bind(I18n.bind("app.title"));
        subtitle.getStyleClass().add("app-subtitle");
        VBox texts = new VBox(2, title, subtitle);

        // Language switch: EN | FR | عربي
        ToggleGroup langGroup = new ToggleGroup();
        HBox langBox = new HBox(2);
        langBox.getStyleClass().add("lang-group");
        addLangToggle(langBox, langGroup, "EN", I18n.Lang.EN);
        addLangToggle(langBox, langGroup, "FR", I18n.Lang.FR);
        addLangToggle(langBox, langGroup, "عربي", I18n.Lang.AR);
        for (Toggle t : langGroup.getToggles()) {
            if (t.getUserData() == I18n.lang()) langGroup.selectToggle(t);
        }
        langGroup.selectedToggleProperty().addListener((o, old, now) -> {
            if (now == null) {
                if (old != null) old.setSelected(true);
            } else if (now.getUserData() != I18n.lang()) {
                setLanguage((I18n.Lang) now.getUserData());
            }
        });

        themeToggle = new ToggleButton();
        themeToggle.getStyleClass().add("theme-toggle");
        themeToggle.setSelected(darkProp.get());
        themeToggle.textProperty().bind(Bindings.createStringBinding(
                () -> darkProp.get() ? I18n.t("theme.light") : I18n.t("theme.dark"),
                darkProp, I18n.langProperty()));
        themeToggle.selectedProperty().addListener((o, was, now) -> setDark(now));

        Button helpBtn = new Button("?");
        helpBtn.getStyleClass().add("help-btn");
        helpBtn.setTooltip(tip("help.tip"));
        helpBtn.setOnAction(e ->
                showAlert(Alert.AlertType.INFORMATION, I18n.t("help.title"), I18n.t("help.body"), null));

        brandBox = new HBox(14, logo, texts);
        brandBox.setAlignment(Pos.CENTER_LEFT);
        Tooltip.install(brandBox, tip("app.subtitle"));
        controlsBox = new HBox(10, langBox, themeToggle, helpBtn);
        controlsBox.setAlignment(Pos.CENTER_LEFT);
        headerSpacer = new Region();
        HBox.setHgrow(headerSpacer, Priority.ALWAYS);

        headerWide = new HBox(14);
        headerWide.setAlignment(Pos.CENTER_LEFT);
        headerNarrow = new VBox(10);

        headerBox = new StackPane(); // filled by applyLayoutMode
        headerBox.getStyleClass().add("header");
        return headerBox;
    }

    private void addLangToggle(HBox box, ToggleGroup group, String text, I18n.Lang lang) {
        ToggleButton b = new ToggleButton(text);
        b.setToggleGroup(group);
        b.setUserData(lang);
        b.getStyleClass().add("lang-toggle");
        box.getChildren().add(b);
    }

    // =====================================================================
    //  Layout: side panel (three cards)
    // =====================================================================

    private Node buildSidePanel() {
        VBox column = new VBox(16, buildSingleCard(), buildBatchCard(), buildSettingsCard());
        column.setMinWidth(0);
        return column;
    }

    private Node buildSingleCard() {
        Label title = sectionTitle("single.title");

        // Segmented control: URL | Email | SMS
        ToggleGroup typeGroup = new ToggleGroup();
        HBox segments = new HBox(2);
        segments.getStyleClass().add("segments");
        for (InputType t : InputType.values()) {
            ToggleButton b = new ToggleButton();
            b.textProperty().bind(I18n.bindFn(t::toString));
            b.setToggleGroup(typeGroup);
            b.setUserData(t);
            b.getStyleClass().add("segment");
            b.setMaxWidth(Double.MAX_VALUE);
            HBox.setHgrow(b, Priority.ALWAYS);
            segments.getChildren().add(b);
        }
        typeGroup.selectToggle(typeGroup.getToggles().get(0));

        inputArea = new TextArea();
        inputArea.setWrapText(true);
        inputArea.setPrefRowCount(4);
        inputArea.promptTextProperty().bind(Bindings.createStringBinding(
                () -> selectedType.get() == InputType.URL
                        ? I18n.t("input.prompt.url")
                        : I18n.t("input.prompt.msg"),
                selectedType, I18n.langProperty()));
        inputArea.addEventFilter(KeyEvent.KEY_PRESSED, e -> {
            if (e.getCode() == KeyCode.ENTER && e.isShortcutDown()) {
                addSingle(true);
                e.consume();
            }
        });

        inputError = new Label();
        inputError.setWrapText(true);
        inputError.getStyleClass().add("inline-error");
        inputError.visibleProperty().bind(inputError.textProperty().isNotEmpty());
        inputError.managedProperty().bind(inputError.visibleProperty());
        inputArea.textProperty().addListener((o, a, b) -> inputError.setText(""));

        typeGroup.selectedToggleProperty().addListener((o, old, now) -> {
            if (now == null) {
                if (old != null) old.setSelected(true); // always keep one type selected
            } else {
                selectedType.set((InputType) now.getUserData());
                inputError.setText("");
            }
        });

        Button addBtn = button("btn.add");
        addBtn.setMaxWidth(Double.MAX_VALUE);
        addBtn.setOnAction(e -> addSingle(false));
        Button addRunBtn = button("btn.addrun", "primary");
        addRunBtn.setMaxWidth(Double.MAX_VALUE);
        addRunBtn.setOnAction(e -> addSingle(true));
        HBox.setHgrow(addBtn, Priority.ALWAYS);
        HBox.setHgrow(addRunBtn, Priority.ALWAYS);
        HBox buttons = new HBox(8, addBtn, addRunBtn);

        return card(title, segments, inputArea, inputError, buttons);
    }

    private Node buildBatchCard() {
        Label title = sectionTitle("batch.title");

        Label hint = new Label();
        hint.textProperty().bind(I18n.bind("batch.hint"));
        hint.setWrapText(true);
        hint.getStyleClass().add("muted");

        Button csvBtn = button("btn.csv");
        csvBtn.setMaxWidth(Double.MAX_VALUE);
        csvBtn.setTooltip(tip("tip.csv"));
        csvBtn.setOnAction(e -> chooseCsv());

        csvLabel = new Label();
        csvLabel.setWrapText(true);
        csvLabel.getStyleClass().add("muted-small");

        Button demoBtn = button("btn.demo");
        demoBtn.setMaxWidth(Double.MAX_VALUE);
        demoBtn.setOnAction(e -> loadDemoData());
        Label demoHint = new Label();
        demoHint.textProperty().bind(I18n.bind("demo.hint"));
        demoHint.setWrapText(true);
        demoHint.getStyleClass().add("muted-small");

        return card(title, hint, csvBtn, csvLabel, new Separator(), demoBtn, demoHint);
    }

    private Node buildSettingsCard() {
        Label title = sectionTitle("settings.title");

        Label label = new Label();
        label.textProperty().bind(I18n.bind("settings.workers"));

        ToggleGroup group = new ToggleGroup();
        HBox segments = new HBox(2);
        segments.getStyleClass().add("segments");
        for (int n : WORKER_CHOICES) {
            ToggleButton b = new ToggleButton(String.valueOf(n));
            b.setToggleGroup(group);
            b.setUserData(n);
            b.getStyleClass().add("segment");
            b.setMaxWidth(Double.MAX_VALUE);
            HBox.setHgrow(b, Priority.ALWAYS);
            segments.getChildren().add(b);
            if (n == workers) group.selectToggle(b);
        }
        group.selectedToggleProperty().addListener((o, old, now) -> {
            if (now == null) {
                if (old != null) old.setSelected(true);
            } else {
                setWorkers((Integer) now.getUserData(), true);
            }
        });

        Label hint = new Label();
        hint.textProperty().bind(I18n.bind("settings.workers.hint"));
        hint.setWrapText(true);
        hint.getStyleClass().add("muted-small");

        return card(title, label, segments, hint);
    }

    private static VBox card(Node... children) {
        VBox box = new VBox(12, children);
        box.getStyleClass().add("panel");
        return box;
    }

    // =====================================================================
    //  Layout: results panel
    // =====================================================================

    private Node buildResultsPanel() {
        table = buildTable();

        // Four summary cards with counters that count up smoothly
        HBox stats = new HBox(12);
        for (RiskLevel level : List.of(RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.NOT_VERIFIED)) {
            Label name = new Label();
            name.textProperty().bind(I18n.bindFn(() -> level.getLabel().toUpperCase(Locale.ROOT)));
            name.getStyleClass().add("stat-name");
            name.setMinWidth(0);

            Label number = new Label("0");
            number.getStyleClass().add("stat-number");
            IntegerProperty shown = new SimpleIntegerProperty(0);
            shown.addListener((o, a, b) -> number.setText(String.valueOf(b.intValue())));
            shownCounts.put(level, shown);

            VBox statCard = new VBox(2, name, number);
            statCard.getStyleClass().addAll("stat-card", level.getCssClass());
            statCard.setMinWidth(0);
            statCard.setPrefWidth(10); // same preferred width + equal growth = four equal cards on one line
            statCard.setMaxWidth(Double.MAX_VALUE);
            HBox.setHgrow(statCard, Priority.ALWAYS);
            stats.getChildren().add(statCard);
        }
        riskBar = new RiskBar();

        Button analyzeBtn = button("btn.analyze", "primary");
        analyzeBtn.setTooltip(tip("tip.analyze"));
        analyzeBtn.disableProperty().bind(Bindings.isEmpty(items));
        analyzeBtn.setOnAction(e -> analyze());

        Button cancelBtn = button("btn.cancel");
        cancelBtn.setTooltip(tip("tip.cancel"));
        cancelBtn.disableProperty().bind(busy.not());
        cancelBtn.setOnAction(e -> cancelAll());

        Button retryBtn = button("btn.retry");
        retryBtn.setTooltip(tip("tip.retry"));
        retryBtn.disableProperty().bind(unverifiedCount.isEqualTo(0));
        retryBtn.setOnAction(e -> retryNotVerified());

        Button removeBtn = button("btn.remove");
        removeBtn.disableProperty().bind(Bindings.isEmpty(table.getSelectionModel().getSelectedItems()));
        removeBtn.setOnAction(e -> removeSelected());

        Button clearBtn = button("btn.clear");
        clearBtn.disableProperty().bind(Bindings.isEmpty(items));
        clearBtn.setOnAction(e -> clearAll());

        Button exportBtn = button("btn.export");
        exportBtn.setTooltip(tip("tip.export"));
        exportBtn.disableProperty().bind(Bindings.isEmpty(sortedItems));
        exportBtn.setOnAction(e -> exportCsv());

        FlowPane actions = new FlowPane(8, 8, analyzeBtn, cancelBtn, retryBtn, removeBtn, clearBtn, exportBtn);
        actions.setAlignment(Pos.CENTER_LEFT);

        VBox panel = new VBox(14, stats, riskBar, actions, buildFilterBar(), table, buildDetailsPanel());
        VBox.setVgrow(table, Priority.ALWAYS);
        table.setMinHeight(140);
        panel.getStyleClass().add("panel");
        panel.setMinWidth(0);
        return panel;
    }

    private Node buildFilterBar() {
        searchField = new TextField();
        searchField.promptTextProperty().bind(I18n.bind("search.prompt"));
        searchField.setPrefWidth(300);
        searchField.textProperty().addListener((o, a, b) -> applyFilter());

        filterGroup = new ToggleGroup();
        HBox segments = new HBox(2);
        segments.getStyleClass().addAll("segments", "segments-small");
        addFilterToggle(segments, null);
        addFilterToggle(segments, RiskLevel.HIGH);
        addFilterToggle(segments, RiskLevel.MEDIUM);
        addFilterToggle(segments, RiskLevel.LOW);
        addFilterToggle(segments, RiskLevel.NOT_VERIFIED);
        filterGroup.selectToggle(filterGroup.getToggles().get(0));
        filterGroup.selectedToggleProperty().addListener((o, old, now) -> {
            if (now == null) {
                if (old != null) old.setSelected(true);
            } else {
                riskFilter.set((RiskLevel) now.getUserData());
                applyFilter();
            }
        });

        resultCount = new Label();
        resultCount.getStyleClass().add("muted-small");

        FlowPane bar = new FlowPane(12, 8, searchField, segments, resultCount);
        bar.setAlignment(Pos.CENTER_LEFT);
        bar.setRowValignment(javafx.geometry.VPos.CENTER);
        bar.widthProperty().addListener((o, a, b) ->
                searchField.setPrefWidth(Math.max(140, Math.min(360, b.doubleValue()))));
        return bar;
    }

    private void addFilterToggle(HBox box, RiskLevel level) {
        ToggleButton b = new ToggleButton();
        if (level == null) b.textProperty().bind(I18n.bind("filter.all"));
        else b.textProperty().bind(I18n.bindFn(level::getLabel));
        b.setToggleGroup(filterGroup);
        b.setUserData(level);
        b.getStyleClass().add("segment");
        box.getChildren().add(b);
    }

    private Node buildDetailsPanel() {
        Label title = new Label();
        title.textProperty().bind(I18n.bind("details.title"));
        title.getStyleClass().add("details-title");

        detailsTime = new Label();
        detailsTime.getStyleClass().add("muted-small");
        detailsStatus = new Label();
        detailsStatus.getStyleClass().add("muted");
        detailsRisk = new Label();
        detailsRisk.getStyleClass().add("badge");

        Button copyBtn = button("btn.copy");
        copyBtn.setOnAction(e -> copyInput(table.getSelectionModel().getSelectedItem()));

        FlowPane head = new FlowPane(10, 6, title, detailsTime, detailsStatus, detailsRisk, copyBtn);
        head.setAlignment(Pos.CENTER_LEFT);
        head.setRowValignment(javafx.geometry.VPos.CENTER);

        detailsInput = new TextArea();
        detailsInput.setEditable(false);
        detailsInput.setWrapText(true);
        detailsInput.setPrefRowCount(2);

        Label whyTitle = new Label();
        whyTitle.textProperty().bind(I18n.bind("details.why"));
        whyTitle.getStyleClass().add("details-label");
        detailsReason = new Label();
        detailsReason.setWrapText(true);

        detailsContent = new VBox(8, head, detailsInput, whyTitle, detailsReason);

        detailsHint = new Label();
        detailsHint.getStyleClass().add("muted");

        VBox box = new VBox(detailsHint, detailsContent);
        box.getStyleClass().add("details-card");
        return box;
    }

    private TableView<ScanItem> buildTable() {
        TableView<ScanItem> tv = new TableView<>(sortedItems);
        sortedItems.comparatorProperty().bind(tv.comparatorProperty());
        tv.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        tv.setFixedCellSize(46);
        tv.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
        tv.setOnKeyPressed(e -> {
            if (e.getCode() == KeyCode.DELETE) removeSelected();
        });
        tv.setRowFactory(t -> new StripeRow());

        Label emptyIcon = new Label("+");
        emptyIcon.getStyleClass().add("empty-icon");
        emptyIcon.setMinSize(68, 68);
        emptyIcon.setPrefSize(68, 68);
        emptyIcon.setAlignment(Pos.CENTER);
        Label emptyTitle = new Label();
        emptyTitle.textProperty().bind(I18n.bind("empty.title"));
        emptyTitle.getStyleClass().add("empty-title");
        Label emptyText = new Label();
        emptyText.textProperty().bind(I18n.bind("empty.text"));
        emptyText.getStyleClass().add("muted");
        VBox empty = new VBox(8, emptyIcon, emptyTitle, emptyText);
        empty.setAlignment(Pos.CENTER);
        tv.setPlaceholder(empty);

        TableColumn<ScanItem, Number> idCol = new TableColumn<>();
        idCol.textProperty().bind(I18n.bind("col.id"));
        idCol.setCellValueFactory(c -> new ReadOnlyIntegerWrapper(c.getValue().getId()));
        idCol.setPrefWidth(46);
        idCol.setMaxWidth(70);

        TableColumn<ScanItem, String> inputCol = new TableColumn<>();
        inputCol.textProperty().bind(I18n.bind("col.input"));
        inputCol.setCellValueFactory(c -> c.getValue().inputProperty());
        inputCol.setCellFactory(col -> new EllipsisCell(false));
        inputCol.setPrefWidth(250);

        TableColumn<ScanItem, InputType> typeCol = new TableColumn<>();
        typeCol.textProperty().bind(I18n.bind("col.type"));
        typeCol.setCellValueFactory(c -> c.getValue().typeProperty());
        typeCol.setPrefWidth(76);

        TableColumn<ScanItem, RiskLevel> riskCol = new TableColumn<>();
        riskCol.textProperty().bind(I18n.bind("col.risk"));
        riskCol.setCellValueFactory(c -> c.getValue().riskProperty());
        riskCol.setCellFactory(col -> new RiskCell());
        riskCol.setPrefWidth(140);
        riskCol.setMinWidth(130);

        TableColumn<ScanItem, ScanStatus> statusCol = new TableColumn<>();
        statusCol.textProperty().bind(I18n.bind("col.status"));
        statusCol.setCellValueFactory(c -> c.getValue().statusProperty());
        statusCol.setCellFactory(col -> new StatusCell());
        statusCol.setPrefWidth(130);
        statusCol.setMinWidth(130);

        TableColumn<ScanItem, Number> progressCol = new TableColumn<>();
        progressCol.textProperty().bind(I18n.bind("col.progress"));
        progressCol.setCellValueFactory(c -> c.getValue().progressProperty());
        progressCol.setCellFactory(col -> new ProgressCell());
        progressCol.setSortable(false);
        progressCol.setPrefWidth(110);

        TableColumn<ScanItem, Number> timeCol = new TableColumn<>();
        timeCol.textProperty().bind(I18n.bind("col.time"));
        timeCol.setCellValueFactory(c -> c.getValue().elapsedMsProperty());
        timeCol.setCellFactory(col -> new TimeCell());
        timeCol.setPrefWidth(80);

        TableColumn<ScanItem, String> detailCol = new TableColumn<>();
        detailCol.textProperty().bind(I18n.bind("col.details"));
        detailCol.setCellValueFactory(c -> c.getValue().detailProperty());
        detailCol.setCellFactory(col -> new EllipsisCell(true));
        detailCol.setPrefWidth(250);

        tv.getColumns().addAll(List.of(idCol, inputCol, typeCol, riskCol, statusCol, progressCol, timeCol, detailCol));
        tv.widthProperty().addListener((o, a, b) ->
                Platform.runLater(() -> adjustTablePolicy(b.doubleValue())));
        return tv;
    }

    private Node buildStatusBar() {
        statusLabel = new Label(I18n.t("msg.ready"));
        statusLabel.setMinWidth(0);

        Label running = new Label();
        running.getStyleClass().add("run-pill");
        running.textProperty().bind(Bindings.createStringBinding(
                () -> runningCount.get() == 0 ? "" : I18n.t("run.count", runningCount.get()),
                runningCount, I18n.langProperty()));
        running.visibleProperty().bind(runningCount.greaterThan(0));
        running.managedProperty().bind(running.visibleProperty());

        Label counter = new Label();
        counter.getStyleClass().add("muted");
        counter.textProperty().bind(Bindings.createStringBinding(
                () -> batchTotal.get() == 0 ? "" : I18n.t("counter.done", batchDone.get(), batchTotal.get()),
                batchTotal, batchDone, I18n.langProperty()));

        ProgressBar overall = new ProgressBar(0);
        overall.setPrefWidth(200);
        overall.setMinWidth(60);
        overall.setPrefHeight(8);
        overall.progressProperty().bind(Bindings.createDoubleBinding(
                () -> batchTotal.get() == 0 ? 0.0 : (double) batchDone.get() / batchTotal.get(),
                batchTotal, batchDone));

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        HBox bar = new HBox(14, statusLabel, spacer, running, counter, overall);
        bar.setAlignment(Pos.CENTER_LEFT);
        bar.getStyleClass().add("status-bar");
        return bar;
    }

    // =====================================================================
    //  Responsive layout
    // =====================================================================

    /** Stacks the panels in narrow windows (split-screen) and puts them side by side in wide ones. */
    private void applyLayoutMode(double width) {
        boolean wantNarrow = narrow ? width < 940 : width < 900;
        if (layoutReady && wantNarrow == narrow) return;
        layoutReady = true;
        narrow = wantNarrow;

        appRoot.getStyleClass().remove("compact");
        if (narrow) appRoot.getStyleClass().add("compact");

        wideBody.getChildren().clear();
        narrowBody.getChildren().clear();
        headerWide.getChildren().clear();
        headerNarrow.getChildren().clear();
        Region side = (Region) sideNode;

        if (narrow) {
            side.setPrefWidth(Region.USE_COMPUTED_SIZE);
            side.setMaxWidth(Double.MAX_VALUE);
            VBox.setVgrow(resultsNode, Priority.NEVER);
            narrowBody.getChildren().addAll(sideNode, resultsNode);
            bodyScroll.setFitToHeight(false);
            bodyScroll.setContent(narrowBody);

            headerNarrow.getChildren().addAll(brandBox, controlsBox);
            headerBox.getChildren().setAll(headerNarrow);
        } else {
            side.setPrefWidth(372);
            side.setMaxWidth(420);
            HBox.setHgrow(resultsNode, Priority.ALWAYS);
            wideBody.getChildren().addAll(sideNode, resultsNode);
            bodyScroll.setFitToHeight(true);
            bodyScroll.setContent(wideBody);

            headerWide.getChildren().addAll(brandBox, headerSpacer, controlsBox);
            headerBox.getChildren().setAll(headerWide);
        }
    }

    /** Fit the columns to the table when there is room; scroll sideways when there is not. */
    private void adjustTablePolicy(double width) {
        if (table == null) return;
        boolean constrained = table.getColumnResizePolicy() == TableView.CONSTRAINED_RESIZE_POLICY;
        if (constrained && width < 860) table.setColumnResizePolicy(TableView.UNCONSTRAINED_RESIZE_POLICY);
        else if (!constrained && width > 900) table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
    }

    // =====================================================================
    //  Logo and application icon
    // =====================================================================

    private static String windowTitle() {
        return BRAND + " \u2014 " + I18n.t("app.title");
    }

    /** The header logo. Colors come from the stylesheet, so it follows the light and dark themes. */
    private static Node createLogo() {
        SVGPath shield = new SVGPath();
        shield.setContent(SHIELD_PATH);
        shield.getStyleClass().add("logo-shield");
        SVGPath check = new SVGPath();
        check.setContent(CHECK_PATH);
        check.getStyleClass().add("logo-check");

        StackPane box = new StackPane(new Group(shield, check));
        box.getStyleClass().add("logo-box");
        box.setMinSize(48, 48);
        box.setPrefSize(48, 48);
        box.setMaxSize(48, 48);
        box.setNodeOrientation(NodeOrientation.LEFT_TO_RIGHT); // the drawing is never mirrored
        return box;
    }

    /** The window and taskbar icon: the same shield on a royal-blue rounded square. */
    private static Image createAppIcon() {
        try {
            Rectangle background = new Rectangle(256, 256);
            background.setArcWidth(60);
            background.setArcHeight(60);
            background.setFill(new LinearGradient(0, 0, 1, 1, true, CycleMethod.NO_CYCLE,
                    new Stop(0, Color.web("#1E40AF")), new Stop(1, Color.web("#2563EB"))));

            SVGPath shield = new SVGPath();
            shield.setContent(SHIELD_PATH);
            shield.setFill(Color.web("#FFFFFF", 0.16));
            shield.setStroke(Color.WHITE);
            shield.setStrokeWidth(1.8);
            shield.setStrokeLineJoin(StrokeLineJoin.ROUND);

            SVGPath check = new SVGPath();
            check.setContent(CHECK_PATH);
            check.setFill(null);
            check.setStroke(Color.WHITE);
            check.setStrokeWidth(2.4);
            check.setStrokeLineCap(StrokeLineCap.ROUND);
            check.setStrokeLineJoin(StrokeLineJoin.ROUND);

            Group mark = new Group(shield, check);
            mark.setScaleX(5.6);
            mark.setScaleY(5.6);

            StackPane icon = new StackPane(background, mark);
            icon.setMinSize(256, 256);
            icon.setPrefSize(256, 256);
            icon.setMaxSize(256, 256);

            SnapshotParameters params = new SnapshotParameters();
            params.setFill(Color.TRANSPARENT);
            return icon.snapshot(params, null);
        } catch (RuntimeException e) {
            return null; // no icon is better than no application
        }
    }

    // ---- small builders ----

    private static Label sectionTitle(String key) {
        Label l = new Label();
        l.textProperty().bind(I18n.bind(key));
        l.getStyleClass().add("section-title");
        return l;
    }

    private static Button button(String key, String... styleClasses) {
        Button b = new Button();
        b.textProperty().bind(I18n.bind(key));
        b.getStyleClass().addAll(styleClasses);
        return b;
    }

    private static Tooltip tip(String key) {
        Tooltip t = new Tooltip();
        t.textProperty().bind(I18n.bind(key));
        return t;
    }

    // =====================================================================
    //  Filter, details, summary
    // =====================================================================

    private void applyFilter() {
        String q = searchField.getText() == null ? "" : searchField.getText().strip().toLowerCase(Locale.ROOT);
        RiskLevel level = riskFilter.get();
        filtered.setPredicate(i ->
                (level == null || i.getRisk() == level)
                        && (q.isEmpty()
                        || i.getInput().toLowerCase(Locale.ROOT).contains(q)
                        || i.getDetail().toLowerCase(Locale.ROOT).contains(q)));
    }

    private void clearFilters() {
        searchField.clear();
        filterGroup.selectToggle(filterGroup.getToggles().get(0));
    }

    private void updateResultCount() {
        int shown = sortedItems.size();
        int total = items.size();
        if (total == 0) resultCount.setText("");
        else if (shown == total) resultCount.setText(total == 1 ? I18n.t("count.one") : I18n.t("count.items", total));
        else resultCount.setText(I18n.t("count.showing", shown, total));
    }

    private void refreshDetails() {
        List<ScanItem> selected = table.getSelectionModel().getSelectedItems();
        boolean single = selected.size() == 1 && selected.get(0) != null;
        detailsContent.setVisible(single);
        detailsContent.setManaged(single);
        detailsHint.setVisible(!single);
        detailsHint.setManaged(!single);
        if (!single) {
            detailsHint.setText(selected.size() > 1
                    ? I18n.t("details.multi", selected.size())
                    : I18n.t("details.hint"));
            return;
        }
        ScanItem it = selected.get(0);
        detailsInput.setText(it.getInput());
        detailsReason.setText(it.getDetail());
        detailsStatus.setText(it.getStatus().getLabel());
        detailsTime.setText(it.getElapsedMs() >= 0 ? I18n.t("details.time", formatMs(it.getElapsedMs())) : "");
        RiskLevel risk = it.getRisk();
        detailsRisk.setText(risk.getLabel());
        detailsRisk.getStyleClass().removeIf(s -> s.startsWith("risk-"));
        detailsRisk.getStyleClass().add(risk.getCssClass());
    }

    private void updateChips() {
        Map<RiskLevel, Long> counts = items.stream()
                .collect(Collectors.groupingBy(ScanItem::getRisk, Collectors.counting()));
        for (Map.Entry<RiskLevel, IntegerProperty> e : shownCounts.entrySet()) {
            int target = counts.getOrDefault(e.getKey(), 0L).intValue();
            IntegerProperty shown = e.getValue();
            if (shown.get() == target) continue;
            Timeline old = countAnims.get(e.getKey());
            if (old != null) old.stop();
            Timeline tl = new Timeline(new KeyFrame(Duration.millis(450),
                    new KeyValue(shown, target, Interpolator.EASE_OUT)));
            countAnims.put(e.getKey(), tl);
            tl.play();
        }
        riskBar.setCounts(counts);
        unverifiedCount.set(counts.getOrDefault(RiskLevel.NOT_VERIFIED, 0L).intValue());
    }

    private void copyInput(ScanItem item) {
        if (item == null) return;
        ClipboardContent clip = new ClipboardContent();
        clip.putString(item.getInput());
        Clipboard.getSystemClipboard().setContent(clip);
        setStatus("msg.copied");
        showToast(I18n.t("toast.copied"));
    }

    // =====================================================================
    //  Adding items
    // =====================================================================

    private void addSingle(boolean analyzeNow) {
        String text = inputArea.getText() == null ? "" : inputArea.getText().strip();
        InputType type = selectedType.get();

        if (text.isEmpty()) {
            inputError.setText(type == InputType.URL ? I18n.t("err.empty.url") : I18n.t("err.empty.msg"));
            inputArea.requestFocus();
            return;
        }
        if (text.length() > CsvInputLoader.MAX_CONTENT_LENGTH) {
            inputError.setText(I18n.t("err.toolong", text.length(), CsvInputLoader.MAX_CONTENT_LENGTH));
            inputArea.requestFocus();
            return;
        }

        clearFilters(); // so the new row is always visible
        ScanItem item = addItem(type, text);
        inputArea.clear();
        table.getSelectionModel().clearSelection();
        table.getSelectionModel().select(item);
        table.scrollTo(item);
        setStatus("msg.added", item.getId());
        if (analyzeNow) analyze();
    }

    private ScanItem addItem(InputType type, String text) {
        ScanItem item = new ScanItem(nextId++, type, text);
        items.add(item);
        return item;
    }

    private void loadDemoData() {
        addItem(InputType.URL, "https://www.univ-constantine2.dz/");
        addItem(InputType.URL, "http://192.168.1.77/secure-login/verify");
        addItem(InputType.URL, "http://paypal.com@account-update.example.net/login");
        addItem(InputType.URL, "https://shop.example.org/cart");
        addItem(InputType.URL, "htp:/broken url");
        addItem(InputType.URL, "https://slow.example.com/timeout-test");
        addItem(InputType.URL, "https://api.example.com/ratelimit");
        addItem(InputType.SMS, "URGENT: your account is suspended. Verify your password within 24 hours at http://bit.example/x");
        addItem(InputType.SMS, "Hi, are we still meeting at 6 pm?");
        addItem(InputType.EMAIL, "Dear customer, you are a winner! Claim your gift card now. Send your card number and PIN to confirm.");
        addItem(InputType.EMAIL, "Notes from today's concurrency lecture are attached.");
        setStatus("msg.demo", 11);
    }

    // =====================================================================
    //  CSV import / export (file work runs off the JavaFX thread)
    // =====================================================================

    private void rememberDirectory(File file) {
        if (file != null && file.getParentFile() != null) {
            lastDirectory = file.getParentFile().toPath();
            prefs.put(PREF_DIR, lastDirectory.toString());
        }
    }

    private void renderCsvLabel() {
        csvLabel.setText(csvName == null ? I18n.t("csv.none") : I18n.t("csv.loaded", csvName, csvCount));
    }

    private void chooseCsv() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(I18n.t("dialog.csv"));
        chooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter(I18n.t("filter.csv"), "*.csv"),
                new FileChooser.ExtensionFilter(I18n.t("filter.files"), "*.*"));
        if (lastDirectory != null && Files.isDirectory(lastDirectory)) {
            chooser.setInitialDirectory(lastDirectory.toFile());
        }
        File file = chooser.showOpenDialog(stage);
        if (file == null) {
            setStatus("msg.nofile");
            return;
        }
        rememberDirectory(file);
        importCsv(file.toPath());
    }

    private void importCsv(Path path) {
        setStatus("msg.reading", path.getFileName().toString());
        Task<CsvInputLoader.LoadResult> task = new Task<>() {
            @Override
            protected CsvInputLoader.LoadResult call() throws Exception {
                return CsvInputLoader.load(path);
            }
        };
        task.setOnSucceeded(e -> onCsvLoaded(path, task.getValue()));
        task.setOnFailed(e -> {
            csvName = null;
            renderCsvLabel();
            setStatus("msg.readfail");
            showAlert(Alert.AlertType.ERROR, I18n.t("alert.err.read"), describe(task.getException()), null);
        });
        Thread t = new Thread(task, "csv-loader");
        t.setDaemon(true);
        t.start();
    }

    private void onCsvLoaded(Path path, CsvInputLoader.LoadResult result) {
        String name = path.getFileName().toString();
        int ok = result.entries().size();
        int skipped = result.errors().size();

        result.entries().forEach(en -> addItem(en.type(), en.content()));
        csvName = name;
        csvCount = ok;
        renderCsvLabel();

        if (ok == 0) {
            setStatus("msg.nothingimport", name);
            showAlert(Alert.AlertType.WARNING, I18n.t("alert.noRows", name),
                    skipped == 0 ? I18n.t("alert.empty") : I18n.t("alert.allbad"),
                    result.errors());
        } else if (skipped > 0) {
            setStatus("msg.imported.skipped", ok, name, skipped);
            showToast(I18n.t("toast.imported", ok));
            showAlert(Alert.AlertType.WARNING, I18n.t("alert.partial.header", ok, skipped),
                    I18n.t("alert.partial.body"), result.errors());
        } else {
            setStatus("msg.imported", ok, name);
            showToast(I18n.t("toast.imported", ok));
        }
    }

    /** Saves the rows currently shown in the table (so filters and sorting are respected). */
    private void exportCsv() {
        if (sortedItems.isEmpty()) {
            setStatus("msg.noexport");
            return;
        }
        FileChooser chooser = new FileChooser();
        chooser.setTitle(I18n.t("dialog.export"));
        chooser.setInitialFileName("threat-results.csv");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter(I18n.t("filter.csv"), "*.csv"));
        if (lastDirectory != null && Files.isDirectory(lastDirectory)) {
            chooser.setInitialDirectory(lastDirectory.toFile());
        }
        File file = chooser.showSaveDialog(stage);
        if (file == null) {
            setStatus("msg.exportcancel");
            return;
        }
        rememberDirectory(file);
        final Path target = file.getName().toLowerCase(Locale.ROOT).endsWith(".csv")
                ? file.toPath()
                : file.toPath().resolveSibling(file.getName() + ".csv");

        // Copy the data on the JavaFX thread, write the file on a background thread.
        final List<List<String>> rows = new ArrayList<>();
        rows.add(Arrays.asList(I18n.t("exp.id"), I18n.t("exp.type"), I18n.t("exp.input"), I18n.t("exp.risk"),
                I18n.t("exp.status"), I18n.t("exp.seconds"), I18n.t("exp.details")));
        for (ScanItem it : sortedItems) {
            String seconds = it.getElapsedMs() < 0 ? ""
                    : String.format(Locale.ROOT, "%.1f", it.getElapsedMs() / 1000.0);
            rows.add(Arrays.asList(String.valueOf(it.getId()), it.getType().toString(), it.getInput(),
                    it.getRisk().getLabel(), it.getStatus().getLabel(), seconds, it.getDetail()));
        }

        Task<Void> task = new Task<>() {
            @Override
            protected Void call() throws Exception {
                CsvExporter.write(target, rows);
                return null;
            }
        };
        task.setOnSucceeded(e -> {
            setStatus("msg.exported", rows.size() - 1, target.getFileName().toString());
            showToast(I18n.t("toast.exported"));
        });
        task.setOnFailed(e -> {
            Throwable ex = task.getException();
            String msg = ex instanceof FileSystemException ? I18n.t("alert.save.locked") : describe(ex);
            setStatus("msg.exportfail");
            showAlert(Alert.AlertType.ERROR, I18n.t("alert.save.err"), msg, null);
        });
        Thread t = new Thread(task, "csv-exporter");
        t.setDaemon(true);
        t.start();
        setStatus("msg.exporting");
    }

    private void installDragAndDrop(Scene scene) {
        scene.setOnDragOver(e -> {
            if (e.getDragboard().hasFiles()) e.acceptTransferModes(TransferMode.COPY);
            e.consume();
        });
        scene.setOnDragDropped(e -> {
            List<File> files = e.getDragboard().getFiles();
            boolean ok = files != null && !files.isEmpty();
            if (ok) importCsv(files.get(0).toPath());
            e.setDropCompleted(ok);
            e.consume();
        });
    }

    // =====================================================================
    //  Running checks (one Task per item, N in parallel)
    // =====================================================================

    private static int normalizeWorkers(int n) {
        if (n <= 1) return 1;
        if (n <= 2) return 2;
        if (n <= 4) return 4;
        return 8;
    }

    /** Resizes the pool while the app runs. The order matters: core size may never exceed max size. */
    private void setWorkers(int n, boolean save) {
        workers = n;
        if (n > pool.getMaximumPoolSize()) {
            pool.setMaximumPoolSize(n);
            pool.setCorePoolSize(n);
        } else {
            pool.setCorePoolSize(n);
            pool.setMaximumPoolSize(n);
        }
        if (save) prefs.putInt(PREF_WORKERS, n);
    }

    private void analyze() {
        runItems(items.stream().filter(i -> i.getStatus() != ScanStatus.COMPLETED).toList(), "msg.alldone");
    }

    private void retryNotVerified() {
        runItems(items.stream().filter(i -> i.getStatus() == ScanStatus.NOT_VERIFIED).toList(), "msg.noretry");
    }

    private void runItems(List<ScanItem> candidates, String nothingToDoKey) {
        List<ScanItem> todo = candidates.stream()
                .filter(i -> !activeTasks.containsKey(i))
                .toList();
        if (todo.isEmpty()) {
            setStatus(items.isEmpty() ? "msg.addfirst" : nothingToDoKey);
            return;
        }
        if (activeTasks.isEmpty()) {
            batchTotal.set(0);
            batchDone.set(0);
            batchStartNanos = System.nanoTime();
        }
        cancelling = false;
        batchTotal.set(batchTotal.get() + todo.size());
        todo.forEach(this::submit);
        busy.set(true);
        updateRunStatus();
    }

    private void submit(ScanItem item) {
        item.resetForRun();
        InputType type = item.getType();
        String text = item.getInput();

        Task<AnalysisResult> task = new Task<>() {
            @Override
            protected AnalysisResult call() throws Exception {
                return service.analyze(type, text, p -> updateProgress(p, 1.0));
            }
        };

        item.progressProperty().bind(task.progressProperty());
        task.runningProperty().addListener((obs, was, now) -> {
            if (now) {
                runningItems.add(item);
                runningCount.set(runningItems.size());
                item.markStarted();
                item.setStatus(ScanStatus.ANALYZING);
                item.setDetail(I18n.t("item.checking"));
            }
        });
        task.setOnSucceeded(e -> finish(item, task.getValue()));
        task.setOnFailed(e -> finish(item,
                AnalysisResult.notVerified(I18n.t("item.error", describe(task.getException())))));
        task.setOnCancelled(e -> {
            item.markCancelled();
            release(item);
        });

        activeTasks.put(item, task);
        pool.execute(task);
    }

    private void finish(ScanItem item, AnalysisResult result) {
        item.progressProperty().unbind();
        item.setProgress(1.0);
        item.markFinished();
        item.applyResult(result); // never shows Low/Medium/High unless the check really completed
        release(item);
    }

    private void release(ScanItem item) {
        if (runningItems.remove(item)) runningCount.set(runningItems.size());
        if (activeTasks.remove(item) != null) {
            batchDone.set(batchDone.get() + 1);
            updateRunStatus();
        }
    }

    private void updateRunStatus() {
        if (!activeTasks.isEmpty()) {
            setStatus("msg.analyzing", batchDone.get(), batchTotal.get());
            return;
        }
        busy.set(false);
        if (cancelling) {
            setStatus("msg.cancelled");
            cancelling = false;
            return;
        }
        long unverified = items.stream().filter(i -> i.getRisk() == RiskLevel.NOT_VERIFIED).count();
        long high = items.stream().filter(i -> i.getRisk() == RiskLevel.HIGH).count();
        String time = formatMs((System.nanoTime() - batchStartNanos) / 1_000_000);
        if (unverified > 0) setStatus("msg.done.unv", batchDone.get(), unverified, time);
        else setStatus("msg.done", batchDone.get(), time);
        showToast(high > 0 ? I18n.t("toast.done.high", high) : I18n.t("toast.done"));
    }

    private void cancelAll() {
        if (activeTasks.isEmpty()) return;
        cancelling = true;
        new ArrayList<>(activeTasks.values()).forEach(t -> t.cancel(true));
    }

    private void removeSelected() {
        removeItems(new ArrayList<>(table.getSelectionModel().getSelectedItems()));
    }

    private void removeItems(List<ScanItem> toRemove) {
        if (toRemove.isEmpty()) return;
        List<ScanItem> copy = new ArrayList<>(toRemove);
        for (ScanItem it : copy) {
            Task<AnalysisResult> t = activeTasks.get(it);
            if (t != null) t.cancel(true);
        }
        items.removeAll(copy);
        setStatus(copy.size() == 1 ? "msg.removed.one" : "msg.removed", copy.size());
    }

    private void clearAll() {
        new ArrayList<>(activeTasks.values()).forEach(t -> t.cancel(true));
        activeTasks.clear();
        runningItems.clear();
        runningCount.set(0);
        items.clear();
        clearFilters();
        batchTotal.set(0);
        batchDone.set(0);
        busy.set(false);
        cancelling = false;
        setStatus("msg.cleared");
    }

    // =====================================================================
    //  Helpers
    // =====================================================================

    /** The status bar remembers its message key, so it can be translated when the language changes. */
    private void setStatus(String key, Object... args) {
        statusKey = key;
        statusArgs = args;
        renderStatus();
    }

    private void renderStatus() {
        statusLabel.setText(I18n.t(statusKey, statusArgs));
    }

    private static String formatMs(long ms) {
        return ms < 1000 ? ms + " ms" : String.format(Locale.ROOT, "%.1f s", ms / 1000.0);
    }

    private static String describe(Throwable t) {
        if (t == null) return "?";
        String m = t.getMessage();
        return (m == null || m.isBlank()) ? t.getClass().getSimpleName() : m;
    }

    private void showAlert(Alert.AlertType type, String header, String message, List<String> details) {
        Alert alert = new Alert(type);
        alert.initOwner(stage);
        alert.setTitle(I18n.t("app.title"));
        alert.setHeaderText(header);
        alert.setContentText(message);
        DialogPane pane = alert.getDialogPane();
        pane.getStylesheets().addAll(stage.getScene().getStylesheets());
        if (darkProp.get()) pane.getStyleClass().add("dark");
        pane.setNodeOrientation(appRoot.getNodeOrientation());
        if (details != null && !details.isEmpty()) {
            TextArea area = new TextArea(String.join("\n", details));
            area.setEditable(false);
            area.setPrefRowCount(8);
            pane.setExpandableContent(area);
            pane.setExpanded(true);
        }
        alert.showAndWait();
    }

    // =====================================================================
    //  Table rows and cells
    // =====================================================================

    /** A row with a colored edge that shows its risk level at a glance, plus a right-click menu. */
    private class StripeRow extends TableRow<ScanItem> {
        private ScanItem watched;
        private final ChangeListener<RiskLevel> riskListener = (o, a, b) -> applyStripe(b);

        StripeRow() {
            MenuItem reanalyze = new MenuItem();
            reanalyze.textProperty().bind(I18n.bind("menu.reanalyze"));
            reanalyze.setOnAction(e -> {
                ScanItem it = getItem();
                if (it != null) runItems(List.of(it), "msg.alldone");
            });

            MenuItem copy = new MenuItem();
            copy.textProperty().bind(I18n.bind("menu.copy"));
            copy.setOnAction(e -> copyInput(getItem()));

            MenuItem remove = new MenuItem();
            remove.textProperty().bind(I18n.bind("menu.remove"));
            remove.setOnAction(e -> {
                ScanItem it = getItem();
                if (it == null) return;
                if (table.getSelectionModel().getSelectedItems().contains(it)) removeSelected();
                else removeItems(List.of(it));
            });

            ContextMenu menu = new ContextMenu(reanalyze, copy, new SeparatorMenuItem(), remove);
            contextMenuProperty().bind(
                    Bindings.when(emptyProperty()).then((ContextMenu) null).otherwise(menu));
        }

        @Override
        protected void updateItem(ScanItem item, boolean empty) {
            super.updateItem(item, empty);
            if (watched != null) watched.riskProperty().removeListener(riskListener);
            watched = (empty || item == null) ? null : item;
            if (watched != null) watched.riskProperty().addListener(riskListener);
            applyStripe(watched == null ? null : watched.getRisk());
        }

        private void applyStripe(RiskLevel risk) {
            getStyleClass().removeIf(s -> s.startsWith("row-"));
            if (risk != null && risk != RiskLevel.NOT_ANALYZED) {
                getStyleClass().add(risk.getCssClass().replace("risk-", "row-"));
            }
        }
    }

    /** Single-line text with an ellipsis and a tooltip showing the full value. */
    private static class EllipsisCell extends TableCell<ScanItem, String> {
        EllipsisCell(boolean muted) {
            if (muted) getStyleClass().add("cell-muted");
        }

        @Override
        protected void updateItem(String value, boolean empty) {
            super.updateItem(value, empty);
            if (empty || value == null) {
                setText(null);
                setTooltip(null);
                return;
            }
            setText(value.replaceAll("\\s+", " "));
            Tooltip tip = new Tooltip(value);
            tip.setWrapText(true);
            tip.setMaxWidth(420);
            setTooltip(tip);
        }
    }

    /** Colored badge. Not Verified has its own dashed look so it can't be mistaken for Low. */
    private static class RiskCell extends TableCell<ScanItem, RiskLevel> {
        private final Label badge = new Label();

        RiskCell() {
            badge.getStyleClass().add("badge");
        }

        @Override
        protected void updateItem(RiskLevel level, boolean empty) {
            super.updateItem(level, empty);
            if (empty || level == null) {
                setGraphic(null);
                setText(null);
            } else if (level == RiskLevel.NOT_ANALYZED) {
                setGraphic(null);
                setText(level.getLabel());
            } else {
                setText(null);
                badge.setText(level.getLabel());
                badge.getStyleClass().removeIf(s -> s.startsWith("risk-"));
                badge.getStyleClass().add(level.getCssClass());
                setGraphic(badge);
            }
        }
    }

    private static class StatusCell extends TableCell<ScanItem, ScanStatus> {
        @Override
        protected void updateItem(ScanStatus status, boolean empty) {
            super.updateItem(status, empty);
            getStyleClass().removeIf(s -> s.startsWith("status-"));
            if (empty || status == null) {
                setText(null);
            } else {
                setText(status.getLabel());
                getStyleClass().add(status.getCssClass());
            }
        }
    }

    /** How long the check took ("850 ms", "2.4 s"). Empty until it has finished. */
    private static class TimeCell extends TableCell<ScanItem, Number> {
        @Override
        protected void updateItem(Number value, boolean empty) {
            super.updateItem(value, empty);
            setText(empty || value == null || value.longValue() < 0 ? null : formatMs(value.longValue()));
        }
    }

    /** A progress bar per row whose fill glides to each new value instead of jumping. */
    private static class ProgressCell extends TableCell<ScanItem, Number> {
        private final ProgressBar bar = new ProgressBar(0);
        private final ChangeListener<Number> listener = (o, a, b) -> animateTo(b.doubleValue());
        private ScanItem bound;
        private Timeline timeline;

        ProgressCell() {
            bar.setMaxWidth(Double.MAX_VALUE);
            bar.setPrefHeight(8);
        }

        @Override
        protected void updateItem(Number value, boolean empty) {
            super.updateItem(value, empty);
            ScanItem item = (empty || getTableRow() == null) ? null : getTableRow().getItem();
            if (item != null && item == bound) return; // only the progress changed: the listener animates it

            if (bound != null) bound.progressProperty().removeListener(listener);
            bound = null;
            if (timeline != null) timeline.stop();
            bar.visibleProperty().unbind();

            if (item == null) {
                setGraphic(null);
                return;
            }
            bound = item;
            bar.setProgress(item.progressProperty().get());
            item.progressProperty().addListener(listener);
            bar.visibleProperty().bind(item.statusProperty().isNotEqualTo(ScanStatus.QUEUED));
            setGraphic(bar);
        }

        private void animateTo(double target) {
            if (timeline != null) timeline.stop();
            if (target < 0 || bar.getProgress() < 0) { // indeterminate: no animation
                bar.setProgress(target);
                return;
            }
            timeline = new Timeline(new KeyFrame(Duration.millis(220),
                    new KeyValue(bar.progressProperty(), target, Interpolator.EASE_BOTH)));
            timeline.play();
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}
