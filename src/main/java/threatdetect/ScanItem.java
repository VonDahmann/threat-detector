package threatdetect;

import javafx.beans.property.*;

/** One row of the results table. Only touch it from the JavaFX thread. */
public class ScanItem {
    private final int id;
    private final StringProperty input = new SimpleStringProperty();
    private final ObjectProperty<InputType> type = new SimpleObjectProperty<>();
    private final ObjectProperty<RiskLevel> risk = new SimpleObjectProperty<>(RiskLevel.NOT_ANALYZED);
    private final ObjectProperty<ScanStatus> status = new SimpleObjectProperty<>(ScanStatus.QUEUED);
    private final DoubleProperty progress = new SimpleDoubleProperty(0);
    private final StringProperty detail = new SimpleStringProperty(I18n.t("item.waiting"));
    /** Time the check took, in milliseconds. -1 means "not measured yet". */
    private final LongProperty elapsedMs = new SimpleLongProperty(-1);
    private long startNanos;

    public ScanItem(int id, InputType type, String input) {
        this.id = id;
        this.type.set(type);
        this.input.set(input);
    }

    public void resetForRun() {
        progress.unbind();
        progress.set(0);
        risk.set(RiskLevel.NOT_ANALYZED);
        status.set(ScanStatus.QUEUED);
        detail.set(I18n.t("item.start"));
        elapsedMs.set(-1);
        startNanos = 0;
    }

    public void markStarted() {
        startNanos = System.nanoTime();
        elapsedMs.set(-1);
    }

    public void markFinished() {
        if (startNanos != 0) {
            elapsedMs.set((System.nanoTime() - startNanos) / 1_000_000);
            startNanos = 0;
        }
    }

    /**
     * Safety net: a Low/Medium/High risk is only shown when the check completed.
     * Anything else becomes Not Verified, whatever the backend returned.
     */
    public void applyResult(AnalysisResult result) {
        boolean verified = result != null
                && result.status() == ScanStatus.COMPLETED
                && result.risk() != null
                && result.risk().isVerdict();
        if (verified) {
            risk.set(result.risk());
            status.set(ScanStatus.COMPLETED);
            detail.set(result.detail() == null ? "" : result.detail());
        } else {
            risk.set(RiskLevel.NOT_VERIFIED);
            status.set(ScanStatus.NOT_VERIFIED);
            boolean noReason = result == null || result.detail() == null || result.detail().isBlank();
            detail.set(noReason ? I18n.t("item.incomplete") : result.detail());
        }
    }

    public void markCancelled() {
        progress.unbind();
        progress.set(0);
        risk.set(RiskLevel.NOT_ANALYZED);
        status.set(ScanStatus.CANCELLED);
        detail.set(I18n.t("item.cancelled"));
        elapsedMs.set(-1);
        startNanos = 0;
    }

    public int getId() { return id; }

    public StringProperty inputProperty() { return input; }
    public String getInput() { return input.get(); }

    public ObjectProperty<InputType> typeProperty() { return type; }
    public InputType getType() { return type.get(); }

    public ObjectProperty<RiskLevel> riskProperty() { return risk; }
    public RiskLevel getRisk() { return risk.get(); }

    public ObjectProperty<ScanStatus> statusProperty() { return status; }
    public ScanStatus getStatus() { return status.get(); }
    public void setStatus(ScanStatus s) { status.set(s); }

    public DoubleProperty progressProperty() { return progress; }
    public void setProgress(double p) { progress.set(p); }

    public StringProperty detailProperty() { return detail; }
    public String getDetail() { return detail.get(); }
    public void setDetail(String d) { detail.set(d); }

    public LongProperty elapsedMsProperty() { return elapsedMs; }
    public long getElapsedMs() { return elapsedMs.get(); }
}
