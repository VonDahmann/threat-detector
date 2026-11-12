package com.threatdetect.ui;

import com.threatdetect.model.InputItem;
import com.threatdetect.model.RiskLevel;
import com.threatdetect.model.Status;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.IntegerProperty;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;

/** One table row. Observable properties; must only be modified on the JavaFX thread. */
public class ResultRow {
    private final InputItem item;
    private final ObjectProperty<Status> status = new SimpleObjectProperty<>(Status.PENDING);
    private final ObjectProperty<RiskLevel> risk = new SimpleObjectProperty<>(null);
    private final IntegerProperty score = new SimpleIntegerProperty(0);
    private final DoubleProperty progress = new SimpleDoubleProperty(0);
    private final StringProperty details = new SimpleStringProperty("Waiting for analysis");

    public ResultRow(InputItem item) {
        this.item = item;
    }

    public InputItem getItem() { return item; }

    public ObjectProperty<Status> statusProperty() { return status; }
    public Status getStatus() { return status.get(); }
    public void setStatus(Status s) { status.set(s); }

    public ObjectProperty<RiskLevel> riskProperty() { return risk; }
    public RiskLevel getRisk() { return risk.get(); }
    public void setRisk(RiskLevel r) { risk.set(r); }

    public IntegerProperty scoreProperty() { return score; }
    public int getScore() { return score.get(); }
    public void setScore(int s) { score.set(s); }

    public DoubleProperty progressProperty() { return progress; }
    public void setProgress(double p) { progress.set(p); }

    public StringProperty detailsProperty() { return details; }
    public String getDetails() { return details.get(); }
    public void setDetails(String d) { details.set(d); }
}