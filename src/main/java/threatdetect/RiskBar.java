package threatdetect;

import javafx.animation.Interpolator;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Timeline;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.geometry.NodeOrientation;
import javafx.scene.layout.Pane;
import javafx.scene.layout.Region;
import javafx.scene.shape.Rectangle;
import javafx.util.Duration;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * A slim bar that shows how the results are split between High, Medium, Low and Not Verified.
 * The segments glide to their new size whenever the counts change.
 */
public class RiskBar extends Pane {

    private static final List<RiskLevel> ORDER =
            List.of(RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.NOT_VERIFIED);

    private final Map<RiskLevel, DoubleProperty> share = new EnumMap<>(RiskLevel.class);
    private final Map<RiskLevel, Region> segments = new EnumMap<>(RiskLevel.class);
    private final Map<RiskLevel, Timeline> animations = new EnumMap<>(RiskLevel.class);

    public RiskBar() {
        getStyleClass().add("risk-bar");
        setNodeOrientation(NodeOrientation.LEFT_TO_RIGHT); // the bar always fills from the same side
        setMinHeight(10);
        setPrefHeight(10);
        setMaxHeight(10);

        Rectangle clip = new Rectangle();
        clip.setArcWidth(10);
        clip.setArcHeight(10);
        clip.widthProperty().bind(widthProperty());
        clip.heightProperty().bind(heightProperty());
        setClip(clip);

        for (RiskLevel level : ORDER) {
            Region seg = new Region();
            seg.getStyleClass().addAll("risk-seg", level.getCssClass());
            DoubleProperty p = new SimpleDoubleProperty(0);
            p.addListener((o, a, b) -> requestLayout());
            share.put(level, p);
            segments.put(level, seg);
            getChildren().add(seg);
        }
    }

    public void setCounts(Map<RiskLevel, Long> counts) {
        long total = 0;
        for (RiskLevel level : ORDER) total += counts.getOrDefault(level, 0L);
        for (RiskLevel level : ORDER) {
            double target = total == 0 ? 0 : counts.getOrDefault(level, 0L) / (double) total;
            DoubleProperty p = share.get(level);
            if (Math.abs(p.get() - target) < 0.0005) continue;
            Timeline old = animations.get(level);
            if (old != null) old.stop();
            Timeline tl = new Timeline(new KeyFrame(Duration.millis(500),
                    new KeyValue(p, target, Interpolator.EASE_BOTH)));
            animations.put(level, tl);
            tl.play();
        }
    }

    @Override
    protected void layoutChildren() {
        double w = getWidth();
        double h = getHeight();
        double x = 0;
        for (RiskLevel level : ORDER) {
            double sw = w * share.get(level).get();
            segments.get(level).resizeRelocate(x, 0, sw, h);
            x += sw;
        }
    }
}

