package threatdetect;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

import javafx.geometry.Pos;
import javafx.scene.AccessibleRole;
import javafx.scene.Group;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.MenuButton;
import javafx.scene.control.RadioMenuItem;
import javafx.scene.control.ToggleGroup;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.shape.Circle;
import javafx.scene.shape.SVGPath;

/**
 * Slim 64px top bar: logo + wordmark on the left, language / theme / help on the right.
 * Styled entirely by theme.css (.header, .icon-btn, .lang-menu ...).
 */
public final class AppHeader extends HBox {

    /* Lucide icon paths (24x24 viewBox, stroked) */
    private static final String GLOBE = "M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20zM12 2a14.5 14.5 0 0 0 0 20a14.5 14.5 0 0 0 0-20M2 12h20";
    private static final String CHEVRON = "M6 9l6 6l6-6";
    private static final String MOON = "M12 3a6 6 0 0 0 9 9a9 9 0 1 1-9-9z";
    private static final String SUN = "M12 8a4 4 0 1 0 0 8a4 4 0 1 0 0-8zM12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41";
    private static final String HELP = "M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20zM9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3M12 17h.01";

    /* Diakrisis mark: a "D" with a radar scan line sweeping from its focal point */
    private static final String LOGO_D = "M7 5h5a7 7 0 0 1 0 14H7zM10 12l5.5-3.8";

    /** code -> {short label shown in the bar, full name shown in the menu} */
    private static final Map<String, String[]> LANGUAGES = new LinkedHashMap<>();
    static {
        LANGUAGES.put("en", new String[] {"EN", "English"});
        LANGUAGES.put("fr", new String[] {"FR", "Français"});
        LANGUAGES.put("ar", new String[] {"عربي", "العربية"});
    }

    private final SVGPath themeIcon = icon(MOON, 18);
    private final Button themeButton = iconButton(themeIcon);
    private final Button helpButton = iconButton(icon(HELP, 18));
    private final Label langCode = new Label();
    private final ToggleGroup langGroup = new ToggleGroup();

    public AppHeader(String initialLang, boolean dark,
                     Consumer<String> onLanguage, Runnable onToggleTheme, Runnable onHelp) {
        getStyleClass().add("header");
        setAlignment(Pos.CENTER_LEFT);

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Region divider = new Region();
        divider.getStyleClass().add("header-divider");
        divider.managedProperty().bind(divider.visibleProperty());

        themeButton.setOnAction(e -> onToggleTheme.run());
        helpButton.setOnAction(e -> onHelp.run());
        helpButton.setAccessibleText("Help");
        helpButton.setTooltip(new Tooltip("Help"));

        HBox tools = new HBox(4, buildLanguageMenu(initialLang, onLanguage), divider, themeButton, helpButton);
        tools.setAlignment(Pos.CENTER_RIGHT);

        getChildren().addAll(buildBrand(), spacer, tools);
        setDark(dark);
    }

    /** Call whenever the theme changes so the icon and labels stay in sync. */
    public void setDark(boolean dark) {
        themeIcon.setContent(dark ? SUN : MOON);
        String label = dark ? "Switch to light mode" : "Switch to dark mode";
        themeButton.setAccessibleText(label);
        themeButton.setTooltip(new Tooltip(label));
    }

    /** Optional: override tooltip/screen-reader texts with translated strings. */
    public void setHelpText(String text) {
        helpButton.setAccessibleText(text);
        helpButton.setTooltip(new Tooltip(text));
    }

    private HBox buildBrand() {
        SVGPath d = new SVGPath();
        d.setContent(LOGO_D);
        d.getStyleClass().add("logo-mark");
        Circle focus = new Circle(10, 12, 1.6);
        focus.getStyleClass().add("logo-dot");
        Group mark = new Group(d, focus);
        mark.setScaleX(0.9);
        mark.setScaleY(0.9);

        StackPane logo = new StackPane(mark);
        logo.getStyleClass().add("logo-box");

        Label title = new Label("Diakrisis");
        title.getStyleClass().add("app-title");

        Label badge = new Label("Threat Detection");
        badge.getStyleClass().add("app-badge");
        badge.managedProperty().bind(badge.visibleProperty()); // hidden in .compact

        HBox brand = new HBox(10, logo, title, badge);
        brand.setAlignment(Pos.CENTER_LEFT);
        brand.setAccessibleRole(AccessibleRole.TEXT);
        brand.setAccessibleText("Diakrisis, Threat Detection");
        return brand;
    }

    private MenuButton buildLanguageMenu(String initialLang, Consumer<String> onLanguage) {
        langCode.getStyleClass().add("lang-code");
        // Group wrappers make the scaled icon size count for layout
        HBox graphic = new HBox(6, new Group(icon(GLOBE, 17)), langCode, new Group(icon(CHEVRON, 13)));
        graphic.setAlignment(Pos.CENTER);

        MenuButton menu = new MenuButton(null, graphic);
        menu.getStyleClass().add("lang-menu");
        menu.setAccessibleText("Language");
        menu.setTooltip(new Tooltip("Language"));

        LANGUAGES.forEach((code, names) -> {
            RadioMenuItem item = new RadioMenuItem(names[1]);
            item.setToggleGroup(langGroup);
            item.setSelected(code.equals(initialLang));
            item.setOnAction(e -> {
                langCode.setText(names[0]);
                onLanguage.accept(code);
            });
            menu.getItems().add(item);
        });
        langCode.setText(LANGUAGES.getOrDefault(initialLang, LANGUAGES.get("en"))[0]);
        return menu;
    }

    private static SVGPath icon(String content, double size) {
        SVGPath p = new SVGPath();
        p.setContent(content);
        p.getStyleClass().add("icon");
        double scale = size / 24.0;
        p.setScaleX(scale);
        p.setScaleY(scale);
        return p;
    }

    private static Button iconButton(SVGPath icon) {
        Button b = new Button();
        b.setGraphic(new Group(icon));
        b.getStyleClass().add("icon-btn");
        return b;
    }
}