package threatdetect;

/**
 * Result of a check. NOT_VERIFIED is deliberately separate from LOW:
 * an item that could not be checked must never look safe.
 */
public enum RiskLevel {
    NOT_ANALYZED(null, "risk-none"),
    LOW("risk.low", "risk-low"),
    MEDIUM("risk.medium", "risk-medium"),
    HIGH("risk.high", "risk-high"),
    NOT_VERIFIED("risk.unverified", "risk-unverified");

    private final String key;
    private final String cssClass;

    RiskLevel(String key, String cssClass) {
        this.key = key;
        this.cssClass = cssClass;
    }

    /** Text in the current language ("—" for items not analyzed yet). */
    public String getLabel() { return key == null ? "—" : I18n.t(key); }
    public String getCssClass() { return cssClass; }

    /** True only for real verdicts (Low, Medium, High). */
    public boolean isVerdict() {
        return this == LOW || this == MEDIUM || this == HIGH;
    }

    @Override
    public String toString() { return getLabel(); }
}
