package threatdetect;

/** Where an item is in its check. */
public enum ScanStatus {
    QUEUED("st.queued", "status-queued"),
    ANALYZING("st.analyzing", "status-analyzing"),
    COMPLETED("st.completed", "status-completed"),
    NOT_VERIFIED("st.unverified", "status-unverified"),
    CANCELLED("st.cancelled", "status-cancelled");

    private final String key;
    private final String cssClass;

    ScanStatus(String key, String cssClass) {
        this.key = key;
        this.cssClass = cssClass;
    }

    public String getLabel() { return I18n.t(key); }
    public String getCssClass() { return cssClass; }

    @Override
    public String toString() { return getLabel(); }
}
