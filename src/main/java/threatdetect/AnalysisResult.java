package threatdetect;

/** What the backend returns for one item. */
public record AnalysisResult(RiskLevel risk, ScanStatus status, String detail) {

    /** The check ran and produced a verdict (Low, Medium or High). */
    public static AnalysisResult completed(RiskLevel risk, String detail) {
        return new AnalysisResult(risk, ScanStatus.COMPLETED, detail);
    }

    /** The check could not be done (timeout, malformed input, rate limit...). Never "safe". */
    public static AnalysisResult notVerified(String reason) {
        return new AnalysisResult(RiskLevel.NOT_VERIFIED, ScanStatus.NOT_VERIFIED, reason);
    }
}
