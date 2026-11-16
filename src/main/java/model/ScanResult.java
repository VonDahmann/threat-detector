package model;

import java.util.List;

/** Result of scanning one item. Immutable. */
public record ScanResult(ScanItem item, RiskLevel level, int score, List<String> reasons, String error) {

    public ScanResult {
        reasons = (reasons == null) ? List.of() : List.copyOf(reasons);
    }

    /** Use this for ANY failure: empty input, bad URL, exception, timeout... Never LOW. */
    public static ScanResult notVerified(ScanItem item, String why) {
        String msg = (why == null || why.isBlank()) ? "Could not be verified" : why;
        return new ScanResult(item, RiskLevel.NOT_VERIFIED, 0, List.of(msg), msg);
    }
}
