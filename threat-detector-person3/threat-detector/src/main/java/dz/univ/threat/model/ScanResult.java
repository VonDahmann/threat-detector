package dz.univ.threat.model;

import java.util.List;

/** Result of scanning one item. Immutable. (Shared contract) */
public record ScanResult(ScanItem item, RiskLevel level, int score,
                         List<String> reasons, String error) {

    public static ScanResult notVerified(ScanItem it, String why) {
        return new ScanResult(it, RiskLevel.NOT_VERIFIED, 0, List.of(), why);
    }
}
