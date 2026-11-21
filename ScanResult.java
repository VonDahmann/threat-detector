package dz.univ.threat.model;

import java.util.List;

public record ScanResult(ScanItem item, RiskLevel level, int score,
                         List<String> reasons, String error) {
    public static ScanResult notVerified(ScanItem item, String why) {
        return new ScanResult(item, RiskLevel.NOT_VERIFIED, 0, List.of(), why);
    }
}