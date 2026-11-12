package com.threatdetect.model;

import java.util.List;

public record AnalysisResult(
        int itemId,
        Status status,
        RiskLevel riskLevel,
        int score,
        List<String> reasons
) {
    public static AnalysisResult notVerified(int itemId, String reason) {
        return new AnalysisResult(itemId, Status.NOT_VERIFIED, RiskLevel.UNKNOWN, 0, List.of(reason));
    }

    public static AnalysisResult error(int itemId, String reason) {
        return new AnalysisResult(itemId, Status.ERROR, RiskLevel.UNKNOWN, 0, List.of(reason));
    }
}