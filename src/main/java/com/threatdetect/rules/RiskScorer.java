package com.threatdetect.rules;

import com.threatdetect.model.RiskLevel;

import java.util.List;

public final class RiskScorer {
    private RiskScorer() {}

    public static int total(List<RuleHit> hits) {
        int sum = hits.stream().mapToInt(RuleHit::points).sum();
        return Math.min(100, sum);
    }

    public static RiskLevel toLevel(int score) {
        if (score >= 50) return RiskLevel.HIGH;
        if (score >= 25) return RiskLevel.MEDIUM;
        return RiskLevel.LOW;
    }
}