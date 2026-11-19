package dz.univ.threat.service;

import dz.univ.threat.model.RiskLevel;

/** Converts a score to a level: Low &lt; 20 | Medium 20-39 | High &gt;= 40. (Shared contract) */
public final class ScoreMapper {
    private ScoreMapper() {}

    public static RiskLevel map(int score) {
        if (score >= 40) return RiskLevel.HIGH;
        if (score >= 20) return RiskLevel.MEDIUM;
        return RiskLevel.LOW;
    }
}
