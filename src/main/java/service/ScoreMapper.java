package service;

import model.RiskLevel;

/** Converts a score (0-100) into LOW / MEDIUM / HIGH. */
public final class ScoreMapper {

    public static final int MEDIUM_FROM = 20;
    public static final int HIGH_FROM = 40;
    public static final int MAX_SCORE = 100;

    private ScoreMapper() {
    }

    public static RiskLevel toLevel(int score) {
        if (score >= HIGH_FROM) return RiskLevel.HIGH;
        if (score >= MEDIUM_FROM) return RiskLevel.MEDIUM;
        return RiskLevel.LOW;
    }

    /** Keeps a total between 0 and 100. */
    public static int cap(int score) {
        return Math.max(0, Math.min(MAX_SCORE, score));
    }
}
