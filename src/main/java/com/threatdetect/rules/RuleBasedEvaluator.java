package com.threatdetect.rules;

import com.threatdetect.model.AnalysisResult;
import com.threatdetect.model.InputItem;
import com.threatdetect.model.InvalidInputException;
import com.threatdetect.model.RiskLevel;
import com.threatdetect.model.Status;
import com.threatdetect.service.ProgressReporter;
import com.threatdetect.service.ThreatEvaluator;

import java.util.List;

public class RuleBasedEvaluator implements ThreatEvaluator {

    private final long simulatedLatencyMs;

    public RuleBasedEvaluator() {
        this(0);
    }

    /** simulatedLatencyMs is for testing/demo only (visible progress bars, timeouts). */
    public RuleBasedEvaluator(long simulatedLatencyMs) {
        this.simulatedLatencyMs = simulatedLatencyMs;
    }

    @Override
    public AnalysisResult evaluate(InputItem item, ProgressReporter progress) throws InterruptedException {
        progress.report(10);
        pause();

        try {
            progress.report(40);
            List<RuleHit> hits = switch (item.getType()) {
                case URL -> UrlRules.evaluate(item.getContent());
                case MESSAGE -> MessageRules.evaluate(item.getContent());
            };

            pause();
            progress.report(80);

            int score = RiskScorer.total(hits);
            RiskLevel level = RiskScorer.toLevel(score);

            List<String> reasons = hits.isEmpty()
                    ? List.of("No suspicious indicators found by local rules")
                    : hits.stream().map(h -> h.reason() + " (+" + h.points() + ")").toList();

            progress.report(100);
            return new AnalysisResult(item.getId(), Status.DONE, level, score, reasons);

        } catch (InvalidInputException e) {
            return AnalysisResult.error(item.getId(), e.getMessage());
        } catch (RuntimeException e) {
            // Anything unexpected is NEVER reported as safe
            return AnalysisResult.notVerified(item.getId(), "Unexpected failure: " + e.getMessage());
        }
    }

    private void pause() throws InterruptedException {
        if (simulatedLatencyMs > 0) {
            Thread.sleep(simulatedLatencyMs / 2);
        }
    }
}