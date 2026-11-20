package threatdetect;

import java.util.function.DoubleConsumer;

/**
 * The only thing the UI knows about the backend.
 *
 * Teammates: implement this interface (rule-based, VirusTotal, Safe Browsing...) and
 * swap one line in ThreatDetectionApp: {@code new MockThreatAnalysisService()}.
 *
 * Contract:
 *  - analyze() is called on a worker thread, never on the JavaFX thread.
 *  - Call progress.accept(value) with a value between 0.0 and 1.0 as work advances.
 *  - If the item can't be verified, return AnalysisResult.notVerified(reason).
 *    Never return Low for something that wasn't actually checked.
 *  - Throwing any exception is allowed: the UI shows it as Not Verified.
 *  - Let InterruptedException propagate so the Cancel button works.
 */
public interface ThreatAnalysisService {
    AnalysisResult analyze(InputType type, String content, DoubleConsumer progress) throws InterruptedException;
}
