// The package line: it says in which folder/package this class lives.
// It MUST be exactly "dz.univ.threat.model" because the guide's project structure puts the
// shared contracts there, and every other class (analyzers, UI, controller) imports from it.
package dz.univ.threat.model;

// We need java.util.List because the "reasons" of a result are a list of texts.
import java.util.List;

/**
 * Result of scanning ONE item (one URL or one message). Immutable. (Shared contract)
 *
 * <p>A "record" is a Java 17 feature: a small, final data class. Java automatically creates for us:
 * the constructor, the getters (item(), level(), score(), reasons(), error()), equals(), hashCode()
 * and toString(). Fields can never be changed after creation, which is exactly what the guide
 * asks for ("results immutable") and what makes Sprint 2 (many threads) safe.
 *
 * @param item    the item that was scanned (id + type + content)
 * @param level   LOW / MEDIUM / HIGH / NOT_VERIFIED
 * @param score   number of risk points, from 0 to 100
 * @param reasons human-readable explanations (shown in the UI tooltip / panel)
 * @param error   null when everything went fine, otherwise the message explaining why
 *                the item could not be verified
 */
public record ScanResult(ScanItem item, RiskLevel level, int score,
                         List<String> reasons, String error) {

    /**
     * "Compact constructor": this code runs automatically EVERY time a ScanResult is created,
     * before the fields are stored. It has no parameter list because it reuses the record's own
     * parameters (item, level, score, reasons, error) and can reassign them.
     */
    public ScanResult {
        // If somebody passed null for the reasons, use an empty list instead (so that code which
        // loops over reasons() never crashes with a NullPointerException).
        // Otherwise make a PRIVATE, UNMODIFIABLE COPY with List.copyOf: even if the caller keeps
        // its own ArrayList and changes it later, our result does not change = truly immutable.
        reasons = (reasons == null) ? List.of() : List.copyOf(reasons);
    }

    /**
     * Use this for ANY failure: empty input, bad URL, exception, timeout...
     * It never returns LOW: "we could not check it" is NOT the same as "it is safe" (golden rule).
     *
     * @param item the item that could not be verified (may be null if there was no item at all)
     * @param why  the reason; if it is null or blank a default message is used
     */
    public static ScanResult notVerified(ScanItem item, String why) {
        // Choose the message to show: if "why" is null or only spaces, fall back to a default text,
        // so the UI never shows an empty explanation.
        String msg = (why == null || why.isBlank()) ? "Could not be verified" : why;
        // Build the result: level NOT_VERIFIED, score 0 (there is nothing to count),
        // the message as the single reason (visible in the UI) and also stored in "error".
        return new ScanResult(item, RiskLevel.NOT_VERIFIED, 0, List.of(msg), msg);
    }
}
