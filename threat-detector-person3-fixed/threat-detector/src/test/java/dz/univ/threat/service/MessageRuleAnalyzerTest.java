// Same package as MessageRuleAnalyzer, so the test can call its package-private helpers
// (extractLinks, normalize) directly.
package dz.univ.threat.service;

import dz.univ.threat.model.InputType;
import dz.univ.threat.model.RiskLevel;
import dz.univ.threat.model.ScanItem;
import dz.univ.threat.model.ScanResult;
import org.junit.jupiter.api.Test;      // JUnit 5: marks a method as a test

import java.util.List;

// "static import" lets us write assertEquals(...) instead of Assertions.assertEquals(...).
import static org.junit.jupiter.api.Assertions.*;

class MessageRuleAnalyzerTest {

    // The analyzer under test. It is stateless, so one shared instance is fine for all tests.
    private final MessageRuleAnalyzer analyzer = new MessageRuleAnalyzer();

    // Small helper: wraps a text in a MESSAGE item (id 1) and analyzes it, to keep tests short.
    private ScanResult scan(String text) {
        return analyzer.analyze(new ScanItem(1, InputType.MESSAGE, text));
    }

    // ---------- The 4 MSG rows of the project dataset (rows 6, 7, 8, 10) ----------

    @Test
    void row6_harmlessMessage_isLow() {
        ScanResult r = scan("Your lab appointment is confirmed for tomorrow at 2:00 PM");
        assertEquals(RiskLevel.LOW, r.level());   // expected: Low
        assertEquals(0, r.score());               // no rule fires => 0 points
    }

    @Test
    void row7_phishingMessage_isHigh() {
        ScanResult r = scan("Notice: Account verification required within 24 hours. "
                + "Visit http://192.168.1.50/verify to prevent suspension.");
        assertEquals(RiskLevel.HIGH, r.level());
        assertEquals(100, r.score());            // 25 (urgency) + 25 (threat) + 20 (account) + 70 (link), capped at 100
    }

    @Test
    void row8_accountDigest_isMedium() {
        ScanResult r = scan("Please review your weekly account digest and notification settings.");
        assertEquals(RiskLevel.MEDIUM, r.level());
        assertEquals(20, r.score());             // "account" + "notification" are the same rule: counted once
    }

    @Test
    void row10_emptyMessage_isNotVerified() {
        ScanResult r = scan("");
        assertEquals(RiskLevel.NOT_VERIFIED, r.level());   // never Low for an empty input
        assertNotNull(r.error());                          // and there is a message explaining why
    }

    // ---------- Error handling (golden rule: never LOW when we cannot verify) ----------

    @Test
    void nullAndBlankContent_areNotVerified() {
        assertEquals(RiskLevel.NOT_VERIFIED, scan(null).level());          // null text
        assertEquals(RiskLevel.NOT_VERIFIED, scan("   \n\t ").level());    // only whitespace
    }

    @Test
    void nullItem_doesNotThrow() {
        // The analyzer must NEVER throw, even when it receives null instead of an item.
        assertEquals(RiskLevel.NOT_VERIFIED, analyzer.analyze(null).level());
    }

    @Test
    void urlItem_isRejected() {
        // A URL item sent to the message analyzer is a mistake => NOT_VERIFIED.
        ScanResult r = analyzer.analyze(new ScanItem(2, InputType.URL, "http://a.com"));
        assertEquals(RiskLevel.NOT_VERIFIED, r.level());
    }

    @Test
    void unverifiableLink_withNoOtherSignal_isNotVerified() {
        // A fake link analyzer that always fails (simulates an API down / malformed link).
        Analyzer alwaysFails = item -> ScanResult.notVerified(item, "API down");
        ScanResult r = new MessageRuleAnalyzer(alwaysFails)
                .analyze(new ScanItem(3, InputType.MESSAGE, "See http://example.org"));
        // No keyword fired and the link could not be checked => we must NOT answer Low.
        assertEquals(RiskLevel.NOT_VERIFIED, r.level());
    }

    @Test
    void unverifiableLink_butAlreadyRiskyMessage_keepsItsRiskLevel() {
        Analyzer alwaysFails = item -> ScanResult.notVerified(item, "API down");
        ScanResult r = new MessageRuleAnalyzer(alwaysFails)
                .analyze(new ScanItem(4, InputType.MESSAGE, "Send your password: http://example.org"));
        // The keyword rule already gives 40 points (High); a broken link cannot make it safer.
        assertEquals(RiskLevel.HIGH, r.level());
        // And the user is told that the link could not be verified.
        assertTrue(r.reasons().stream().anyMatch(s -> s.contains("could not be verified")));
    }

    @Test
    void analyzerThatThrows_isCaught_andBecomesNotVerified() {
        // A link analyzer that breaks with an exception: MessageRuleAnalyzer must absorb it.
        Analyzer explodes = item -> { throw new IllegalStateException("boom"); };
        ScanResult r = new MessageRuleAnalyzer(explodes)
                .analyze(new ScanItem(5, InputType.MESSAGE, "See http://example.org"));
        assertEquals(RiskLevel.NOT_VERIFIED, r.level());
        assertNotNull(r.error());
    }

    // ---------- Rules ----------

    @Test
    void secretsRequest_isHigh() {
        ScanResult r = scan("Please send me your PIN code.");
        assertEquals(RiskLevel.HIGH, r.level());
        assertEquals(40, r.score());             // asking for a secret = +40 = High on its own
    }

    @Test
    void wholeWordsOnly_pinInsideAnotherWordDoesNotMatch() {
        // "spinning" contains "pin" and "shopping" does not matter: whole words only => 0 points.
        assertEquals(0, scan("We are spinning a nice story about shopping").score());
    }

    @Test
    void sameRuleCountsOnce() {
        // "urgent" three times + "immediately" = still ONE urgency rule = 25 points.
        assertEquals(25, scan("urgent urgent urgent, do it immediately").score());
    }

    @Test
    void french_isDetected() {
        ScanResult r = scan("Votre compte sera suspendu. Envoyez votre mot de passe immédiatement.");
        assertEquals(RiskLevel.HIGH, r.level());
        assertEquals(100, r.score());            // 25 + 25 + 40 + 20 = 110 -> capped
    }

    @Test
    void arabic_isDetected() {
        ScanResult r = scan("عاجل: سيتم تعليق حسابك، أرسل كلمة السر الآن");
        assertEquals(RiskLevel.HIGH, r.level());
        assertEquals(100, r.score());
    }

    @Test
    void accentsAndCaseDoNotMatter() {
        // Upper case and missing accent: "IMMEDIATEMENT" still matches "immédiatement".
        assertEquals(25, scan("IMMEDIATEMENT").score());
    }

    @Test
    void arabicDecorationsAreIgnored() {
        // Tatweel (ـ) and vowel marks must not stop the match: "عـاجـل" == "عاجل".
        assertEquals(25, scan("عـاجـل").score());
        assertEquals(25, scan("فَوْراً").score());
    }

    @Test
    void arabicIndicDigitsAreConverted() {
        // "٢٤" must be read as "24", so "خلال ٢٤ ساعة" matches the keyword "خلال 24 ساعة".
        assertEquals(25, scan("خلال ٢٤ ساعة").score());
    }

    @Test
    void normalize_collapsesSpacesAndLowercases() {
        assertEquals("mot de passe", MessageRuleAnalyzer.normalize("  MOT   de\npasse "));
    }

    // ---------- Links ----------

    @Test
    void extractLinks_removesTrailingPunctuation_andDuplicates() {
        List<String> links = MessageRuleAnalyzer.extractLinks(
                "Go to http://a.com/x. or (https://b.org/y), again http://a.com/x");
        // Final dot and ")," removed, and the repeated link only appears once, in order.
        assertEquals(List.of("http://a.com/x", "https://b.org/y"), links);
    }

    @Test
    void extractLinks_wwwGetsHttps() {
        // A link written without protocol gets "https://" in front.
        assertEquals(List.of("https://www.example.com"), MessageRuleAnalyzer.extractLinks("visit www.example.com"));
    }

    @Test
    void extractLinks_noLink_givesEmptyList() {
        assertTrue(MessageRuleAnalyzer.extractLinks("no link here").isEmpty());
    }

    @Test
    void riskiestLinkOnly_isAdded() {
        // Two IP links, 70 points each: only ONE is added (70), not 140.
        ScanResult r = scan("http://192.168.1.50/a http://192.168.1.51/b");
        assertEquals(70, r.score());
    }
}
