package dz.univ.threat.service;

import dz.univ.threat.model.InputType;
import dz.univ.threat.model.RiskLevel;
import dz.univ.threat.model.ScanItem;
import dz.univ.threat.model.ScanResult;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MessageRuleAnalyzerTest {

    private final MessageRuleAnalyzer analyzer = new MessageRuleAnalyzer();

    private ScanResult scan(String text) {
        return analyzer.analyze(new ScanItem(1, InputType.MESSAGE, text));
    }

    // ---------- The 4 MSG rows of the project dataset ----------

    @Test
    void row6_harmlessMessage_isLow() {
        ScanResult r = scan("Your lab appointment is confirmed for tomorrow at 2:00 PM");
        assertEquals(RiskLevel.LOW, r.level());
        assertEquals(0, r.score());
    }

    @Test
    void row7_phishingMessage_isHigh() {
        ScanResult r = scan("Notice: Account verification required within 24 hours. "
                + "Visit http://192.168.1.50/verify to prevent suspension.");
        assertEquals(RiskLevel.HIGH, r.level());
        assertEquals(100, r.score());            // 25 + 25 + 20 + 70 (link), capped at 100
    }

    @Test
    void row8_accountDigest_isMedium() {
        ScanResult r = scan("Please review your weekly account digest and notification settings.");
        assertEquals(RiskLevel.MEDIUM, r.level());
        assertEquals(20, r.score());             // "account" + "notification" count once
    }

    @Test
    void row10_emptyMessage_isNotVerified() {
        ScanResult r = scan("");
        assertEquals(RiskLevel.NOT_VERIFIED, r.level());
        assertNotNull(r.error());
    }

    // ---------- Error handling (golden rule: never LOW when we cannot verify) ----------

    @Test
    void nullAndBlankContent_areNotVerified() {
        assertEquals(RiskLevel.NOT_VERIFIED, scan(null).level());
        assertEquals(RiskLevel.NOT_VERIFIED, scan("   \n\t ").level());
    }

    @Test
    void nullItem_doesNotThrow() {
        assertEquals(RiskLevel.NOT_VERIFIED, analyzer.analyze(null).level());
    }

    @Test
    void urlItem_isRejected() {
        ScanResult r = analyzer.analyze(new ScanItem(2, InputType.URL, "http://a.com"));
        assertEquals(RiskLevel.NOT_VERIFIED, r.level());
    }

    @Test
    void unverifiableLink_withNoOtherSignal_isNotVerified() {
        Analyzer alwaysFails = item -> ScanResult.notVerified(item, "API down");
        ScanResult r = new MessageRuleAnalyzer(alwaysFails)
                .analyze(new ScanItem(3, InputType.MESSAGE, "See http://example.org"));
        assertEquals(RiskLevel.NOT_VERIFIED, r.level());
    }

    // ---------- Rules ----------

    @Test
    void secretsRequest_isHigh() {
        ScanResult r = scan("Please send me your PIN code.");
        assertEquals(RiskLevel.HIGH, r.level());
        assertEquals(40, r.score());
    }

    @Test
    void wholeWordsOnly_pinInsideAnotherWordDoesNotMatch() {
        assertEquals(0, scan("We are spinning a nice story about shopping").score());
    }

    @Test
    void sameRuleCountsOnce() {
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
        assertEquals(25, scan("IMMEDIATEMENT").score());
    }

    // ---------- Links ----------

    @Test
    void extractLinks_removesTrailingPunctuation_andDuplicates() {
        List<String> links = MessageRuleAnalyzer.extractLinks(
                "Go to http://a.com/x. or (https://b.org/y), again http://a.com/x");
        assertEquals(List.of("http://a.com/x", "https://b.org/y"), links);
    }

    @Test
    void extractLinks_wwwGetsHttps() {
        assertEquals(List.of("https://www.example.com"), MessageRuleAnalyzer.extractLinks("visit www.example.com"));
    }

    @Test
    void riskiestLinkOnly_isAdded() {
        ScanResult r = scan("http://192.168.1.50/a http://192.168.1.51/b");
        assertEquals(70, r.score());
    }
}
