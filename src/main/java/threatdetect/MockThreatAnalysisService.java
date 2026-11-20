package threatdetect;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.DoubleConsumer;
import java.util.regex.Pattern;

/**
 * Fake backend so the UI can be tested alone. It sleeps to simulate work and applies a few
 * toy rules. Demo triggers: an input containing "timeout" or "ratelimit" ends as Not Verified.
 * Its messages come from I18n so the demo also looks right in French and Arabic.
 * A real backend simply returns its own texts.
 */
public class MockThreatAnalysisService implements ThreatAnalysisService {

    private static final int STEPS = 10;
    private static final double RANDOM_FAILURE_RATE = 0.06;

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    private static final Pattern HAS_SCHEME = Pattern.compile("^[a-zA-Z][a-zA-Z0-9+.-]*://.*");

    private static final List<String> SENSITIVE_WORDS =
            List.of("login", "verify", "secure", "account", "update", "paypal", "bank");
    private static final List<String> URGENCY = List.of(
            "urgent", "immediately", "within 24 hours", "act now", "suspended", "final notice",
            "immédiatement", "compte suspendu", "dernier avis",
            "عاجل", "فورا", "فورًا", "تم تعليق");
    private static final List<String> CREDENTIALS = List.of(
            "password", "otp", "verification code", "pin", "card number", "login",
            "mot de passe", "code de vérification", "numéro de carte",
            "كلمة المرور", "كلمة السر", "رمز التحقق", "رقم البطاقة");
    private static final List<String> PRIZES = List.of(
            "winner", "prize", "gift card", "lottery",
            "gagnant", "cadeau", "félicitations",
            "جائزة", "فزت", "مبروك");

    @Override
    public AnalysisResult analyze(InputType type, String content, DoubleConsumer progress) throws InterruptedException {
        String text = content == null ? "" : content.strip();
        if (text.isEmpty()) {
            return AnalysisResult.notVerified(I18n.t("mock.empty"));
        }

        URI uri = null;
        if (type == InputType.URL) {
            try {
                uri = parseUrl(text);
            } catch (IllegalArgumentException e) {
                return AnalysisResult.notVerified(e.getMessage());
            }
        }

        String lower = text.toLowerCase(Locale.ROOT);
        for (int step = 1; step <= STEPS; step++) {
            Thread.sleep(ThreadLocalRandom.current().nextLong(120, 320));
            progress.accept(step / (double) STEPS);

            if (step == 6) {
                if (lower.contains("timeout")) {
                    return AnalysisResult.notVerified(I18n.t("mock.timeout"));
                }
                if (lower.contains("ratelimit")) {
                    return AnalysisResult.notVerified(I18n.t("mock.ratelimit"));
                }
                if (ThreadLocalRandom.current().nextDouble() < RANDOM_FAILURE_RATE) {
                    return AnalysisResult.notVerified(I18n.t("mock.unavailable"));
                }
            }
        }
        return uri != null ? scoreUrl(uri, text) : scoreMessage(lower);
    }

    private static URI parseUrl(String raw) {
        if (raw.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException(I18n.t("mock.url.spaces"));
        }
        String candidate = HAS_SCHEME.matcher(raw).matches() ? raw : "https://" + raw;
        URI uri;
        try {
            uri = new URI(candidate);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(I18n.t("mock.url.syntax", e.getReason()));
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new IllegalArgumentException(I18n.t("mock.url.scheme", scheme));
        }
        if (uri.getHost() == null || uri.getHost().isBlank()) {
            throw new IllegalArgumentException(I18n.t("mock.url.nohost"));
        }
        return uri;
    }

    private static AnalysisResult scoreUrl(URI uri, String raw) {
        List<String> reasons = new ArrayList<>();
        int score = 0;
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        String address = host + (uri.getRawPath() == null ? "" : uri.getRawPath().toLowerCase(Locale.ROOT));

        if ("http".equalsIgnoreCase(uri.getScheme())) { score += 25; reasons.add(I18n.t("r.http")); }
        if (IPV4.matcher(host).matches()) { score += 40; reasons.add(I18n.t("r.ip")); }
        if (uri.getRawUserInfo() != null) { score += 30; reasons.add(I18n.t("r.at")); }
        if (host.chars().filter(c -> c == '.').count() >= 4) { score += 20; reasons.add(I18n.t("r.subdomains")); }
        if (SENSITIVE_WORDS.stream().anyMatch(address::contains)) { score += 15; reasons.add(I18n.t("r.keyword")); }
        if (raw.length() > 100) { score += 10; reasons.add(I18n.t("r.long")); }
        return toResult(score, reasons);
    }

    private static AnalysisResult scoreMessage(String lower) {
        List<String> reasons = new ArrayList<>();
        int score = 0;
        if (URGENCY.stream().anyMatch(lower::contains)) { score += 25; reasons.add(I18n.t("r.urgent")); }
        if (CREDENTIALS.stream().anyMatch(lower::contains)) { score += 35; reasons.add(I18n.t("r.cred")); }
        if (PRIZES.stream().anyMatch(lower::contains)) { score += 20; reasons.add(I18n.t("r.prize")); }
        if (lower.contains("http")) { score += 10; reasons.add(I18n.t("r.link")); }
        return toResult(score, reasons);
    }

    private static AnalysisResult toResult(int score, List<String> reasons) {
        RiskLevel level = score < 25 ? RiskLevel.LOW : score < 55 ? RiskLevel.MEDIUM : RiskLevel.HIGH;
        String detail = reasons.isEmpty()
                ? I18n.t("mock.safe")
                : I18n.t("mock.score", score, String.join(I18n.t("sep"), reasons));
        return AnalysisResult.completed(level, detail);
    }
}
