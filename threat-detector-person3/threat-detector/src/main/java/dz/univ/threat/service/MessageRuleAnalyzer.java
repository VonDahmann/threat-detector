package dz.univ.threat.service;

import dz.univ.threat.model.InputType;
import dz.univ.threat.model.RiskLevel;
import dz.univ.threat.model.ScanItem;
import dz.univ.threat.model.ScanResult;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Rule-based analyzer for MESSAGES (SMS / email) - Person 3's part.
 *
 * <p>How it works, in 5 steps:
 * <ol>
 *   <li>Check the input. Empty / wrong type =&gt; NOT_VERIFIED (never LOW).</li>
 *   <li>Normalize the text (lowercase, remove accents, simplify Arabic letters).</li>
 *   <li>Apply 4 keyword rules (urgency, threat, secrets, generic account words).
 *       Each rule is counted ONCE, however many of its words appear.</li>
 *   <li>Extract the links and score each one with the URL analyzer (Person 2's work).</li>
 *   <li>Add everything, cap at 100, convert with {@link ScoreMapper}.</li>
 * </ol>
 *
 * <p>Thread safety (Sprint 2): this class has NO mutable fields, so many threads can use
 * the same instance at the same time.
 */
public class MessageRuleAnalyzer implements Analyzer {

    // ---------- Points (same values as the sprint plan; tune them while testing) ----------
    static final int POINTS_URGENCY = 25;
    static final int POINTS_THREAT = 25;
    static final int POINTS_SECRETS = 40;
    static final int POINTS_GENERIC = 20;
    static final int MAX_SCORE = 100;

    // ---------- Keyword lists (English / French / Arabic) ----------
    // Write them in a natural way: they are normalized automatically when the class loads.
    private static final String[] URGENCY = {
            // EN
            "urgent", "urgently", "immediately", "within 24 hours", "within 48 hours", "final notice",
            "last warning", "act now", "right away", "asap", "expires today",
            // FR
            "immédiatement", "dans les 24 heures", "sous 24h", "dernier avis", "dernier rappel", "sans délai",
            // AR
            "عاجل", "عاجلا", "فورا", "فوراً", "خلال 24 ساعة", "آخر تحذير", "في أسرع وقت"
    };

    private static final String[] THREAT = {
            // EN
            "suspension", "suspended", "suspend", "blocked", "locked", "deactivated", "terminated",
            "restricted", "will be closed",
            // FR
            "suspendu", "suspendue", "bloqué", "bloquée", "verrouillé", "désactivé", "désactivée",
            // AR
            "تعليق", "معلق", "إيقاف", "حظر", "مغلق", "تجميد", "سيتم إغلاق"
    };

    private static final String[] SECRETS = {
            // EN
            "password", "passcode", "otp", "pin", "cvv", "cvc", "card number", "credit card",
            "security code", "verification code", "one-time code", "social security",
            // FR
            "mot de passe", "code pin", "code secret", "numéro de carte", "carte bancaire",
            "code de vérification",
            // AR
            "كلمة السر", "كلمة المرور", "رمز التحقق", "كود التحقق", "رقم البطاقة", "الرقم السري",
            "رمز سري", "بطاقة الائتمان"
    };

    private static final String[] GENERIC = {
            // EN
            "account", "verify", "verification", "notification", "login", "log in", "sign in",
            // FR
            "compte", "vérifier", "vérification", "connexion",
            // AR
            "حساب", "تحقق", "التحقق", "إشعار", "الإشعارات", "تسجيل الدخول"
    };

    private static final List<Rule> RULES = List.of(
            new Rule("Urgency language", POINTS_URGENCY, URGENCY),
            new Rule("Account suspension / blocking threat", POINTS_THREAT, THREAT),
            new Rule("Asks for secret data", POINTS_SECRETS, SECRETS),
            new Rule("Mentions account / verification", POINTS_GENERIC, GENERIC)
    );

    // A link starts with http://, https:// or www. and stops at the first space or quote.
    private static final Pattern LINK = Pattern.compile("(?i)\\b(?:https?://|www\\.)[^\\s<>\"']+");
    private static final String TRAILING_PUNCTUATION = ".,;:!?)]}»'\"،؟";

    private final Analyzer urlAnalyzer;

    /** Default: uses the project's UrlRuleAnalyzer to score links. */
    public MessageRuleAnalyzer() {
        this(new UrlRuleAnalyzer());
    }

    /** Lets tests (or Sprint 2) give another analyzer for links. */
    public MessageRuleAnalyzer(Analyzer urlAnalyzer) {
        this.urlAnalyzer = Objects.requireNonNull(urlAnalyzer, "urlAnalyzer");
    }

    @Override
    public ScanResult analyze(ScanItem item) {
        try {
            // ---- Step 1: check the input ----
            if (item == null) {
                return ScanResult.notVerified(null, "No item to analyze");
            }
            if (item.type() != InputType.MESSAGE) {
                return ScanResult.notVerified(item, "MessageRuleAnalyzer only analyzes MESSAGE items");
            }
            String content = item.content();
            if (content == null || content.isBlank()) {
                return ScanResult.notVerified(item, "Empty input");
            }

            int score = 0;
            List<String> reasons = new ArrayList<>();

            // ---- Steps 2 + 3: normalize and apply the keyword rules ----
            String text = normalize(content);
            for (Rule rule : RULES) {
                List<String> found = rule.findMatches(text);
                if (!found.isEmpty()) {
                    score += rule.points();
                    reasons.add(rule.label() + ": " + String.join(", ", found) + " (+" + rule.points() + ")");
                }
            }

            // ---- Step 4: links ----
            int bestLinkScore = 0;
            boolean unverifiedLink = false;
            for (String link : extractLinks(content)) {
                ScanResult r = urlAnalyzer.analyze(new ScanItem(item.id(), InputType.URL, link));
                if (r.level() == RiskLevel.NOT_VERIFIED) {
                    unverifiedLink = true;
                    reasons.add("Link could not be verified: " + link + " (" + r.error() + ")");
                } else if (r.score() > 0) {
                    bestLinkScore = Math.max(bestLinkScore, r.score());
                    reasons.add("Risky link " + link + " (+" + r.score() + "): " + String.join("; ", r.reasons()));
                }
            }
            score += bestLinkScore;   // only the riskiest link counts, so 5 links do not inflate the score

            // ---- Step 5: final result ----
            score = Math.min(score, MAX_SCORE);

            // Golden rule: a link we could not check must never lead to a "safe" answer.
            if (unverifiedLink && score < 20) {
                return ScanResult.notVerified(item, "A link in the message could not be verified");
            }
            return new ScanResult(item, ScoreMapper.map(score), score, List.copyOf(reasons), null);

        } catch (Exception e) {
            // An analyzer must NEVER throw.
            return ScanResult.notVerified(item, "Unexpected error: " + e.getClass().getSimpleName());
        }
    }

    // ------------------------------------------------------------------------------------
    // Helpers (package-private so the tests can call them)
    // ------------------------------------------------------------------------------------

    /** Finds the links in a message, e.g. "Visit http://a.com/x." gives ["http://a.com/x"]. */
    static List<String> extractLinks(String content) {
        Set<String> links = new LinkedHashSet<>();   // LinkedHashSet = no duplicates, keeps order
        Matcher m = LINK.matcher(content);
        while (m.find()) {
            String link = m.group();
            while (!link.isEmpty() && TRAILING_PUNCTUATION.indexOf(link.charAt(link.length() - 1)) >= 0) {
                link = link.substring(0, link.length() - 1);
            }
            if (link.regionMatches(true, 0, "www.", 0, 4)) {
                link = "https://" + link;   // no protocol given: do not punish it as "HTTP"
            }
            if (!link.isEmpty()) {
                links.add(link);
            }
        }
        return new ArrayList<>(links);
    }

    /**
     * Makes text easy to compare:
     * lowercase, no accents (é -> e), no Arabic diacritics, simplified Arabic letters,
     * Arabic-Indic digits (٢٤) -> 24, and one single space between words.
     */
    static String normalize(String s) {
        String t = s.toLowerCase(Locale.ROOT);
        t = Normalizer.normalize(t, Normalizer.Form.NFD).replaceAll("\\p{M}+", "");
        t = t.replace('ى', 'ي').replace('ة', 'ه');
        StringBuilder sb = new StringBuilder(t.length());
        for (char c : t.toCharArray()) {
            sb.append(c >= '٠' && c <= '٩' ? (char) ('0' + (c - '٠')) : c);
        }
        return sb.toString().replaceAll("\\s+", " ").trim();
    }

    // ------------------------------------------------------------------------------------
    // One rule = a label + points + a list of keywords
    // ------------------------------------------------------------------------------------

    private record Rule(String label, int points, List<Keyword> keywords) {
        Rule(String label, int points, String[] words) {
            this(label, points, build(words));
        }

        private static List<Keyword> build(String[] words) {
            List<Keyword> list = new ArrayList<>();
            for (String w : words) {
                list.add(new Keyword(w));
            }
            return List.copyOf(list);
        }c

        /** Up to 3 distinct keywords of this rule that appear in the (normalized) text. */
        List<String> findMatches(String text) {
            List<String> found = new ArrayList<>();
            for (Keyword k : keywords) {
                if (found.size() < 3 && !found.contains(k.text()) && k.pattern().matcher(text).find()) {
                    found.add(k.text());
                }
            }
            return found;
        }
    }

    private record Keyword(String text, Pattern pattern) {
        Keyword(String raw) {
            this(normalize(raw), compile(normalize(raw)));
        }

        private static Pattern compile(String word) {
            boolean arabic = word.codePoints().anyMatch(cp -> cp >= 0x0600 && cp <= 0x06FF);
            if (arabic) {
                // Arabic words get prefixes glued to them (ال, ب, و ...), so plain "contains" is used.
                return Pattern.compile(Pattern.quote(word));
            }
            // Latin words: whole word only ("pin" must not match "spinning"); optional plural "s".
            return Pattern.compile("(?<![\\p{L}\\p{N}])" + Pattern.quote(word) + "s?(?![\\p{L}\\p{N}])");
        }
    }
}
