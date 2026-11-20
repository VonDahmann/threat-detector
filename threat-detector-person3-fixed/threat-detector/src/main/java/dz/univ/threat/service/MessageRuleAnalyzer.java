// This class belongs to the "service" package (the backend logic). The backend must NEVER import
// javax.swing (golden rule of requirement 3: backend completely separated from the UI).
package dz.univ.threat.service;

// ---- Imports from our own project (the shared contracts written by Person 1) ----
import dz.univ.threat.model.InputType;   // enum: URL or MESSAGE
import dz.univ.threat.model.RiskLevel;   // enum: LOW, MEDIUM, HIGH, NOT_VERIFIED
import dz.univ.threat.model.ScanItem;    // record: (id, type, content) = the thing to scan
import dz.univ.threat.model.ScanResult;  // record: the answer we return

// ---- Imports from the Java standard library ----
import java.text.Normalizer;             // splits "é" into "e" + accent so we can remove the accent
import java.util.ArrayList;              // resizable list
import java.util.LinkedHashSet;          // a set (no duplicates) that remembers insertion order
import java.util.List;                   // list interface
import java.util.Locale;                 // used so toLowerCase does not depend on the PC language
import java.util.Objects;                // Objects.requireNonNull = null check helper
import java.util.Set;                    // set interface
import java.util.regex.Matcher;          // runs a regex on a text
import java.util.regex.Pattern;          // a compiled regular expression

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
// "implements Analyzer" = we promise to have the method analyze(ScanItem) that NEVER throws.
public class MessageRuleAnalyzer implements Analyzer {

    // =====================================================================================
    // POINTS: how many risk points each rule adds (same values as the sprint guide, section 6)
    // "static final" = constants shared by the whole class that can never change.
    // They are package-private (no "public") so the tests in the same package can read them.
    // =====================================================================================
    static final int POINTS_URGENCY = 25;   // "urgent", "within 24 hours"...        -> +25
    static final int POINTS_THREAT = 25;    // "suspended", "blocked"...             -> +25
    static final int POINTS_SECRETS = 40;   // "password", "OTP", "PIN", "CVV"...    -> +40
    static final int POINTS_GENERIC = 20;   // "account", "verify"...                -> +20
    static final int MAX_SCORE = 100;       // the total can never be higher than 100

    // =====================================================================================
    // PRE-COMPILED REGULAR EXPRESSIONS used by normalize().
    // IMPORTANT: they are declared BEFORE the RULES list below on purpose. Java initializes
    // static fields from top to bottom, and building RULES calls normalize(), which uses these.
    // If they were declared after RULES they would still be null and the class would crash.
    // Compiling a regex once here (instead of on every message) is also faster.
    // =====================================================================================

    // \p{M} = any "mark": accents (é = e + ́), Arabic diacritics (fatha, damma, shadda...).
    // The "+" means "one or more in a row".
    private static final Pattern COMBINING_MARKS = Pattern.compile("\\p{M}+");

    // \s = any whitespace (space, tab, new line, non-breaking space...). Used to collapse spaces.
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    // U+0640 = Arabic "tatweel" (the stretching line in "عـاجـل"). It is only decoration, so we
    // delete it, otherwise "عـاجـل" would not match the keyword "عاجل".
    private static final Pattern TATWEEL = Pattern.compile("ـ");

    // =====================================================================================
    // KEYWORD LISTS (English / French / Arabic).
    // Write them naturally (with accents etc.): normalize() is applied to them automatically
    // when the class loads, so they are compared in the same "simplified" form as the message.
    // To tune the detector, just add or remove words here.
    // =====================================================================================

    // Rule 1: URGENCY language (pressure to act fast). +25
    private static final String[] URGENCY = {
            // EN  (English)
            "urgent", "urgently", "immediately", "within 24 hours", "within 48 hours", "final notice",
            "last warning", "act now", "right away", "asap", "expires today",
            // FR  (French)
            "immédiatement", "dans les 24 heures", "sous 24h", "dernier avis", "dernier rappel", "sans délai",
            // AR  (Arabic)
            "عاجل", "عاجلا", "فورا", "فوراً", "خلال 24 ساعة", "آخر تحذير", "في أسرع وقت"
    };

    // Rule 2: THREAT of account suspension / blocking (fear). +25
    private static final String[] THREAT = {
            // EN
            "suspension", "suspended", "suspend", "blocked", "locked", "deactivated", "terminated",
            "restricted", "will be closed",
            // FR
            "suspendu", "suspendue", "bloqué", "bloquée", "verrouillé", "désactivé", "désactivée",
            // AR
            "تعليق", "معلق", "إيقاف", "حظر", "مغلق", "تجميد", "سيتم إغلاق"
    };

    // Rule 3: asking for SECRETS (the most dangerous sign of phishing). +40
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

    // Rule 4: GENERIC account / verification words (weak signal on their own). +20
    private static final String[] GENERIC = {
            // EN
            "account", "verify", "verification", "notification", "login", "log in", "sign in",
            // FR
            "compte", "vérifier", "vérification", "connexion",
            // AR
            "حساب", "تحقق", "التحقق", "إشعار", "الإشعارات", "تسجيل الدخول"
    };

    // The 4 rules in one list, so analyze() can simply loop over them.
    // List.of(...) makes an unmodifiable list (nobody can change the rules while running).
    // Each Rule = (label shown to the user, points, keyword array).
    private static final List<Rule> RULES = List.of(
            new Rule("Urgency language", POINTS_URGENCY, URGENCY),
            new Rule("Account suspension / blocking threat", POINTS_THREAT, THREAT),
            new Rule("Asks for secret data", POINTS_SECRETS, SECRETS),
            new Rule("Mentions account / verification", POINTS_GENERIC, GENERIC)
    );

    // Regex that finds links inside a message:
    //   (?i)            = ignore upper/lower case (HTTP:// works too)
    //   \b              = start at a word boundary (so "xwww.a.com" is not matched in the middle)
    //   (?:https?://|www\.) = the link begins with http://, https:// or "www."
    //   [^\s<>"']+      = then take every character until a space, < > or a quote
    private static final Pattern LINK = Pattern.compile("(?i)\\b(?:https?://|www\\.)[^\\s<>\"']+");

    // Characters that are often glued to the END of a link in normal writing, e.g.
    // "Visit http://a.com." (final dot) or "(http://a.com)". They are not part of the link,
    // so we remove them. Includes the Arabic comma ، and the Arabic question mark ؟.
    private static final String TRAILING_PUNCTUATION = ".,;:!?)]}»'\"،؟";

    // The analyzer used to score each link found in a message (Person 2's UrlRuleAnalyzer by
    // default). "final" = set once in the constructor, never changed => class stays thread-safe.
    private final Analyzer urlAnalyzer;

    /** Default: uses the project's UrlRuleAnalyzer to score links. */
    public MessageRuleAnalyzer() {
        // Call the other constructor below, giving it a new UrlRuleAnalyzer.
        this(new UrlRuleAnalyzer());
    }

    /** Lets tests (or Sprint 2) give another analyzer for links. */
    public MessageRuleAnalyzer(Analyzer urlAnalyzer) {
        // requireNonNull stops immediately with a clear message if someone passes null here
        // (a programming mistake), instead of failing later in a confusing place.
        this.urlAnalyzer = Objects.requireNonNull(urlAnalyzer, "urlAnalyzer");
    }

    /**
     * Main method required by the Analyzer contract. It NEVER throws: every problem becomes
     * a NOT_VERIFIED result (golden rule of the project).
     */
    @Override   // tells the compiler we are implementing the method declared in Analyzer
    public ScanResult analyze(ScanItem item) {
        // One big try/catch around everything: whatever unexpected error happens inside,
        // we catch it at the bottom and return NOT_VERIFIED instead of crashing the app.
        try {
            // ---- Step 1: check the input -------------------------------------------------
            if (item == null) {
                // No item at all (should not happen, but we never trust inputs).
                return ScanResult.notVerified(null, "No item to analyze");
            }
            if (item.type() != InputType.MESSAGE) {
                // This analyzer only understands messages; URLs go to UrlRuleAnalyzer.
                return ScanResult.notVerified(item, "MessageRuleAnalyzer only analyzes MESSAGE items");
            }
            // Take the text of the message out of the item.
            String content = item.content();
            if (content == null || content.isBlank()) {
                // Empty or only spaces/tabs/new lines: we cannot judge it => NOT_VERIFIED,
                // NEVER Low (row 10 of the dataset). The exact text "Empty input" is in the guide.
                return ScanResult.notVerified(item, "Empty input");
            }

            // The running total of points, and the list of explanations for the UI.
            int score = 0;
            List<String> reasons = new ArrayList<>();

            // ---- Steps 2 + 3: normalize the text, then apply the keyword rules -----------
            // Normalized copy used ONLY for keyword search ("IMMÉDIATEMENT" -> "immediatement").
            // The original "content" is kept untouched for extracting links.
            String text = normalize(content);
            // Go through the 4 rules one by one.
            for (Rule rule : RULES) {
                // Ask the rule which of its keywords appear in the text (max 3, for readability).
                List<String> found = rule.findMatches(text);
                // If at least one keyword matched, the rule "fires" ONE time only:
                // 5 urgent words give +25, not +125 (otherwise long messages explode the score).
                if (!found.isEmpty()) {
                    score += rule.points();   // add the points of this rule
                    // Add a readable reason, e.g. "Urgency language: urgent, asap (+25)"
                    reasons.add(rule.label() + ": " + String.join(", ", found) + " (+" + rule.points() + ")");
                }
            }

            // ---- Step 4: links inside the message ----------------------------------------
            int bestLinkScore = 0;             // the highest link score found so far
            boolean unverifiedLink = false;    // becomes true if at least one link could not be checked
            // Loop over every link found in the ORIGINAL text.
            for (String link : extractLinks(content)) {
                // Re-use the URL analyzer by wrapping the link in a ScanItem of type URL.
                // We keep the same id as the message so results can be tied back to it.
                ScanResult r = urlAnalyzer.analyze(new ScanItem(item.id(), InputType.URL, link));
                if (r.level() == RiskLevel.NOT_VERIFIED) {
                    // The link could not be checked (malformed, analyzer error...). Remember it
                    // (used by the golden-rule check below) and tell the user in the reasons.
                    unverifiedLink = true;
                    reasons.add("Link could not be verified: " + link + " (" + r.error() + ")");
                } else if (r.score() > 0) {
                    // A risky link: keep the maximum score among all links.
                    bestLinkScore = Math.max(bestLinkScore, r.score());
                    // Explain it, including the reasons given by the URL analyzer.
                    reasons.add("Risky link " + link + " (+" + r.score() + "): " + String.join("; ", r.reasons()));
                }
                // A link with score 0 is safe-looking: nothing to add, nothing to say.
            }
            // Only the RISKIEST link counts, so a message with 5 links does not inflate the score.
            score += bestLinkScore;

            // ---- Step 5: final result ----------------------------------------------------
            // Never exceed 100 points (row 7: 25 + 25 + 20 + 70 = 140 becomes 100).
            score = Math.min(score, MAX_SCORE);

            // GOLDEN RULE: if a link could not be verified AND nothing else made the message look
            // risky (score under 20 = would be LOW), saying "Low" would be a lie. So we answer
            // NOT_VERIFIED instead. (If the score is already Medium/High we keep it: that is
            // already a warning, and "unverified" cannot make a risky message safer.)
            if (unverifiedLink && score < 20) {
                return ScanResult.notVerified(item, "A link in the message could not be verified");
            }
            // Normal case: convert the score to LOW / MEDIUM / HIGH with the shared ScoreMapper
            // (under 20 = Low, 20-39 = Medium, 40+ = High) and return the finished result.
            // error = null because everything went fine. The ScanResult constructor already makes
            // its own immutable copy of the reasons list.
            return new ScanResult(item, ScoreMapper.map(score), score, reasons, null);

        } catch (Exception e) {
            // Safety net: any unexpected exception (bug, bad regex input...) ends up here.
            // We return NOT_VERIFIED with the exception type, never Low, and never rethrow.
            return ScanResult.notVerified(item, "Unexpected error: " + e.getClass().getSimpleName());
        }
    }

    // ------------------------------------------------------------------------------------
    // Helpers (package-private = no "public", so the tests in the same package can call them)
    // ------------------------------------------------------------------------------------

    /** Finds the links in a message, e.g. "Visit http://a.com/x." gives ["http://a.com/x"]. */
    static List<String> extractLinks(String content) {
        // LinkedHashSet: a set refuses duplicates (the same link written twice counts once)
        // and keeps the order in which links appear in the message.
        Set<String> links = new LinkedHashSet<>();
        // Prepare the regex search on the message text.
        Matcher m = LINK.matcher(content);
        // m.find() jumps to the next match each time, and returns false when there are no more.
        while (m.find()) {
            String link = m.group();   // the text that matched, e.g. "http://a.com/x."
            // Remove punctuation glued at the end, one character at a time, as long as the link
            // is not empty and its last character is in the TRAILING_PUNCTUATION list.
            while (!link.isEmpty() && TRAILING_PUNCTUATION.indexOf(link.charAt(link.length() - 1)) >= 0) {
                link = link.substring(0, link.length() - 1);   // cut off the last character
            }
            // If the link starts with "www." (any case) it has no protocol. We add "https://" so the
            // URL analyzer does not punish it with the "HTTP instead of HTTPS" rule, and so that
            // java.net.URI can parse it (URI needs a scheme).
            if (link.regionMatches(true, 0, "www.", 0, 4)) {
                link = "https://" + link;
            }
            // Only store it if something is left after cleaning.
            if (!link.isEmpty()) {
                links.add(link);
            }
        }
        // Return a normal list (the caller only needs to loop over it).
        return new ArrayList<>(links);
    }

    /**
     * Makes text easy to compare:
     * lowercase, no accents (é -> e), no Arabic diacritics, simplified Arabic letters,
     * Arabic-Indic digits (٢٤) -> 24, and one single space between words.
     */
    static String normalize(String s) {
        // 1) Lowercase. Locale.ROOT = fixed rules, so the result is the same on every computer
        //    (e.g. a Turkish PC would otherwise turn "I" into a dotless "ı").
        String t = s.toLowerCase(Locale.ROOT);
        // 2) NFD = "decomposed" form: "é" becomes "e" + a separate accent character. Then we delete
        //    all the accent characters. This also turns Arabic "أ إ آ" into a bare "ا" and removes
        //    Arabic vowel marks (tashkeel), so "فوراً" becomes "فورا".
        t = COMBINING_MARKS.matcher(Normalizer.normalize(t, Normalizer.Form.NFD)).replaceAll("");
        // 3) Remove the Arabic tatweel (decorative stretching line).
        t = TATWEEL.matcher(t).replaceAll("");
        // 4) Unify two Arabic letters that people write interchangeably:
        //    "ى" (alef maqsura) -> "ي" (ya)   and   "ة" (ta marbuta) -> "ه" (ha).
        t = t.replace('ى', 'ي').replace('ة', 'ه');
        // 5) Convert Arabic digits to normal digits, character by character, so "٢٤ ساعة" and
        //    "24 ساعة" are equal. StringBuilder = efficient way to build a string piece by piece.
        StringBuilder sb = new StringBuilder(t.length());
        for (char c : t.toCharArray()) {
            if (c >= '٠' && c <= '٩') {
                sb.append((char) ('0' + (c - '٠')));        // Arabic-Indic digits  ٠-٩  (U+0660..0669)
            } else if (c >= '۰' && c <= '۹') {
                sb.append((char) ('0' + (c - '۰')));        // Persian/Urdu digits  ۰-۹  (U+06F0..06F9)
            } else {
                sb.append(c);                                // any other character stays as it is
            }
        }
        // 6) Replace every run of spaces/tabs/new lines by ONE space and trim both ends,
        //    so "mot   de\npasse" becomes "mot de passe".
        return WHITESPACE.matcher(sb).replaceAll(" ").trim();
    }

    // ------------------------------------------------------------------------------------
    // One rule = a label + points + a list of keywords
    // "private record" = small data class used only inside MessageRuleAnalyzer.
    // ------------------------------------------------------------------------------------

    private record Rule(String label, int points, List<Keyword> keywords) {

        // Convenience constructor: lets us write new Rule("...", 25, URGENCY) with a plain
        // String[] and converts it into a list of Keyword objects.
        Rule(String label, int points, String[] words) {
            this(label, points, build(words));   // call the main (canonical) constructor
        }

        // Turns each raw word ("immédiatement") into a Keyword (normalized text + regex).
        private static List<Keyword> build(String[] words) {
            List<Keyword> list = new ArrayList<>();
            for (String w : words) {
                list.add(new Keyword(w));
            }
            return List.copyOf(list);   // unmodifiable: nobody can change the rule later
        }

        /** Up to 3 distinct keywords of this rule that appear in the (normalized) text. */
        List<String> findMatches(String text) {
            List<String> found = new ArrayList<>();
            for (Keyword k : keywords) {
                // Conditions to accept the keyword:
                //  - we have fewer than 3 already (keeps the explanation short),
                //  - it is not already in the list,
                //  - its regex really matches somewhere in the text.
                if (found.size() < 3 && !found.contains(k.text()) && k.pattern().matcher(text).find()) {
                    found.add(k.text());
                }
            }
            return found;   // empty list = this rule does not fire
        }
    }

    // One keyword = its normalized text (for display) + the compiled regex used to search it.
    private record Keyword(String text, Pattern pattern) {

        // Convenience constructor taking the raw word as written in the lists above.
        Keyword(String raw) {
            // normalize() is called once to build the text and once to build the pattern.
            this(normalize(raw), compile(normalize(raw)));
        }

        // Builds the right regex depending on the alphabet of the word.
        private static Pattern compile(String word) {
            // Is there at least one character in the Arabic block (U+0600 to U+06FF)?
            boolean arabic = word.codePoints().anyMatch(cp -> cp >= 0x0600 && cp <= 0x06FF);
            if (arabic) {
                // Arabic words get prefixes/suffixes glued to them (ال, ب, و, ك...), for example
                // "حساب" inside "حسابك" or "بحسابك". So we use a plain "contains" search.
                // Pattern.quote escapes any special regex characters so the word is taken literally.
                return Pattern.compile(Pattern.quote(word));
            }
            // Latin words (English / French): WHOLE WORD ONLY, so "pin" does not match "spinning".
            //   (?<![\p{L}\p{N}])  = not preceded by a letter or digit  (word starts here)
            //   quote(word)        = the keyword itself, literally
            //   s?                 = optional plural "s" (password / passwords)
            //   (?![\p{L}\p{N}])   = not followed by a letter or digit  (word ends here)
            return Pattern.compile("(?<![\\p{L}\\p{N}])" + Pattern.quote(word) + "s?(?![\\p{L}\\p{N}])");
        }
    }
}
