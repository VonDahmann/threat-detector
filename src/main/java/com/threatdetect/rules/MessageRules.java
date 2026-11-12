package com.threatdetect.rules;

import com.threatdetect.model.InvalidInputException;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class MessageRules {

    private static final List<String> URGENCY = List.of(
            "urgent", "immediately", "act now", "right away", "within 24 hours", "final notice",
            "last warning", "account suspended", "will be suspended", "will be blocked", "expires today",
            "immédiatement", "dernier avertissement", "compte suspendu", "sous 24 heures");

    private static final List<String> CREDENTIALS = List.of(
            "password", "passcode", "pin code", "otp", "verification code", "security code",
            "card number", "cvv", "confirm your account", "verify your account", "login details",
            "mot de passe", "code de vérification", "numéro de carte", "identifiants");

    private static final List<String> REWARDS = List.of(
            "you won", "you have won", "winner", "lottery", "prize", "gift card", "claim your",
            "free money", "congratulations", "félicitations", "vous avez gagné", "gagnant");

    private static final Pattern LINK = Pattern.compile("(?i)\\b(?:https?://|www\\.)\\S+");

    private MessageRules() {}

    public static List<RuleHit> evaluate(String raw) throws InvalidInputException {
        if (raw == null || raw.isBlank()) {
            throw new InvalidInputException("Empty message");
        }

        String text = raw.trim();
        String lower = text.toLowerCase(Locale.ROOT);
        List<RuleHit> hits = new ArrayList<>();

        firstMatch(lower, URGENCY).ifPresent(w ->
                hits.add(new RuleHit(20, "Urgency language: \"" + w + "\"")));

        firstMatch(lower, CREDENTIALS).ifPresent(w ->
                hits.add(new RuleHit(30, "Requests sensitive information: \"" + w + "\"")));

        firstMatch(lower, REWARDS).ifPresent(w ->
                hits.add(new RuleHit(20, "Prize/reward bait: \"" + w + "\"")));

        // Links
        List<String> links = new ArrayList<>();
        Matcher m = LINK.matcher(text);
        while (m.find()) {
            links.add(m.group().replaceAll("[.,;:!?)]+$", ""));
        }
        if (!links.isEmpty()) {
            hits.add(new RuleHit(10, "Contains " + links.size() + " link(s)"));
            for (String link : links) {
                try {
                    int linkScore = RiskScorer.total(UrlRules.evaluate(link));
                    if (linkScore >= 30) {
                        hits.add(new RuleHit(25, "Contains a suspicious link: " + link));
                        break;
                    }
                } catch (InvalidInputException ignored) {
                    hits.add(new RuleHit(10, "Contains a malformed link: " + link));
                    break;
                }
            }
        }

        // Shouting
        long letters = text.chars().filter(Character::isLetter).count();
        long upper = text.chars().filter(Character::isUpperCase).count();
        if (letters >= 20 && upper > letters * 0.6) {
            hits.add(new RuleHit(10, "Mostly UPPERCASE text"));
        }

        // Excessive punctuation
        if (text.chars().filter(c -> c == '!').count() >= 3) {
            hits.add(new RuleHit(5, "Excessive exclamation marks"));
        }

        return hits;
    }

    private static Optional<String> firstMatch(String lower, List<String> words) {
        for (String w : words) {
            if (lower.contains(w)) return Optional.of(w);
        }
        return Optional.empty();
    }
}