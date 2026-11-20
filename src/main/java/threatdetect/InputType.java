package threatdetect;

import java.util.Locale;
import java.util.Optional;

/** Kind of item the user wants to check. */
public enum InputType {
    URL("type.url"),
    EMAIL("type.email"),
    SMS("type.sms");

    private final String key;

    InputType(String key) {
        this.key = key;
    }

    /** Shown in the interface, in the current language. */
    @Override
    public String toString() {
        return I18n.t(key);
    }

    /** Reads the "type" column of a CSV file (url, email, sms...). */
    public static Optional<InputType> fromToken(String token) {
        if (token == null) return Optional.empty();
        return switch (token.strip().toLowerCase(Locale.ROOT)) {
            case "url", "link", "رابط" -> Optional.of(URL);
            case "email", "mail", "e-mail", "بريد" -> Optional.of(EMAIL);
            case "sms", "text", "رسالة" -> Optional.of(SMS);
            default -> Optional.empty();
        };
    }

    /** Best guess when a CSV row has no type column. */
    public static InputType guess(String content) {
        String s = content == null ? "" : content.strip();
        boolean singleToken = s.chars().noneMatch(Character::isWhitespace);
        if (singleToken && (s.contains("://") || s.toLowerCase(Locale.ROOT).startsWith("www.") || s.contains("."))) {
            return URL;
        }
        return s.length() > 160 ? EMAIL : SMS;
    }
}
