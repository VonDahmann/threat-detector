package com.threatdetect.service;

import com.threatdetect.model.InputItem;
import com.threatdetect.model.InputType;
import com.threatdetect.model.InvalidInputException;

import java.util.regex.Pattern;

public final class InputFactory {

    public static final int MAX_LENGTH = 5000;

    private static final Pattern WITH_SCHEME =
            Pattern.compile("^[a-z][a-z0-9+.-]*://\\S+$", Pattern.CASE_INSENSITIVE);
    private static final Pattern WWW =
            Pattern.compile("^www\\.\\S+$", Pattern.CASE_INSENSITIVE);
    private static final Pattern DOMAIN_LIKE =
            Pattern.compile("^[a-z0-9-]+(\\.[a-z0-9-]+)+(:\\d+)?([/?#]\\S*)?$", Pattern.CASE_INSENSITIVE);

    private InputFactory() {}

    /** Best guess: single token that looks like a link is a URL, everything else is a message. */
    public static InputType guess(String text) {
        String t = text.trim();
        if (WITH_SCHEME.matcher(t).matches()
                || WWW.matcher(t).matches()
                || DOMAIN_LIKE.matcher(t).matches()) {
            return InputType.URL;
        }
        return InputType.MESSAGE;
    }

    /** Builds one item from the UI text field. Pass type = null for auto-detect. */
    public static InputItem single(String text, InputType type) throws InvalidInputException {
        if (text == null || text.isBlank()) {
            throw new InvalidInputException("Please enter a URL or a message");
        }
        String t = text.trim();
        if (t.length() > MAX_LENGTH) {
            throw new InvalidInputException("Input is too long (max " + MAX_LENGTH + " characters)");
        }
        return new InputItem(type != null ? type : guess(t), t);
    }
}