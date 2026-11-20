package threatdetect;

import java.io.IOException;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Minimal CSV reader so the UI can be demonstrated alone. Teammates' parser can replace it.
 * Accepted rows: "type,content" or just "content". Comma and semicolon separators work.
 * Bad rows are reported, never thrown.
 */
public final class CsvInputLoader {

    public static final int MAX_CONTENT_LENGTH = 2000;
    private static final Set<String> HEADER_WORDS = Set.of("type", "content", "url", "message", "text", "input", "id", "المعرّف", "المعرف");

    public record Entry(InputType type, String content, int line) {}
    public record LoadResult(List<Entry> entries, List<String> errors) {}

    private CsvInputLoader() {}

    /** Throws IOException with a message that is safe to show to the user. */
    public static LoadResult load(Path path) throws IOException {
        if (path == null || !Files.exists(path)) {
            throw new IOException(I18n.t("csv.err.notfound"));
        }
        if (Files.isDirectory(path)) {
            throw new IOException(I18n.t("csv.err.folder"));
        }
        if (!path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".csv")) {
            throw new IOException(I18n.t("csv.err.notcsv"));
        }
        if (!Files.isReadable(path)) {
            throw new IOException(I18n.t("csv.err.unreadable"));
        }

        List<String> lines;
        try {
            lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        } catch (MalformedInputException e) {
            throw new IOException(I18n.t("csv.err.utf8"));
        }

        List<Entry> entries = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        char delimiter = 0;
        boolean first = true;

        for (int i = 0; i < lines.size(); i++) {
            int lineNo = i + 1;
            String raw = lines.get(i);
            if (i == 0 && raw.startsWith("\uFEFF")) raw = raw.substring(1);
            if (raw.isBlank()) continue;

            if (delimiter == 0) delimiter = detectDelimiter(raw);
            boolean isFirstRow = first;
            first = false;

            List<String> fields = splitLine(raw, delimiter);
            if (fields == null) {
                errors.add(I18n.t("csv.err.quote", lineNo));
                continue;
            }
            if (isFirstRow && HEADER_WORDS.contains(fields.get(0).toLowerCase(Locale.ROOT))) {
                continue; // header row
            }

            Optional<InputType> parsedType = fields.size() >= 2 ? InputType.fromToken(fields.get(0)) : Optional.empty();
            InputType type;
            String content;
            // A file exported by this app: id;type;input;risk;status;seconds;details
            boolean exported = fields.size() >= 4 && fields.get(0).matches("\\d+")
                    && InputType.fromToken(fields.get(1)).isPresent();
            if (exported) {
                type = InputType.fromToken(fields.get(1)).get();
                content = fields.get(2);
            } else if (parsedType.isPresent()) {
                type = parsedType.get();
                content = fields.size() == 2
                        ? fields.get(1)
                        : raw.substring(raw.indexOf(delimiter) + 1).strip();
            } else {
                content = fields.size() == 1 ? fields.get(0) : raw.strip();
                type = InputType.guess(content);
            }

            if (content.isBlank()) {
                errors.add(I18n.t("csv.err.empty", lineNo));
            } else if (content.length() > MAX_CONTENT_LENGTH) {
                errors.add(I18n.t("csv.err.long", lineNo, MAX_CONTENT_LENGTH));
            } else {
                entries.add(new Entry(type, content, lineNo));
            }
        }
        return new LoadResult(entries, errors);
    }

    private static char detectDelimiter(String line) {
        long commas = line.chars().filter(c -> c == ',').count();
        long semicolons = line.chars().filter(c -> c == ';').count();
        return semicolons > commas ? ';' : ',';
    }

    /** Returns null when a quote is left open. */
    static List<String> splitLine(String line, char delimiter) {
        List<String> fields = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inQuotes) {
                if (c == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        cur.append('"');
                        i++;
                    } else {
                        inQuotes = false;
                    }
                } else {
                    cur.append(c);
                }
            } else if (c == '"' && cur.toString().isBlank()) {
                inQuotes = true;
                cur.setLength(0);
            } else if (c == delimiter) {
                fields.add(cur.toString().strip());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        if (inQuotes) return null;
        fields.add(cur.toString().strip());
        return fields;
    }
}
