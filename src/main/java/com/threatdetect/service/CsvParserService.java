package com.threatdetect.service;

import com.threatdetect.model.InputItem;
import com.threatdetect.model.InputType;
import com.threatdetect.model.InvalidInputException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

public final class CsvParserService {

    public static final long MAX_FILE_BYTES = 5L * 1024 * 1024;
    public static final int MAX_ROWS = 5000;

    private static final Set<String> TWO_COL_HEADERS = Set.of("type", "kind");
    private static final Set<String> ONE_COL_HEADERS =
            Set.of("url", "urls", "link", "message", "messages", "content", "input", "text");

    private record RawRecord(int line, List<String> cells, boolean unterminatedQuote) {}

    /** File-level problems throw InvalidInputException; row-level problems go into the result. */
    public CsvParseResult parse(Path path) throws InvalidInputException {
        if (path == null) {
            throw new InvalidInputException("No file selected");
        }
        String name = path.getFileName() == null ? path.toString() : path.getFileName().toString();

        if (!Files.exists(path)) {
            throw new InvalidInputException("File not found: " + name);
        }
        if (!Files.isRegularFile(path)) {
            throw new InvalidInputException("Not a regular file: " + name);
        }
        if (!Files.isReadable(path)) {
            throw new InvalidInputException("File is not readable: " + name);
        }
        String lower = name.toLowerCase(Locale.ROOT);
        if (!lower.endsWith(".csv") && !lower.endsWith(".txt")) {
            throw new InvalidInputException("Unsupported file type (expected .csv): " + name);
        }

        String text;
        try {
            long size = Files.size(path);
            if (size == 0) {
                throw new InvalidInputException("File is empty: " + name);
            }
            if (size > MAX_FILE_BYTES) {
                throw new InvalidInputException("File is too large (max " + (MAX_FILE_BYTES / 1024 / 1024) + " MB)");
            }
            byte[] bytes = Files.readAllBytes(path);
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new InvalidInputException("File is not valid UTF-8 text: " + name);
        } catch (IOException e) {
            throw new InvalidInputException("Cannot read file: " + e.getMessage());
        }

        if (text.startsWith("\uFEFF")) {
            text = text.substring(1);   // strip BOM (Excel adds it)
        }
        return parseText(text);
    }

    // ------------------------------------------------------------------ parsing

    CsvParseResult parseText(String text) throws InvalidInputException {
        List<RawRecord> records = tokenize(text);

        int idx = 0;
        while (idx < records.size() && isBlank(records.get(idx))) idx++;
        if (idx >= records.size()) {
            throw new InvalidInputException("File contains no data");
        }
        if (isHeader(records.get(idx).cells())) {
            idx++;
        }

        List<InputItem> items = new ArrayList<>();
        List<RowError> errors = new ArrayList<>();
        int total = 0;

        for (int i = idx; i < records.size(); i++) {
            RawRecord r = records.get(i);
            if (isBlank(r)) continue;   // blank lines are ignored silently

            total++;
            if (total > MAX_ROWS) {
                errors.add(new RowError(r.line(), "Row limit exceeded (" + MAX_ROWS + "), remaining rows ignored"));
                total--;
                break;
            }
            if (r.unterminatedQuote()) {
                errors.add(new RowError(r.line(), "Unterminated quote (rest of the file was swallowed by this row)"));
                continue;
            }

            List<String> cells = r.cells();
            String typeText;
            String content;

            if (cells.size() == 1) {
                content = cells.get(0).trim();
                typeText = null;
            } else if (cells.size() == 2) {
                typeText = cells.get(0).trim();
                content = cells.get(1).trim();
            } else {
                errors.add(new RowError(r.line(),
                        "Expected 1 or 2 columns but found " + cells.size() + " (put text containing commas in quotes)"));
                continue;
            }

            InputType type;
            if (typeText == null) {
                type = InputFactory.guess(content);
            } else {
                Optional<InputType> parsed = parseType(typeText);
                if (parsed.isEmpty()) {
                    errors.add(new RowError(r.line(), "Unknown type '" + typeText + "' (expected URL or MESSAGE)"));
                    continue;
                }
                type = parsed.get();
            }

            if (content.isBlank()) {
                errors.add(new RowError(r.line(), "Empty content"));
                continue;
            }
            if (content.length() > InputFactory.MAX_LENGTH) {
                errors.add(new RowError(r.line(), "Content too long (max " + InputFactory.MAX_LENGTH + " characters)"));
                continue;
            }
            items.add(new InputItem(type, content));
        }

        if (items.isEmpty() && errors.isEmpty()) {
            throw new InvalidInputException("File has a header but no data rows");
        }
        return new CsvParseResult(items, errors, total);
    }

    /** Small RFC-4180 style tokenizer: quotes, "" escapes, commas and newlines inside quotes. */
    private List<RawRecord> tokenize(String text) {
        List<RawRecord> records = new ArrayList<>();
        List<String> cells = new ArrayList<>();
        StringBuilder cell = new StringBuilder();
        boolean inQuotes = false;
        int line = 1;
        int recordStartLine = 1;
        int n = text.length();

        for (int i = 0; i < n; i++) {
            char c = text.charAt(i);
            if (inQuotes) {
                if (c == '"') {
                    if (i + 1 < n && text.charAt(i + 1) == '"') {
                        cell.append('"');
                        i++;
                    } else {
                        inQuotes = false;
                    }
                } else {
                    if (c == '\n') line++;
                    cell.append(c);
                }
            } else {
                switch (c) {
                    case '"' -> inQuotes = true;
                    case ',' -> {
                        cells.add(cell.toString());
                        cell.setLength(0);
                    }
                    case '\r' -> { }
                    case '\n' -> {
                        cells.add(cell.toString());
                        records.add(new RawRecord(recordStartLine, cells, false));
                        cells = new ArrayList<>();
                        cell.setLength(0);
                        line++;
                        recordStartLine = line;
                    }
                    default -> cell.append(c);
                }
            }
        }

        if (inQuotes) {
            cells.add(cell.toString());
            records.add(new RawRecord(recordStartLine, cells, true));
        } else if (cell.length() > 0 || !cells.isEmpty()) {
            cells.add(cell.toString());
            records.add(new RawRecord(recordStartLine, cells, false));
        }
        return records;
    }

    private static boolean isBlank(RawRecord r) {
        return !r.unterminatedQuote() && r.cells().stream().allMatch(String::isBlank);
    }

    private static boolean isHeader(List<String> cells) {
        String first = cells.get(0).trim().toLowerCase(Locale.ROOT);
        if (cells.size() == 1) return ONE_COL_HEADERS.contains(first);
        if (cells.size() == 2) return TWO_COL_HEADERS.contains(first);
        return false;
    }

    private static Optional<InputType> parseType(String s) {
        return switch (s.toLowerCase(Locale.ROOT)) {
            case "url", "link", "website" -> Optional.of(InputType.URL);
            case "message", "msg", "sms", "email", "mail", "text" -> Optional.of(InputType.MESSAGE);
            default -> Optional.empty();
        };
    }
}