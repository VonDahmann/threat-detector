package threatdetect;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.DecimalFormatSymbols;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Writes the results table to a CSV file that opens correctly in Excel.
 * - UTF-8 with a BOM so accents survive.
 * - ';' as separator when the computer uses a decimal comma (French Windows), ',' otherwise.
 * - Cells starting with = + - @ get a leading ' so spreadsheets never run them as formulas
 *   (important here: the inputs are suspicious links and messages).
 */
public final class CsvExporter {

    private CsvExporter() {}

    /** Call this from a background thread. rows.get(0) is the header. */
    public static void write(Path path, List<List<String>> rows) throws IOException {
        char delimiter = defaultDelimiter();
        try (BufferedWriter w = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            w.write('\uFEFF');
            for (List<String> row : rows) {
                w.write(row.stream()
                        .map(v -> escape(v, delimiter))
                        .collect(Collectors.joining(String.valueOf(delimiter))));
                w.write("\r\n");
            }
        }
    }

    static char defaultDelimiter() {
        return DecimalFormatSymbols.getInstance().getDecimalSeparator() == ',' ? ';' : ',';
    }

    static String escape(String value, char delimiter) {
        String v = value == null ? "" : value;
        if (!v.isEmpty() && "=+-@\t\r".indexOf(v.charAt(0)) >= 0) {
            v = "'" + v;
        }
        boolean needsQuotes = v.indexOf(delimiter) >= 0 || v.indexOf('"') >= 0
                || v.indexOf('\n') >= 0 || v.indexOf('\r') >= 0;
        if (needsQuotes) {
            v = "\"" + v.replace("\"", "\"\"") + "\"";
        }
        return v;
    }
}
