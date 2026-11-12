package com.threatdetect.service;

import com.threatdetect.model.InvalidInputException;

import java.nio.file.Files;
import java.nio.file.Path;

public class CsvTest {

    public static void main(String[] args) throws Exception {
        CsvParserService parser = new CsvParserService();
        Path dir = Files.createTempDirectory("csvtest");

        Path good = dir.resolve("good.csv");
        Files.writeString(good, """
                type,content
                URL,https://www.google.com
                url,http://paypal.secure-login.xyz/verify
                MESSAGE,"URGENT, send your password immediately"
                message,"She said ""hello"", then left"
                sms,Hi are we meeting tomorrow?
                banana,whatever
                URL,
                URL,too,many,columns

                MESSAGE,"multi
                line message"
                MESSAGE,"unterminated
                """);
        show("good.csv (mixed valid/invalid rows)", parser, good);

        Path single = dir.resolve("single.csv");
        Files.writeString(single, """
                url
                https://github.com
                bit.ly/abc
                192.168.1.1/login
                Hello are you free tonight?
                """);
        show("single.csv (one column, auto-detect)", parser, single);

        show("missing file", parser, dir.resolve("missing.csv"));

        Path empty = dir.resolve("empty.csv");
        Files.writeString(empty, "");
        show("empty file", parser, empty);

        Path headerOnly = dir.resolve("header.csv");
        Files.writeString(headerOnly, "type,content\n");
        show("header only", parser, headerOnly);

        Path wrongExt = dir.resolve("data.pdf");
        Files.writeString(wrongExt, "URL,https://x.com");
        show("wrong extension", parser, wrongExt);

        Path badUtf8 = dir.resolve("bad.csv");
        Files.write(badUtf8, new byte[]{(byte) 0xC3, (byte) 0x28, 'a', ',', 'b'});
        show("invalid UTF-8", parser, badUtf8);
    }

    private static void show(String label, CsvParserService parser, Path p) {
        System.out.println("=== " + label + " ===");
        try {
            CsvParseResult r = parser.parse(p);
            System.out.println("  rows=" + r.totalRows() + " items=" + r.items().size() + " errors=" + r.errors().size());
            r.items().forEach(i ->
                    System.out.println("  OK     " + i.getType() + " | " + i.getContent().replace("\n", "\\n")));
            r.errors().forEach(e ->
                    System.out.println("  ERROR  line " + e.line() + ": " + e.reason()));
        } catch (InvalidInputException e) {
            System.out.println("  REJECTED: " + e.getMessage());
        }
    }
}