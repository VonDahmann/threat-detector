package model;

/** One thing to scan: a URL or a message. Immutable. */
public record ScanItem(int id, InputType type, String content) {
}
