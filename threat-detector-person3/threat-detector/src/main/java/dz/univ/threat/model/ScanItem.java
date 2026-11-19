package dz.univ.threat.model;

/** One thing to scan. Immutable. (Shared contract) */
public record ScanItem(int id, InputType type, String content) {}
