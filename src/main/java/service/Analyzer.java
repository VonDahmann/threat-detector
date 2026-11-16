package service;

import model.ScanItem;
import model.ScanResult;

public interface Analyzer {

    /**
     * Must NEVER throw. Any problem is returned as ScanResult.notVerified(item, reason).
     * Implementations must be stateless so they are safe to share between threads (Sprint 2).
     */
    ScanResult analyze(ScanItem item);
}
