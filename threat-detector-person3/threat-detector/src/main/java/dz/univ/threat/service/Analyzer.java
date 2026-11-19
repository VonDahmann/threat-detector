package dz.univ.threat.service;

import dz.univ.threat.model.ScanItem;
import dz.univ.threat.model.ScanResult;

/** An analyzer must NEVER throw: any problem becomes ScanResult.notVerified(...). (Shared contract) */
public interface Analyzer {
    ScanResult analyze(ScanItem item);
}
