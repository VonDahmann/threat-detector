package com.threatdetect.service;

import com.threatdetect.model.AnalysisResult;
import com.threatdetect.model.InputItem;

public interface ThreatEvaluator {
    /**
     * Must be interruptible: if the thread is interrupted (timeout or cancel),
     * implementations should stop and throw InterruptedException.
     */
    AnalysisResult evaluate(InputItem item, ProgressReporter progress) throws InterruptedException;
}