package com.threatdetect.service;

import com.threatdetect.model.AnalysisResult;
import com.threatdetect.model.InputItem;

/**
 * Callbacks are invoked from WORKER threads, never from the UI thread.
 * A UI implementation must hop to the UI thread (Platform.runLater).
 */
public interface AnalysisListener {
    default void onStarted(InputItem item) {}
    default void onProgress(InputItem item, int percent) {}
    default void onCompleted(InputItem item, AnalysisResult result) {}
    default void onBatchFinished() {}
}