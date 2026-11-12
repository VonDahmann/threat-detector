package com.threatdetect.service;

import com.threatdetect.model.AnalysisResult;
import com.threatdetect.model.InputItem;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class ThreatAnalysisService {

    /** Handle returned to the caller so a running batch can be cancelled. */
    public static final class BatchHandle {
        private final AtomicInteger remaining;
        private final AtomicBoolean cancelled = new AtomicBoolean(false);
        private final Set<Thread> activeThreads = ConcurrentHashMap.newKeySet();

        private BatchHandle(int size) {
            this.remaining = new AtomicInteger(size);
        }

        public void cancel() {
            cancelled.set(true);
            activeThreads.forEach(Thread::interrupt);   // stop items already running
        }

        public boolean isCancelled() {
            return cancelled.get();
        }
    }

    private final ThreatEvaluator evaluator;
    private final long timeoutMs;
    private final ExecutorService workers;             // runs the evaluations
    private final ScheduledExecutorService watchdog;   // enforces timeouts

    public ThreatAnalysisService(ThreatEvaluator evaluator, int poolSize, long timeoutMs) {
        this.evaluator = evaluator;
        this.timeoutMs = timeoutMs;
        this.workers = Executors.newFixedThreadPool(poolSize, daemonFactory("analysis-worker"));
        this.watchdog = Executors.newSingleThreadScheduledExecutor(daemonFactory("analysis-watchdog"));
    }

    /** Submits every item as its own task and returns immediately (non-blocking). */
    public BatchHandle submit(List<InputItem> items, AnalysisListener listener) {
        BatchHandle batch = new BatchHandle(items.size());
        if (items.isEmpty()) {
            safe(listener::onBatchFinished);
            return batch;
        }
        for (InputItem item : items) {
            workers.execute(() -> process(item, listener, batch));
        }
        return batch;
    }

    public void shutdown() {
        workers.shutdownNow();
        watchdog.shutdownNow();
    }

    // ---------------------------------------------------------------- internals

    private void process(InputItem item, AnalysisListener listener, BatchHandle batch) {
        AnalysisResult result = evaluateSafely(item, listener, batch);

        safe(() -> listener.onCompleted(item, result));

        // The worker that finishes the LAST item announces the end of the batch.
        if (batch.remaining.decrementAndGet() == 0) {
            safe(listener::onBatchFinished);
        }
    }

    /** Never throws and never returns "safe" for something that was not verified. */
    private AnalysisResult evaluateSafely(InputItem item, AnalysisListener listener, BatchHandle batch) {
        Thread self = Thread.currentThread();
        AtomicBoolean timedOut = new AtomicBoolean(false);
        ScheduledFuture<?> timer = null;

        try {
            if (batch.isCancelled()) {
                return AnalysisResult.notVerified(item.getId(), "Cancelled by user");
            }

            batch.activeThreads.add(self);
            safe(() -> listener.onStarted(item));

            // The timeout clock starts when the item starts running, not while it waits in the queue.
            timer = watchdog.schedule(() -> {
                timedOut.set(true);
                self.interrupt();
            }, timeoutMs, TimeUnit.MILLISECONDS);

            return evaluator.evaluate(item, percent -> safe(() -> listener.onProgress(item, percent)));

        } catch (InterruptedException e) {
            String why = timedOut.get() ? "Timed out after " + timeoutMs + " ms"
                    : batch.isCancelled() ? "Cancelled by user"
                    : "Interrupted";
            return AnalysisResult.notVerified(item.getId(), why);

        } catch (Exception e) {
            return AnalysisResult.notVerified(item.getId(), "Unexpected failure: " + e.getMessage());

        } finally {
            if (timer != null) timer.cancel(false);
            batch.activeThreads.remove(self);
            Thread.interrupted();   // clear a late interrupt so it can't leak into the next task
        }
    }

    /** A buggy listener must never break the worker or the batch counter. */
    private static void safe(Runnable r) {
        try {
            r.run();
        } catch (RuntimeException e) {
            e.printStackTrace();
        }
    }

    private static ThreadFactory daemonFactory(String prefix) {
        AtomicInteger n = new AtomicInteger(1);
        return r -> {
            Thread t = new Thread(r, prefix + "-" + n.getAndIncrement());
            t.setDaemon(true);
            return t;
        };
    }
}