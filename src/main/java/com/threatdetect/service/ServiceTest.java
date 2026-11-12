package com.threatdetect.service;

import com.threatdetect.model.AnalysisResult;
import com.threatdetect.model.InputItem;
import com.threatdetect.model.InputType;
import com.threatdetect.rules.RuleBasedEvaluator;

import java.util.List;
import java.util.concurrent.CountDownLatch;

public class ServiceTest {

    public static void main(String[] args) throws Exception {
        System.out.println("=== Run 1: 8 items, 4 workers, 800 ms of work each ===");
        run(800, 4, 5000);

        System.out.println("\n=== Run 2: timeout (3000 ms of work, 1000 ms limit) ===");
        run(3000, 4, 1000);
    }

    private static void run(long latencyMs, int poolSize, long timeoutMs) throws InterruptedException {
        ThreatAnalysisService service =
                new ThreatAnalysisService(new RuleBasedEvaluator(latencyMs), poolSize, timeoutMs);

        List<InputItem> items = List.of(
                new InputItem(InputType.URL, "https://www.google.com"),
                new InputItem(InputType.URL, "http://paypal.secure-login.xyz/verify/account"),
                new InputItem(InputType.URL, "http://192.168.1.1/login"),
                new InputItem(InputType.URL, "not a url"),
                new InputItem(InputType.MESSAGE, "URGENT! Send your password immediately"),
                new InputItem(InputType.MESSAGE, "Hi, are we meeting tomorrow?"),
                new InputItem(InputType.URL, "https://github.com"),
                new InputItem(InputType.MESSAGE, "")
        );

        CountDownLatch done = new CountDownLatch(1);
        long start = System.currentTimeMillis();

        service.submit(items, new AnalysisListener() {
            @Override
            public void onStarted(InputItem item) {
                log("item " + item.getId() + " STARTED");
            }

            @Override
            public void onProgress(InputItem item, int percent) {
                log("item " + item.getId() + " progress " + percent + "%");
            }

            @Override
            public void onCompleted(InputItem item, AnalysisResult r) {
                log("item " + item.getId() + " DONE -> " + r.status() + " / " + r.riskLevel() + " " + r.reasons());
            }

            @Override
            public void onBatchFinished() {
                done.countDown();
            }
        });

        done.await();
        long elapsed = System.currentTimeMillis() - start;
        System.out.println(">>> Batch finished in " + elapsed + " ms");
        service.shutdown();
    }

    private static void log(String msg) {
        System.out.printf("[%-18s] %s%n", Thread.currentThread().getName(), msg);
    }
}