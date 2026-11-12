# Multi-Threaded Threat Detection Desktop App: Sprint N°01 Report

## 1. Overview

The application evaluates URLs and text messages for security threats. Sprint 1 delivers the JavaFX user interface and a decoupled backend that loads inputs (single or CSV), evaluates them concurrently with a local rule engine (Option A), and shows risk levels, statuses and per-item progress.

**Technology:** Java 21, JavaFX 21, Maven. Concurrency uses `java.util.concurrent`.

## 2. Architecture

The code is split into four packages with one-way dependencies:

```
            +--------------------------------------------+
            |  ui   (JavaFX)                             |
            |  MainView, ResultRow                       |
            +----------------------+---------------------+
                                   | submit(items, listener)
                                   | callbacks (AnalysisListener)
                                   v
            +--------------------------------------------+
            |  service                                   |
            |  ThreatAnalysisService  (thread pool,      |
            |    timeouts, cancel, batch completion)     |
            |  CsvParserService, InputFactory            |
            |  interfaces: ThreatEvaluator,              |
            |    AnalysisListener, ProgressReporter      |
            +----------------------+---------------------+
                                   | evaluate(item, progress)
                                   v
            +--------------------------------------------+
            |  rules                                     |
            |  RuleBasedEvaluator -> UrlRules,           |
            |    MessageRules, RiskScorer, RuleHit       |
            +--------------------------------------------+

            model: InputItem, AnalysisResult, Status, RiskLevel, ...
            (used by all layers, depends on nothing)
```

Key design decisions:

- **Separation of UI and logic.** Only `ui` imports JavaFX. `service` and `rules` can be tested from a plain `main` method (done with `ServiceTest` and `CsvTest`).
- **Strategy pattern.** `ThreatAnalysisService` depends on the `ThreatEvaluator` interface, not on the rule engine. An online-API evaluator (Option B) or an AI evaluator can be added without changing the service or the UI.
- **Observer pattern.** The service reports events (`onStarted`, `onProgress`, `onCompleted`, `onBatchFinished`) through `AnalysisListener`, so it never references UI classes.
- **Immutable data.** `AnalysisResult` is a Java record, so it can be passed between threads without synchronisation.
- **Safe defaults.** Results that cannot be produced become `NOT_VERIFIED` or `ERROR`, never `LOW`/safe.

## 3. Concurrency design

### 3.1 Threads and their roles

| Thread(s) | Created by | Role |
|---|---|---|
| JavaFX Application Thread | JavaFX | Renders the UI and is the only thread that touches UI objects |
| `analysis-worker-1..N` | fixed thread pool (`Executors.newFixedThreadPool`) | Run one evaluation task each |
| `analysis-watchdog` | `Executors.newSingleThreadScheduledExecutor` | Fires timeouts |
| `csv-loader` | `Task` on a daemon thread | Reads and parses a CSV file without freezing the UI |

All backend threads are daemon threads, and `Application.stop()` calls `ThreatAnalysisService.shutdown()`, so closing the window never leaves the JVM running.

### 3.2 Life of a batch

1. The user clicks **Analyze**. `MainView` calls `service.submit(items, listener)` on the UI thread. The call **returns immediately** (non-blocking) with a `BatchHandle`.
2. `submit` creates **one task per item** and hands it to the pool. With 4 workers, 4 items run in parallel and the rest wait in the pool's queue.
3. A worker runs `process(item)`:
    - checks whether the batch was cancelled;
    - notifies `onStarted`;
    - schedules a **timeout** on the watchdog (the clock starts when the item starts running, not while it is queued);
    - calls `evaluator.evaluate(item, progressReporter)`, which reports progress through `onProgress`;
    - cancels the timeout, then notifies `onCompleted`.
4. Each listener callback runs on a worker thread, so the UI implementation (`FxListener`) wraps every update in `Platform.runLater(...)`. UI state (`rowById`, table rows, counters) is therefore only ever modified by one thread and needs no locks.
5. A shared `AtomicInteger remaining` counts down as items finish. The worker that reaches 0 calls `onBatchFinished`, so exactly one thread announces the end of the batch, with no polling.

### 3.3 Timeouts

The watchdog schedules `self.interrupt()` for the worker thread after `TIMEOUT_MS`. The evaluator is written to be **interruptible** (it throws `InterruptedException`), so the worker stops and the result becomes `NOT_VERIFIED ("Timed out after N ms")`. A `timedOut` `AtomicBoolean` distinguishes a timeout from a user cancellation. In the `finally` block the timer is cancelled and `Thread.interrupted()` clears any late interrupt so it cannot leak into the next task run by the same pooled thread.

### 3.4 Cancellation

`BatchHandle.cancel()` sets an `AtomicBoolean` and interrupts every thread in `activeThreads` (a `ConcurrentHashMap.newKeySet()`). Running items stop at their next interruption point, and queued items check the flag as soon as they start and return `NOT_VERIFIED ("Cancelled by user")`. This is cooperative cancellation: the code never kills threads.

### 3.5 Thread-safety summary

| Shared state | Protection |
|---|---|
| Item ID counter (`InputItem`) | `AtomicInteger` |
| Batch remaining counter | `AtomicInteger` (`decrementAndGet`) |
| Cancelled / timed-out flags | `AtomicBoolean` |
| Set of running threads | `ConcurrentHashMap.newKeySet()` |
| Results passed to the UI | immutable record |
| UI model (table rows, map, counters) | confined to the JavaFX thread (`Platform.runLater`) |

### 3.6 Failure isolation

Each task is wrapped so that an exception in one item cannot affect another: `evaluateSafely` catches `InterruptedException` and any other `Exception` and converts it to a `NOT_VERIFIED` result, and listener callbacks run through `safe(...)` so a buggy listener cannot break the batch counter.

### 3.7 Measured behaviour

Test run with 8 items, 4 workers and 800 ms of simulated work per item: the batch finished in **1640 ms** (a sequential run would take about 6400 ms). With a 1000 ms timeout and 3000 ms of work, all 8 items ended as `NOT_VERIFIED` after **2003 ms** (2 rounds of 4) instead of 24 s.

## 4. Detection logic (Option A)

Each rule that fires returns a `RuleHit(points, reason)`. `RiskScorer` sums them (capped at 100) and maps the total to a level: **0-24 Low, 25-49 Medium, 50-100 High**.

- **URLs:** HTTP vs HTTPS, IP hostname, `@` user-info trick, excessive subdomains, brand imitation in unofficial domains, suspicious TLD, URL shortener, punycode, many hyphens, non-standard port, very long URL, sensitive path keywords.
- **Messages:** urgency language, credential/code requests, prize bait, embedded links (with an extra penalty when a link is itself suspicious), uppercase shouting, excessive exclamation marks.

"Low" means that no indicators were found by the local rules, not that the item is proven safe.

## 5. Error handling

- `InvalidInputException` is used for expected problems (empty or malformed input) and becomes an `ERROR` row with a readable reason.
- Unexpected exceptions, timeouts and cancellations become `NOT_VERIFIED`.
- `CsvParserService` separates **file-level** problems (missing, empty, wrong type, too large, invalid UTF-8; thrown as `InvalidInputException`) from **row-level** problems (collected in `CsvParseResult.errors()`), so one bad row never blocks the rest.

## 6. Sprint 1 requirements mapping

| # | Requirement | Where it is implemented |
|---|---|---|
| 1 | GUI built with a suitable framework | JavaFX: `App`, `ui/MainView`, `ui/ResultRow` |
| 2 | Load single inputs or CSV batch files | `MainView.onAdd`, `onBrowse` / `loadCsvAsync`; `InputFactory.single`; `CsvParserService.parse` |
| 3 | Modular architecture, rules and parsing in backend service classes | `rules/*`, `service/*` have no JavaFX imports; `ThreatEvaluator` and `AnalysisListener` interfaces separate layers |
| 4 | Display inputs, results, risk levels and status indicators | `MainView` `TableView` (Type, Input, Status, Risk, Score, Summary), colour-coded cells, details panel, summary counters |
| 5 | Progress indicator for each evaluation | `ProgressReporter` → `AnalysisListener.onProgress` → `ProgressBarTableCell`; overall `ProgressBar` |
| 6 | Responsive, user-friendly interface | Thread pool for analysis, `Task` for CSV loading, `Platform.runLater` for UI updates, Cancel button, status messages |
| 7 | Input and error handling without crashing | `InputFactory`, `UrlRules`/`MessageRules` (`InvalidInputException`), `CsvParserService` (file and row errors), `ThreatAnalysisService.evaluateSafely` and `safe()`. Unavailable-API responses are covered by the Option B evaluator |
| 8 | At least one detection approach | Option A: `UrlRules`, `MessageRules`, `RiskScorer`, `RuleBasedEvaluator` |

## 7. Testing

- `ServiceTest`: parallel execution, progress events, failure isolation, timeouts.
- `CsvTest`: valid rows, invalid rows (with line numbers), quoted/multi-line fields, auto-detection, and five file-level failures.
- Manual UI checklist: empty input, single add, CSV load, concurrent analysis while resizing the window, cancel, bad files.

## 8. Limitations and future work

- Interruption only stops code that reaches an interruption point (sleep, blocking I/O that supports it). A network evaluator therefore also needs its own HTTP connect and request timeouts.
- After a cancel, items that were marked *Not verified* are not re-queued automatically; they have to be added again.
- Planned for later sprints: an online threat-intelligence evaluator (HTTP 429 handling, missing key, invalid responses) and an optional AI-based secondary assessment, both behind the existing `ThreatEvaluator` interface.