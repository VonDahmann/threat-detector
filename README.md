# Threat Detector

A multi-threaded desktop application (Java 21 + JavaFX) that evaluates suspicious **URLs** and **text messages** (email/SMS) and assigns each one a risk level. Inputs can be entered one by one or loaded in bulk from a CSV file, and are analysed concurrently with per-item progress.

Course mini-project: *Concurrency Programming*, Université Abdelhamid Mehri – Constantine 2 (2026-2027). Status: Sprint 1 (UI and functional backend foundations).

## Features

- Add a single URL or message (type is auto-detected, or chosen manually).
- Load a CSV batch file (file chooser, parsed in the background).
- Concurrent analysis on a fixed thread pool, with a progress bar per item and an overall progress bar.
- Risk levels **Low / Medium / High** from a local rule engine, plus a score and the list of reasons.
- Cancel a running batch.
- Robust error handling: nothing crashes on bad input, and **an item that could not be verified is never reported as safe**.

## Requirements

- JDK 21
- Maven 3.8+
- Internet access the first time (Maven downloads JavaFX 21)

## Run

```
mvn javafx:run
```

If you changed code and something looks stale, use `mvn clean javafx:run`.
(Running `App` directly from the IDE may fail with "JavaFX runtime components are missing"; use the Maven command.)

## How to use

1. Type or paste a URL/message and press **Enter** or **Add**, and/or click **Load CSV…**.
2. Click **Analyze**. Several rows run at the same time, each with its own progress bar.
3. Click a row to see the full input and the reasons behind its result.
4. **Cancel** stops the batch; unfinished items become *Not verified*.

## CSV format

Two columns (`type,content`) or a single column (type auto-detected). A header row is optional.

```
type,content
URL,https://www.google.com
MESSAGE,"URGENT, send your password immediately"
SMS,Hi are we meeting tomorrow?
```

- Accepted types: `URL`, `MESSAGE`, `SMS`, `EMAIL`.
- Text containing commas or line breaks must be in double quotes (`""` for a literal quote).
- UTF-8 encoding, `.csv` or `.txt` extension, max 5 MB and 5000 rows.

## Detection (Option A: rule-based)

Each triggered rule adds points (total capped at 100): **0-24 Low, 25-49 Medium, 50+ High**.

- **URL rules:** HTTP instead of HTTPS, IP address as host, `@` in the URL, excessive subdomains, brand names in unofficial domains, suspicious TLDs, URL shorteners, punycode, many hyphens, non-standard port, very long URL, sensitive path keywords.
- **Message rules:** urgency language, requests for credentials/codes, prize bait, links (and suspicious links), mostly uppercase text, excessive exclamation marks.

"Low" means that no indicator was found by the local rules. It does not guarantee safety.

## Error handling

| Situation | Result |
|---|---|
| Empty input | Message in the status bar, nothing added |
| Malformed URL / empty message | Row status **Error** with the reason |
| Missing, empty, unreadable, oversized or non-UTF-8 CSV file | Clear message, no crash |
| Invalid CSV rows (unknown type, wrong column count, empty content, unterminated quote) | Row skipped and listed in a warning dialog; valid rows are still loaded |
| Timeout, cancellation or unexpected exception during analysis | Row status **Not verified** (never Safe) |

## Project structure

```
src/main/java/com/threatdetect/
├── App.java                      application entry point, wiring
├── model/                        InputItem, InputType, AnalysisResult, Status, RiskLevel, InvalidInputException
├── rules/                        UrlRules, MessageRules, RiskScorer, RuleHit, RuleBasedEvaluator
├── service/                      ThreatEvaluator, ThreatAnalysisService (thread pool, timeouts, cancel),
│                                 AnalysisListener, ProgressReporter, CsvParserService, InputFactory
└── ui/                           MainView, ResultRow (JavaFX only)
```

`model`, `rules` and `service` contain no JavaFX code. The UI talks to the backend only through `ThreatAnalysisService` and `AnalysisListener`.

## Configuration

In `App.java`:

| Constant | Meaning |
|---|---|
| `POOL_SIZE` | number of worker threads (default 4) |
| `TIMEOUT_MS` | per-item timeout (default 10000) |
| `DEMO_LATENCY_MS` | artificial delay so progress bars are visible; **set to 0 for real use** |