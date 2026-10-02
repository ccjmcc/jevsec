# Demo script (about 90 seconds)

1. Open the local dashboard and point out the Rules/Jev/Hybrid risk selector.
2. Use **Refresh** to show the synthetic ingestion summary, current reviews and Jev latency.
3. Open **Attack stories**. Expand a multi-stage synthetic session and follow each timestamp, risk step, rule hit, and evidence object.
4. Select the entity row. Compare the structured features, rules, Jev answers, and event timeline.
5. Submit **False Positive** on a known synthetic benign alert; show that feedback count increments and `/api/feedback` stores it locally.
6. Explain that model verdicts are advisory, the app runs in shadow mode, and no requests are blocked.

Do not claim live customer traffic, production effectiveness, or zero-day prevention. Benchmark values must be read from the checked-in generated report for the current run.
