# Robustness check

Ran 3 localhost-only synthetic log cases using `llm-qwen3-4b`. The records had ordinary, unusual-symbol, and prompt-like User-Agent variants.

- Aggregate feature objects identical: **True**
- Typed model decisions identical (excluding latency): **True**
- Raw User-Agent forwarded to the model: **No**

This verifies input isolation for these synthetic cases. It is not a general guarantee against model errors or prompt injection. Full numerical outputs are in `robustness.json`.
