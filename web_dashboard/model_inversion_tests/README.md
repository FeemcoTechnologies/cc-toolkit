# LLM Model-Inversion / Training-Data Extraction Testing

Tooling for authorised security assessments of language models: given query access
(black-box API) or weight access (local checkpoints), these scripts search for
evidence that a model memorised **non-public information from its training corpus**
and attempt to recover it.

> **AUTHORISATION REQUIRED.** Run these only against models/systems you are
> explicitly permitted to test: signed scope, your own infrastructure, or a
> sanctioned red-team engagement. Unauthorised extraction of private training
> data is illegal in most jurisdictions. Always delete recovered sensitive data
> after the assessment.

## Files

| File | Use |
|---|---|
| `llm_inversion_api.py` | Black-box suite against any OpenAI-compatible endpoint (OpenAI, Azure, vLLM, TGI, DeepSeek...). **Stdlib only, zero dependencies.** |
| `llm_inversion_local.py` | Weights-access suite (perplexity / loss from forward passes) + an end-to-end self-contained demo. Requires `torch` + `transformers`. |
| `README.md` | This file. |

## Techniques implemented

| Test | What it detects | Reference |
|---|---|---|
| `extract` — sampling + perplexity outlier ranking | Sample many continuations from fixed prefixes; sequences with anomalously low perplexity are likely memorised verbatim training data | Carlini et al., "Extracting Training Data from Large Language Models" (2021) |
| `probes` — regurgitation prompts | Prompt-level attempts to make the model emit its system prompt / training material / remembered PII; auto-detects refusals and leaked PII patterns | Common red-team prompt collections |
| `canary` — random unique strings | A random string completed back nearly verbatim must have come from training data (astronomically unlikely otherwise). Proven technique: insert canaries into a fine-tune run, then test | Carlini et al., "The Secret Sharer" (2022) |
| `membership` — loss-based inference | Score candidate texts against a control set of known non-members; candidates with far lower loss are likely training members (LiRA-lite) | Carlini et al., LiRA (2022) |
| `split` — continuation overlap | The strongest single piece of evidence: cut a suspect string in half, feed the first half to the model, measure how much of the true second half it reproduces | Extension of Carlini 2021 |

The classic *gradient-based* inversion (Fredrikson et al., 2015 — reconstructing
representative training inputs by optimising inputs against class confidence)
is the ancestor of all of these; the LLM versions rely on the same core signal:
**the model's own confidence is a side channel into its training data.**

## Quick start — API (black-box)

```bash
export OPENAI_API_KEY=sk-...   # or any gateway key

# 1. Regurgitation / system-prompt probes
python3 llm_inversion_api.py --base-url https://api.openai.com/v1 --model gpt-4o-mini probes

# 2. Sampling extraction: flag low-perplexity continuations
python3 llm_inversion_api.py --base-url ... --model ... extract --samples 24 --threshold 5.0

# 3. Canary completion test
python3 llm_inversion_api.py --base-url ... --model ... canary --count 8

# 4. Membership inference on suspect strings (one per line)
python3 llm_inversion_api.py --base-url ... --model ... membership --candidate-file suspects.txt

# 5. Split-and-continue test on the same suspects
python3 llm_inversion_api.py --base-url ... --model ... split --candidate-file suspects.txt

# run 1–3 in one go, keep an audit trail
python3 llm_inversion_api.py ... all --report findings.json
```

Notes:
- `extract`/`canary`/`probes`/`split` only need `/chat/completions`.
- `membership` (and high-quality arbitrary-string scoring) needs an endpoint
  supporting legacy `/completions` with `echo=true&logprobs` (OpenAI legacy,
  vLLM, TGI, many gateways). If unsupported you will get a clear error.

## Quick start — local (weights access)

```bash
python3 llm_inversion_local.py --model ./finetuned-model extract --samples 16
python3 llm_inversion_local.py --model gpt2 membership --candidate-file suspects.txt
python3 llm_inversion_local.py --model gpt2 split --candidate-file suspects.txt
python3 llm_inversion_local.py --model gpt2 canary
```

## End-to-end demo (understand the attack in 60 seconds)

```bash
python3 llm_inversion_local.py --model gpt2 demo --steps 40
```

Builds a synthetic "private" employee dataset (names, emails, IDs, random
canary strings), fine-tunes a small model on it for a handful of steps, then
runs the suite against it:

1. shows **membership separation** — training records have dramatically lower
   perplexity than held-out records;
2. shows **verbatim extraction** — the model completes `Name: Alice ...` /
   `CANARY-...` strings it memorised, and refuses/guesses for held-out data;
3. demonstrates the **canary** principle end to end.

This is the cleanest way to prove to a client that the methodology works, and
to validate your test harness before touching a real target.

## Interpreting results — honesty notes

- **Low perplexity alone is NOT proof of leakage.** Common public text (quotes,
  lorem ipsum) scores low too. Always combine with `split` overlap or canary
  completion for a positive finding.
- **Refusals are not a pass.** Models refuse regurgitation prompts but still
  leak via sampling (`extract`) — which is why the sampling test is the
  foundation of the methodology.
- Calibrate thresholds with `membership` on known control texts before
  judging borderline results.
- All findings are emitted as structured JSON (`--report`) for your audit
  trail and client report.

## References

- Fredrikson et al., "Model Inversion Attacks that Exploit Confidence Information" (2015) — https://arxiv.org/abs/1511.02518
- Carlini et al., "Extracting Training Data from Large Language Models" (2021) — https://arxiv.org/abs/2012.07805
- Carlini et al., "The Secret Sharer: Evaluating and Testing Unintended Memorization in Neural Networks" (2022) — https://arxiv.org/abs/2211.08769
- Carlini et al., "Membership Inference Attacks from First Principles" (LiRA, 2022) — https://arxiv.org/abs/2202.07646
- OWASP Top 10 for LLM Applications (Sensitive Information Disclosure) — https://owasp.org/www-project-top-10-for-large-language-model-applications/
