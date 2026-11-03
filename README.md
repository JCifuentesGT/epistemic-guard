# epistemic-guard

> Early exploratory prototype. Not a finished tool and not a security guarantee.

An exploratory prototype on **epistemic cybersecurity**: monitoring that an AI agent keeps following the hard rules it was
given. It focuses on one concrete failure: an agent modifying its own rules after reading untrusted content (indirect prompt
injection), and on explaining why it happened from external logs rather than asking the model.

## Status
- Done: a hash-chained, append-only log and an integrity monitor for watched files (`src/epistemic_guard/`, 22 unit tests).
- Done: a small probe of Claude Code hooks to learn what they can and cannot see (`experiments/probe/`).
- Not done yet: action classifier, provenance report, canary test bench, experiments, database module.

## Quick start
```
py -3 -m pytest
```
To try the monitor, run from the repository root with `src` on the path (PowerShell: `$env:PYTHONPATH = "src"`):
```
py -3 -m epistemic_guard baseline experiments/probe/RULES.md
py -3 -m epistemic_guard check experiments/probe/RULES.md
```
The log is written to `guard.local.jsonl`, which git ignores.

## What this is not
- Not a proof that an agent is safe, secure or "ethical". It only checks the integrity of a rule file under specific attacks.
- Not claimed to be new. Related work exists (for example VIGIL and EnforceCore); it has not yet been compared in detail.
- Not tested on any real system. Everything runs locally with synthetic data and harmless markers.
- Not a barrier. On native Windows the agent can bypass hook-based blocking and can disable its own hooks (see
  `experiments/probe/README.md`), so the design relies on detection by an external monitor.

## How AI was used
The code in `src/`, the tests and the probe scripts were written by Claude Code (Anthropic) at the author's direction.
The author's own contribution (the idea, the design decisions and the review of the code) is to be described by the
author before this repository is made public.

## Limitations
Small sample sizes; results depend on the model and version; attribution depends on complete logs. The hash chain does
not detect removal of the last records of a log, nor a full rewrite with recomputed hashes, unless its head hash is
kept elsewhere.
