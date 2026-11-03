"""Integrity monitor: watch files (the rule file, settings) and log any deviation to the hash-chained log.

The monitor runs as its own process, outside the agent. The log is the source of truth for "what the file was
supposed to be" (baseline or approved change) and "what the monitor has seen since".

Event types written to the log:
  baseline         first recorded hash of a file
  approved_change  the user approved a new hash on purpose (with a reason)
  alert            the file differs from the expected hash (kind: modified | missing)
  restored         the file is back to the expected hash after an alert
"""

import hashlib
from pathlib import Path

from . import hashchain


def _key(path) -> str:
    """One canonical spelling per file, so 'RULES.md' and an absolute path are the same entry."""
    return str(Path(path).resolve())


def sha256_file(path) -> str | None:
    """SHA-256 of the file contents, or None if the file does not exist."""
    p = Path(path)
    if not p.is_file():
        return None
    digest = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expected_and_seen(records: list[dict]) -> tuple[dict, dict]:
    """Replay the log. expected = hash the file SHOULD have. seen = last state already logged (avoids duplicate alerts)."""
    expected: dict[str, str] = {}
    seen: dict[str, str | None] = {}
    for record in records:
        event = record["event"]
        kind = event.get("type")
        path = event.get("path")
        if kind in ("baseline", "approved_change"):
            expected[path] = event["sha256"]
            seen[path] = event["sha256"]
        elif kind == "restored":
            seen[path] = event["sha256"]
        elif kind == "alert":
            seen[path] = event["observed"]
    return expected, seen


def baseline(paths, log_path) -> None:
    """Record the current hash of each file as the expected one. Refuses to overwrite an existing baseline."""
    expected, _ = _expected_and_seen(hashchain.read_records(log_path))
    for path in paths:
        key = _key(path)
        if key in expected:
            raise ValueError(f"{key} already has a baseline; use approve() to accept a change on purpose")
        digest = sha256_file(path)
        if digest is None:
            raise FileNotFoundError(f"cannot baseline a file that does not exist: {key}")
        hashchain.append(log_path, {"type": "baseline", "path": key, "sha256": digest})


def approve(path, log_path, reason: str) -> None:
    """The user accepts the file as it is now. A reason is required so the log explains why the rule changed."""
    if not reason.strip():
        raise ValueError("approving a change requires a reason")
    key = _key(path)
    expected, _ = _expected_and_seen(hashchain.read_records(log_path))
    if key not in expected:
        raise ValueError(f"{key} has no baseline yet")
    digest = sha256_file(path)
    if digest is None:
        raise FileNotFoundError(f"cannot approve a file that does not exist: {key}")
    hashchain.append(log_path, {
        "type": "approved_change", "path": key, "sha256": digest,
        "previous": expected[key], "reason": reason,
    })


def check(paths, log_path) -> list[dict]:
    """Compare every watched file with its expected hash. Returns one finding per current problem.

    Each finding has: kind (modified | missing | no_baseline | log_tampered), path, expected, observed,
    new (True the first time this exact deviation is seen, and logged as an alert).
    """
    verdict = hashchain.verify(log_path)
    if not verdict.ok:
        # The log itself was damaged. We cannot append to it, so this finding is only returned, not logged.
        return [{"kind": "log_tampered", "path": str(log_path), "detail": verdict.error, "new": True}]

    expected, seen = _expected_and_seen(hashchain.read_records(log_path))
    findings = []
    for path in paths:
        key = _key(path)
        if key not in expected:
            findings.append({"kind": "no_baseline", "path": key, "new": False})
            continue

        observed = sha256_file(path)
        if observed == expected[key]:
            if seen.get(key) != expected[key]:      # it was altered before and is back to normal
                hashchain.append(log_path, {"type": "restored", "path": key, "sha256": observed})
            continue

        kind = "missing" if observed is None else "modified"
        is_new = observed != seen.get(key)           # same bad state as last time: report it, but do not log it twice
        if is_new:
            hashchain.append(log_path, {
                "type": "alert", "kind": kind, "path": key,
                "expected": expected[key], "observed": observed,
            })
        findings.append({"kind": kind, "path": key, "expected": expected[key], "observed": observed, "new": is_new})
    return findings
