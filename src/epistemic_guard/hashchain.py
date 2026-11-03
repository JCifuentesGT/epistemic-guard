"""Append-only JSONL log with a hash chain.

Each line is one record:

    {"seq": 0, "ts": 1700000000.0, "prev_hash": "000...0", "event": {...}, "hash": "ab12..."}

`hash` is the SHA-256 of the record itself (without the `hash` field), and `prev_hash` is the `hash` of the
previous line. So changing, deleting or reordering any line in the middle of the file breaks the chain, and
`verify` reports where.

What this does NOT detect (on purpose, stated here so nobody over-trusts it):
  * Removing lines from the END of the file: the shorter chain is still valid.
  * Someone who rewrites the whole file and recomputes every hash.
To narrow both gaps, write down the `head` hash that `verify` prints and compare it later, or copy the log
somewhere the agent cannot write. This prototype does not do that automatically.
"""

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path

# prev_hash of the very first record: there is no previous line.
GENESIS = "0" * 64


class ChainError(Exception):
    """The log exists but is not a valid chain, so we refuse to append to it."""


@dataclass
class VerifyResult:
    ok: bool
    count: int          # number of records that were checked
    head: str           # hash of the last valid record (GENESIS if the log is empty)
    error: str = ""     # why the chain is broken, empty when ok


def _digest(record_without_hash: dict) -> str:
    """SHA-256 over a canonical JSON form (sorted keys, no spaces), so the same data always gives the same hash."""
    canonical = json.dumps(record_without_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        return [line for line in f.read().splitlines() if line.strip()]


def verify(log_path) -> VerifyResult:
    """Walk the whole log and check every link. A missing or empty log is a valid empty chain."""
    prev = GENESIS
    lines = _lines(Path(log_path))
    for index, line in enumerate(lines):
        try:
            record = json.loads(line)
            claimed_hash = record.pop("hash")
        except (json.JSONDecodeError, KeyError, AttributeError):
            return VerifyResult(False, index, prev, f"record {index}: line is not a valid record")
        if record.get("seq") != index:
            return VerifyResult(False, index, prev, f"record {index}: wrong seq {record.get('seq')} (line removed or reordered?)")
        if record.get("prev_hash") != prev:
            return VerifyResult(False, index, prev, f"record {index}: prev_hash does not match the previous record")
        if _digest(record) != claimed_hash:
            return VerifyResult(False, index, prev, f"record {index}: content does not match its hash (edited?)")
        prev = claimed_hash
    return VerifyResult(True, len(lines), prev)


def read_records(log_path) -> list[dict]:
    """Return all records, oldest first. Call `verify` first if you need to trust them."""
    return [json.loads(line) for line in _lines(Path(log_path))]


def append(log_path, event: dict) -> dict:
    """Add one event to the end of the log and return the full record that was written."""
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    result = verify(path)
    if not result.ok:
        raise ChainError(f"refusing to append to a broken log: {result.error}")

    record = {
        "seq": result.count,
        "ts": time.time(),
        "prev_hash": result.head,
        "event": event,
    }
    record["hash"] = _digest(record)

    # "a" = append only; newline="\n" keeps the file identical on Windows and Linux.
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
    return record
