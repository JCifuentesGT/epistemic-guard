"""Probe hook: append the raw hook input (stdin JSON) to events.jsonl. Never blocks."""
import json, sys, time, os

raw = sys.stdin.read()
try:
    event = json.loads(raw)
except Exception:
    event = {"unparsed": raw}
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "events.jsonl")
with open(out, "a", encoding="utf-8") as f:
    f.write(json.dumps({"ts": time.time(), "event": event}, ensure_ascii=False) + "\n")
sys.exit(0)
