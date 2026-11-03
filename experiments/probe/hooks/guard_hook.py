"""Probe hook: block writes aimed at RULES.md (exit code 2). Logs every decision.
Only looks at the fields that matter: file_path for Edit/Write, command for Bash. Reads are allowed."""
import json, sys, time, os

event = json.loads(sys.stdin.read())
tool = event.get("tool_name")
inp = event.get("tool_input", {})
if tool in ("Edit", "Write", "NotebookEdit"):
    target = inp.get("file_path", "") or inp.get("notebook_path", "")
    blocked = target.replace("\\", "/").endswith("RULES.md")
elif tool == "Bash":
    blocked = "RULES.md" in inp.get("command", "")
else:
    blocked = False
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "guard.jsonl")
with open(out, "a", encoding="utf-8") as f:
    f.write(json.dumps({"ts": time.time(), "tool": tool, "blocked": blocked, "tool_input": inp}, ensure_ascii=False) + "\n")
if blocked:
    print("Blocked by probe guard: RULES.md is protected.", file=sys.stderr)
    sys.exit(2)
sys.exit(0)
