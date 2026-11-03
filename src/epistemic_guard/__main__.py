"""Command line for the integrity monitor.  Run from the repository root with:  py -3 -m epistemic_guard ...

  baseline FILE...            record the current hash of each file as the expected one
  check FILE...               one check; exit code 0 = all clean, 1 = something deviates
  watch FILE... [--interval]  check again and again, print only new alerts
  approve FILE --reason TEXT  accept the current content of FILE on purpose
  verify                      check that the log chain itself is intact
"""

import argparse
import sys
import time

from . import hashchain, monitor

DEFAULT_LOG = "guard.local.jsonl"   # *.local.jsonl is ignored by git


def _print_finding(f: dict) -> None:
    if f["kind"] == "log_tampered":
        print(f"[ALERT] the log is damaged: {f['detail']}")
    elif f["kind"] == "no_baseline":
        print(f"[WARN] no baseline for {f['path']}")
    else:
        print(f"[ALERT] {f['kind']}: {f['path']}  expected {f['expected'][:12]}  observed {(f['observed'] or 'none')[:12]}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="epistemic_guard", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log", default=DEFAULT_LOG, help=f"path of the hash-chained log (default {DEFAULT_LOG})")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("baseline", "check", "watch"):
        p = sub.add_parser(name)
        p.add_argument("files", nargs="+")
        if name == "watch":
            p.add_argument("--interval", type=float, default=2.0, help="seconds between checks")
    p = sub.add_parser("approve")
    p.add_argument("file")
    p.add_argument("--reason", required=True)
    sub.add_parser("verify")

    args = parser.parse_args(argv)

    if args.command == "baseline":
        monitor.baseline(args.files, args.log)
        print(f"baseline recorded for {len(args.files)} file(s)")
        return 0

    if args.command == "approve":
        monitor.approve(args.file, args.log, args.reason)
        print("change approved and logged")
        return 0

    if args.command == "verify":
        result = hashchain.verify(args.log)
        print(f"{'OK' if result.ok else 'BROKEN'}: {result.count} record(s), head {result.head}")
        if not result.ok:
            print(result.error)
        return 0 if result.ok else 1

    if args.command == "check":
        findings = monitor.check(args.files, args.log)
        for f in findings:
            _print_finding(f)
        if not findings:
            print("all clean")
        return 1 if findings else 0

    # watch: loop until Ctrl+C, print only deviations that are new
    print(f"watching {len(args.files)} file(s) every {args.interval}s (Ctrl+C to stop)")
    already_reported = set()    # a damaged log is never "logged", so remember it here to avoid printing it every cycle
    try:
        while True:
            for f in monitor.check(args.files, args.log):
                if f["new"] and (f["kind"], f.get("detail")) not in already_reported:
                    _print_finding(f)
                    if f["kind"] == "log_tampered":
                        already_reported.add((f["kind"], f.get("detail")))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
