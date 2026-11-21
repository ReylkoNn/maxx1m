"""Offline subprocess bridge for a fixed synthetic self-test, not a messaging API.

No user data, production keys or network input must be passed to this prototype.
"""
import json
import subprocess
import sys
from pathlib import Path


def run_probe(timeout=20):
    path = Path(__file__).resolve().with_name("probe.mjs")
    result = subprocess.run(
        ["node", "--experimental-wasm-modules", str(path)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=timeout, check=True,
    )
    report = json.loads(result.stdout)
    expected = {"experimental", "usable_for_production", "two_member_exchange", "replay_rejected",
                "third_member_commit_rejected", "tampering_rejected", "original_rejected_after_tamper",
                "remove_exposed", "group_persistence_exposed"}
    if not isinstance(report, dict) or set(report) != expected or any(type(v) is not bool for v in report.values()):
        raise ValueError("Unexpected OpenMLS probe output")
    if report["experimental"] is not True or report["usable_for_production"] is not False:
        raise ValueError("Invalid OpenMLS probe safety flag")
    return report


if __name__ == "__main__":
    try:
        print(json.dumps(run_probe(), indent=2))
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"OpenMLS probe failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
