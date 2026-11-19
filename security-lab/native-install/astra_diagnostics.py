"""Narrow diagnostic collection for one receipt-only copied-claims process."""
from __future__ import annotations
import datetime
import json
from pathlib import Path
import re
import subprocess
import time


def crash_summary(text: str, pid: int) -> dict[str, object] | None:
    decoder = json.JSONDecoder()
    remaining = text.lstrip()
    while remaining:
        item, end = decoder.raw_decode(remaining)
        remaining = remaining[end:].lstrip()
        if not isinstance(item, dict):
            continue
        path = item.get("procPath", "")
        if item.get("pid") == pid and isinstance(path, str) and path.endswith(
            "/adhoc_copied_claims.app/Contents/MacOS/ReceiptLab"
        ):
            return {key: item[key] for key in ("pid", "procPath", "captureTime", "termination",
                                              "exception", "codeSigningID", "codeSigningTeamID") if key in item}
    return None


def capture_attempt(executable: str, group: str, account: str) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    started = time.time()
    process = subprocess.Popen([executable, "denied", group, account], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        stdout, stderr = process.communicate()
    details: dict[str, object] = {"pid": process.pid, "executable": executable,
        "started_at": datetime.datetime.fromtimestamp(started, datetime.timezone.utc).isoformat(),
        "runner_killed_after_timeout": timed_out}
    # Give crash reporting and unified logging a brief chance to persist this event.
    time.sleep(2)
    token = Path(executable).parents[3].name
    if not re.fullmatch(r"sudo-relay-astra-check-[A-Za-z0-9_-]+", token):
        raise ValueError("Unexpected test directory; refusing a broader log query")
    predicate = (
        '(process == "amfid" OR process == "kernel" OR process == "taskgated" '
        'OR process == "taskgated-helper" OR process == "syspolicyd") AND '
        f'(eventMessage CONTAINS "{token}" OR eventMessage CONTAINS "adhoc_copied_claims" '
        f'OR eventMessage MATCHES ".*\\\\b{process.pid}\\\\b.*")'
    )
    details["log_predicate"] = predicate
    # No sudo or permission changes. Missing/private logs remain missing evidence.
    try:
        logs = subprocess.run(["/usr/bin/log", "show", "--last", "2m", "--style", "ndjson",
                               "--info", "--debug", "--predicate", predicate],
                              capture_output=True, text=True, timeout=20)
        details["signing_logs"] = {"returncode": logs.returncode,
            "stdout": logs.stdout[:65536], "stderr": logs.stderr[:4096],
            "truncated": len(logs.stdout) > 65536 or len(logs.stderr) > 4096}
    except (OSError, subprocess.TimeoutExpired) as error:
        details["signing_logs_error"] = str(error)
    reports: list[dict[str, object]] = []
    details["crash_reports"] = reports
    directory = Path.home() / "Library/Logs/DiagnosticReports"
    try:
        candidates = sorted(directory.glob("ReceiptLab*.ips"), key=lambda path: path.stat().st_mtime, reverse=True)
        for path in candidates[:10]:
            stat = path.stat()
            if stat.st_mtime < started - 2 or stat.st_size > 2_000_000:
                continue
            try:
                summary = crash_summary(path.read_text(), process.pid)
            except (OSError, ValueError) as error:
                details["crash_parse_error"] = str(error)
                continue
            if summary is not None:
                reports.append(summary)
    except OSError as error:
        details["crash_collection_error"] = str(error)
    return subprocess.CompletedProcess([executable], process.returncode, stdout, stderr), details
