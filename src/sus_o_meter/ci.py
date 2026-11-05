"""Offline quality checks and aggregate CI reporting."""

import json
import platform
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from .reports import new_report, write_report

CHECK_NAMES = ("tests", "lint", "format", "dependencies", "build")
PYTHON_VERSIONS = ("3.11", "3.14")


def run_checks(output: Path) -> int:
    output.mkdir(parents=True, exist_ok=True)
    commands = {
        "tests": [sys.executable, "-m", "pytest", "-q", f"--junitxml={output / 'tests.xml'}"],
        "lint": [sys.executable, "-m", "ruff", "check", "."],
        "format": [sys.executable, "-m", "ruff", "format", "--check", "."],
        "dependencies": [sys.executable, "-m", "pip", "check"],
        "build": [sys.executable, "-m", "build"],
    }
    result = {"python": platform.python_version(), "checks": []}
    for name, command in commands.items():
        started = time.monotonic()
        try:
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            code = completed.returncode
            log = completed.stdout + "\n" + completed.stderr
        except OSError:
            code, log = 2, "Could not launch the quality check"
        (output / f"{name}.log").write_text(log, encoding="utf-8")
        result["checks"].append(
            {
                "name": name,
                "status": "passed" if code == 0 else "failed",
                "exit_code": code,
                "seconds": round(time.monotonic() - started, 3),
            }
        )
        (output / "checks.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps({"check": name, "exit_code": code}), flush=True)
    return int(any(check["exit_code"] for check in result["checks"]))


def junit_counts(path: Path) -> dict[str, int]:
    data = path.read_bytes()
    if len(data) > 10_000_000 or b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise ValueError("Unsafe or oversized JUnit data")
    root = ET.fromstring(data)
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    if not suites:
        raise ValueError("Missing JUnit test suite")
    counts = {
        name: sum(int(suite.get(name, "0")) for suite in suites)
        for name in ("tests", "failures", "errors", "skipped")
    }
    if any(value < 0 for value in counts.values()):
        raise ValueError("Invalid JUnit counts")
    if counts["failures"] + counts["errors"] + counts["skipped"] > counts["tests"]:
        raise ValueError("Inconsistent JUnit counts")
    return counts


def ci_report(inputs: Path, output: Path, ci_result: str) -> int:
    report = new_report("CI")
    report["metadata"]["ci_job_result"] = ci_result
    totals = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
    valid = ci_result == "success"
    for version in PYTHON_VERSIONS:
        try:
            data = json.loads((inputs / version / "checks.json").read_text(encoding="utf-8"))
            checks = data["checks"]
            if len(checks) != len(CHECK_NAMES) or {check["name"] for check in checks} != set(
                CHECK_NAMES
            ):
                raise ValueError("Missing checks")
            for check in checks:
                valid = valid and check["status"] == "passed" and check["exit_code"] == 0
                report["checks"].append({"runtime": version, **check})
            counts = junit_counts(inputs / version / "tests.xml")
            valid = valid and counts["tests"] > 0 and not (counts["failures"] or counts["errors"])
            for name in totals:
                totals[name] += counts[name]
        except (OSError, ValueError, KeyError, TypeError, ET.ParseError):
            valid = False
            report["checks"].append(
                {"runtime": version, "name": "report completeness", "status": "missing or invalid"}
            )
    report["metrics"] = {
        "Test executions": totals["tests"],
        "Passed": totals["tests"] - totals["failures"] - totals["errors"] - totals["skipped"],
        "Failures": totals["failures"],
        "Errors": totals["errors"],
        "Skipped": totals["skipped"],
        "Python versions": len(PYTHON_VERSIONS),
    }
    report["status"] = "passed" if valid else "failed"
    report["message"] = (
        "All required quality checks passed. The scan gate may now open."
        if valid
        else "CI did not pass or its evidence is incomplete. Scanning is blocked."
    )
    write_report(report, output / report["id"], "ci-report")
    return 0 if valid else 1
