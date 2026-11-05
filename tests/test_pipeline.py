import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

from sus_o_meter import ci, pipeline
from sus_o_meter.engines import EngineResult, Verdict
from sus_o_meter.reports import new_report, render_html, render_summary, write_report


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    project = root / "checkout"
    project.mkdir()
    runner = root / "runner"
    runner.mkdir()
    create = tempfile.mkdtemp
    monkeypatch.setattr(pipeline.tempfile, "mkdtemp", lambda **kwargs: create(dir=runner, **kwargs))
    monkeypatch.setenv("GITHUB_OUTPUT", str(root / "step-output"))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(root / "step-summary"))
    monkeypatch.delenv("VT_API_KEY", raising=False)
    return project


def get_report(workspace):
    output = workspace.parent / "step-output"
    directory = Path(output.read_text().splitlines()[-1].removeprefix("artifact_path="))
    return json.loads(next(directory.glob("*.json")).read_text()), directory


def add_sample(workspace):
    directory = workspace / "sus-scanning-files"
    directory.mkdir()
    sample = directory / "harmless.txt"
    sample.write_bytes(b"harmless fixture, not malware\n")
    return sample


def test_dry_run_never_calls_engines_or_quarantine(workspace, monkeypatch):
    sample = add_sample(workspace)
    before = sample.stat()
    monkeypatch.setattr(pipeline, "VirusTotal", Mock(side_effect=AssertionError("No API")))
    monkeypatch.setattr(pipeline, "Quarantine", Mock(side_effect=AssertionError("No quarantine")))
    assert pipeline.scan_pipeline(workspace, name="classroom-01") == 0
    report, directory = get_report(workspace)
    assert report["status"] == "dry-run complete"
    assert report["metrics"]["Clean"] == 0
    assert report["metrics"]["Files hashed"] == 1
    assert report["files"][0]["status"] == "not scanned (dry run)"
    assert len(report["files"][0]["sha256"]) == 64
    assert sample.read_bytes() == b"harmless fixture, not malware\n"
    assert sample.stat().st_mtime_ns == before.st_mtime_ns
    assert sorted(path.name for path in directory.iterdir()) == [
        "classroom-01.html",
        "classroom-01.json",
        "classroom-01.md",
    ]
    assert not list(workspace.parent.glob("runner/sus-runner-quarantine-*"))


def test_custom_reports_get_unique_directories(workspace):
    add_sample(workspace)
    assert pipeline.scan_pipeline(workspace, report_dir="my reports", name="report-01") == 0
    first, first_dir = get_report(workspace)
    assert pipeline.scan_pipeline(workspace, report_dir="my reports", name="report-01") == 0
    second, second_dir = get_report(workspace)
    assert first["id"] != second["id"]
    assert first_dir != second_dir
    assert first_dir.parent == workspace / "my reports"


@pytest.mark.parametrize("automatic, expected", [(True, 0), (False, 2)])
def test_absent_target_skips_only_automatic_runs(workspace, automatic, expected):
    assert pipeline.scan_pipeline(workspace, dry_run=False, automatic=automatic) == expected
    report, _ = get_report(workspace)
    assert report["status"] == ("skipped" if automatic else "error")


def test_empty_folder_needs_no_key(workspace):
    (workspace / "sus-scanning-files").mkdir()
    assert pipeline.scan_pipeline(workspace, dry_run=False) == 0
    assert get_report(workspace)[0]["status"] == "skipped"


def test_missing_key_produces_error_report(workspace):
    add_sample(workspace)
    assert pipeline.scan_pipeline(workspace, dry_run=False) == 2
    report, _ = get_report(workspace)
    assert report["status"] == "error"
    assert "VT_API_KEY" in report["message"]


@pytest.mark.parametrize(
    "path",
    [
        "",
        ".",
        "..",
        "../elsewhere",
        "/tmp",
        "sub/../target",
        ".git",
        ".github",
        ".venv/subdir",
        "$(whoami)",
        "files\nartifact_path=/etc",
        "some*glob",
    ],
)
def test_untrusted_paths_rejected(workspace, path):
    with pytest.raises(ValueError):
        pipeline.workspace_path(workspace, path)


@pytest.mark.parametrize("value", ["", "../report", "my.html", "a/b", "x\nbad", "$(id)", "-bad"])
def test_report_names_reject_shell_or_path_syntax(value):
    with pytest.raises(ValueError):
        pipeline.report_name(value)


def test_directory_symlink_is_rejected(workspace):
    (workspace / "alias").symlink_to(workspace.parent)
    with pytest.raises(ValueError):
        pipeline.workspace_path(workspace, "alias/out", output=True)


@pytest.mark.parametrize("report_dir", ["sus-scanning-files", "sus-scanning-files/out", "src/out"])
def test_invalid_output_generates_safe_fallback_report(workspace, report_dir):
    sample = add_sample(workspace)
    assert pipeline.scan_pipeline(workspace, report_dir=report_dir) == 2
    report, directory = get_report(workspace)
    assert report["status"] == "error"
    assert directory.is_relative_to(workspace.parent / "runner")
    assert sample.exists()
    assert list(sample.parent.iterdir()) == [sample]


@pytest.mark.parametrize(
    "verdict, code, status",
    [
        (Verdict.CLEAN, 0, "no detections"),
        (Verdict.UNKNOWN, 2, "incomplete"),
        (Verdict.MALICIOUS, 1, "malicious"),
    ],
)
def test_real_scan_preserves_outcome_and_publishes_no_samples(
    workspace, monkeypatch, verdict, code, status
):
    sample = add_sample(workspace)
    monkeypatch.setenv("VT_API_KEY", "test-placeholder")
    client = Mock(scan=Mock(return_value=EngineResult("test", verdict)))
    factory = Mock(return_value=client)
    monkeypatch.setattr(pipeline, "VirusTotal", factory)
    assert pipeline.scan_pipeline(workspace, dry_run=False) == code
    report, directory = get_report(workspace)
    assert report["status"] == status
    assert report["exit_code"] == code
    assert len(report["files"]) == 1
    assert report["files"][0]["sha256"]
    assert {file.suffix for file in directory.iterdir()} == {".html", ".json", ".md"}
    assert "test-placeholder" not in next(directory.glob("*.json")).read_text()
    assert factory.call_args.kwargs["upload_unknown"] is False
    if verdict == Verdict.MALICIOUS:
        assert not sample.exists()
        assert report["files"][0]["status"] == "quarantined"
        assert list(
            (workspace.parent / "runner").glob("sus-runner-quarantine-*/quarantine/*/sample.zip")
        )
    else:
        assert sample.exists()
    client.close.assert_called_once()


def test_html_and_summary_escape_untrusted_content():
    report = new_report("Scan")
    report["message"] = "<script>alert('x')</script>\n|`bad`"
    report["files"] = [{"path": "<img src=x onerror=alert(1)>", "status": "<script>"}]
    html = render_html(report)
    assert "<script>" not in html
    assert "<img" not in html
    assert "&lt;script&gt;" in html
    assert "Content-Security-Policy" in html
    summary = render_summary(report)
    assert "<script>" not in summary
    assert "&#96;" in summary and "&#124;" in summary


def test_report_writer_rejects_overwrite_and_traversal(workspace):
    report = new_report("CI")
    directory = workspace / "report"
    write_report(report, directory, "report")
    with pytest.raises(FileExistsError):
        write_report(report, directory, "report")
    with pytest.raises(ValueError):
        write_report(report, directory, "../escape")


def ci_evidence(root, version, *, failure=False):
    directory = root / version
    directory.mkdir(parents=True)
    checks = [
        {"name": name, "status": "passed", "exit_code": 0, "seconds": 0.1}
        for name in ci.CHECK_NAMES
    ]
    if failure:
        checks[0].update(status="failed", exit_code=1)
    (directory / "checks.json").write_text(json.dumps({"checks": checks}))
    (directory / "tests.xml").write_text(
        f'<testsuites><testsuite tests="10" failures="{int(failure)}" errors="0" skipped="1">'
        "</testsuite></testsuites>"
    )


@pytest.mark.parametrize("failed", [False, True])
def test_ci_report_counts_and_failed_gate(workspace, failed):
    inputs = workspace / "inputs"
    for version in ci.PYTHON_VERSIONS:
        ci_evidence(inputs, version, failure=failed)
    assert ci.ci_report(inputs, workspace / "reports", "failure" if failed else "success") == int(
        failed
    )
    report, _ = get_report(workspace)
    assert report["status"] == ("failed" if failed else "passed")
    assert report["metrics"]["Test executions"] == 20
    assert report["metrics"]["Skipped"] == 2
    assert len(report["checks"]) == 10
    assert ("scan gate may now open" in report["message"]) is not failed


def test_ci_missing_evidence_cannot_pass(workspace):
    assert ci.ci_report(workspace / "absent", workspace / "reports", "success") == 1
    report, _ = get_report(workspace)
    assert report["status"] == "failed"
    assert report["metrics"]["Test executions"] == 0


def test_junit_entities_rejected(workspace):
    path = workspace / "bad.xml"
    path.write_text('<!DOCTYPE x [<!ENTITY e "x">]><testsuite/>')
    with pytest.raises(ValueError):
        ci.junit_counts(path)


def test_ci_runner_preserves_all_check_logs_after_test_failure(workspace, monkeypatch):
    mocked = Mock(
        side_effect=[
            subprocess.CompletedProcess([], 1, "test failed", "trace"),
            *[subprocess.CompletedProcess([], 0, "passed", "") for _ in range(4)],
        ]
    )
    monkeypatch.setattr(ci.subprocess, "run", mocked)
    output = workspace / "checks"
    assert ci.run_checks(output) == 1
    assert mocked.call_count == 5
    assert len(list(output.glob("*.log"))) == 5
    checks = json.loads((output / "checks.json").read_text())["checks"]
    assert checks[0]["status"] == "failed"
    assert all(check["status"] == "passed" for check in checks[1:])


def test_workflow_gates_secrets_and_manual_inputs():
    path = Path(__file__).parents[1] / ".github/workflows/ci-cd.yml"
    workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    assert "pull_request_target" not in workflow["on"]
    assert workflow["permissions"] == {"contents": "read"}
    inputs = workflow["on"]["workflow_dispatch"]["inputs"]
    assert set(inputs) == {"scan_directory", "report_directory", "report_name", "dry_run"}
    assert inputs["dry_run"]["default"] == "true"
    job = workflow["jobs"]["scan-cd"]
    assert job["needs"] == ["ci", "ci-report"]
    assert "needs.ci.result == 'success'" in job["if"]
    assert "needs.ci-report.result == 'success'" in job["if"]
    assert "github.ref == 'refs/heads/main'" in job["if"]
    for name in ["ci", "ci-report"]:
        assert "secrets." not in json.dumps(workflow["jobs"][name])
    step = next(step for step in job["steps"] if step.get("id") == "scan")
    assert step["run"] == "python -m sus_o_meter.pipeline scan"
    assert "!inputs.dry_run" in step["env"]["VT_API_KEY"]
    upload = job["steps"][-1]
    assert "*.zip" not in upload["with"]["path"]
    assert "*.bin" not in upload["with"]["path"]
