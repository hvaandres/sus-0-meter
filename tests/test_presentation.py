from io import StringIO
from pathlib import Path
from unittest.mock import Mock

import pytest
from rich.console import Console

from sus_o_meter.cli import main, select_target
from sus_o_meter.engines import EngineResult, Verdict
from sus_o_meter.presentation import MAGICIAN, ScanDisplay, show_banner
from sus_o_meter.quarantine import Quarantine
from sus_o_meter.scanner import scan_directory


def terminal():
    output = StringIO()
    return Console(file=output, width=160, markup=False, highlight=False), output


def test_magician_banner():
    console, output = terminal()
    show_banner(console)
    assert "/____\\" in MAGICIAN
    assert "/____\\" in output.getvalue()
    assert "malware-triage magician" in output.getvalue()


def test_directory_prompt_retries_blank_missing_and_quarantine(sample, monkeypatch):
    console, output = terminal()
    quarantine = sample.parent / "quarantine"
    quarantine.mkdir(mode=0o700)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    prompt = Mock(
        side_effect=["", str(sample.parent / "missing"), str(quarantine), str(sample.parent)]
    )
    monkeypatch.setattr(console, "input", prompt)
    assert select_target(None, quarantine, console) == sample.parent
    assert prompt.call_count == 4
    assert "Please enter a directory path" in output.getvalue()
    assert "That location is unavailable" in output.getvalue()


def test_prompt_accepts_quoted_paths_with_spaces(sample, monkeypatch):
    console, _ = terminal()
    directory = sample.parent / "my samples"
    directory.mkdir()
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(console, "input", lambda _: f'"{directory}"')
    assert select_target(None, sample.parent / "quarantine", console) == directory


def test_prompt_expands_home_directory(sample, monkeypatch):
    console, _ = terminal()
    monkeypatch.setenv("HOME", str(sample.parent))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(console, "input", lambda _: "~")
    assert select_target(None, sample.parent / "quarantine", console) == sample.parent


def test_prompt_works_without_readline(sample, monkeypatch):
    console, _ = terminal()
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sus_o_meter.cli.importlib.import_module", Mock(side_effect=ImportError))
    monkeypatch.setattr(console, "input", lambda _: str(sample.parent))
    assert select_target(None, sample.parent / "quarantine", console) == sample.parent


def test_explicit_directory_does_not_prompt(sample, monkeypatch):
    console, _ = terminal()
    prompt = Mock(side_effect=AssertionError("Must not prompt"))
    monkeypatch.setattr(console, "input", prompt)
    assert select_target(sample.parent, sample.parent / "quarantine", console) == sample.parent
    prompt.assert_not_called()


def test_noninteractive_cli_requires_directory(monkeypatch, capsys):
    monkeypatch.setenv("VT_API_KEY", "test-placeholder")
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main([]) == 2
    assert "--dir is required" in capsys.readouterr().out


@pytest.mark.parametrize("exception, code", [(EOFError, 2), (KeyboardInterrupt, 130)])
def test_prompt_cancelled_cleanly(monkeypatch, capsys, exception, code):
    monkeypatch.setenv("VT_API_KEY", "test-placeholder")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(Console, "input", Mock(side_effect=exception))
    assert main([]) == code
    assert "Traceback" not in capsys.readouterr().out


def test_cli_interactive_end_to_end(sample, monkeypatch, capsys):
    monkeypatch.setenv("VT_API_KEY", "test-placeholder")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(Console, "input", Mock(return_value=str(sample.parent)))
    engine = Mock(scan=Mock(return_value=EngineResult("test", Verdict.CLEAN)))
    monkeypatch.setattr("sus_o_meter.cli.VirusTotal", Mock(return_value=engine))
    assert main(["--quarantine-dir", str(sample.parent / "quarantine")]) == 0
    output = capsys.readouterr().out
    assert "malware-triage magician" in output
    assert sample.name in output
    assert "Reading file bytes" in output
    assert "SHA-256 calculated" in output
    assert "Total Files Scanned" in output
    assert "test-placeholder" not in output


def test_heartbeat_timing_context_and_new_step_reset():
    console, output = terminal()
    now = [0.0]
    display = ScanDisplay(console, clock=lambda: now[0])
    display.status("Waiting for VirusTotal hash lookup", Path("/samples/example.bin"))
    now[0] = 14
    display.heartbeat()
    assert "We are still working on this" not in output.getvalue()
    now[0] = 15
    display.heartbeat()
    assert "We are still working on this (15s in this step)" in output.getvalue()
    assert "/samples/example.bin" in output.getvalue()
    assert "Current step: Waiting for VirusTotal hash lookup" in output.getvalue()
    now[0] = 30
    display.heartbeat()
    assert output.getvalue().count("We are still working on this") == 2
    display.status("Checking analysis status")
    assert display.current_file == Path("/samples/example.bin")
    now[0] = 44
    display.heartbeat()
    assert output.getvalue().count("We are still working on this") == 2
    now[0] = 45
    display.heartbeat()
    assert output.getvalue().count("We are still working on this") == 3


@pytest.mark.parametrize("fail", [False, True])
def test_heartbeat_thread_stops_on_exit(fail):
    console, _ = terminal()
    display = ScanDisplay(console)
    try:
        with display:
            assert display.thread.is_alive()
            if fail:
                raise RuntimeError("test failure")
    except RuntimeError:
        pass
    assert display.stop.is_set()
    assert not display.thread.is_alive()


def test_status_and_progress_escape_controls_and_preserve_markup():
    console, output = terminal()
    with ScanDisplay(console) as display:
        display.status("Scanning [red]literal[/red]\x1b[31m", Path("/samples/file\n\x1b.bin"))
    text = output.getvalue()
    assert "\x1b" not in text
    assert "\\u001b" in text
    assert "[red]literal[/red]" in text
    assert "file\\n" in text


def test_scanner_reports_ordered_file_steps(sample):
    events = []
    engine = Mock(scan=Mock(return_value=EngineResult("test", Verdict.CLEAN, "No detections")))
    with Quarantine(sample.parent / "quarantine") as quarantine:
        scan_directory(
            sample.parent,
            quarantine,
            [engine],
            status=lambda message, path: events.append((message, path)),
        )
    messages = [message for message, _ in events]
    opening = next(i for i, message in enumerate(messages) if message.startswith("Opening file"))
    hashing = next(
        i for i, message in enumerate(messages) if message.startswith("Reading file bytes")
    )
    hashed = next(
        i for i, message in enumerate(messages) if message.startswith("SHA-256 calculated")
    )
    engine_start = next(
        i for i, message in enumerate(messages) if message.startswith("Consulting engine")
    )
    assert opening < hashing < hashed < engine_start
    assert all(path == sample for _, path in events[opening : engine_start + 1])
    assert messages[-1] == "Scan complete; preparing the final summary"


def test_empty_scan_finishes_progress(sample):
    sample.unlink()
    updates = Mock()
    with Quarantine(sample.parent / "quarantine") as quarantine:
        summary = scan_directory(sample.parent, quarantine, [], progress=updates)
    assert summary.scanned == 0
    updates.assert_called_with("Complete", 0, 0)
