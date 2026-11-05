"""Terminal presentation only; the heartbeat never performs scanning or network I/O."""

import json
import threading
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.text import Text

MAGICIAN = r"""
       /\
      /  \       *
     /____\     /
     (o  o)    /
      \__/   -*
     /|  |\ /
    /_|__|_\
      /  \
"""


def show_banner(console: Console) -> None:
    console.print(
        Panel(
            Text(
                MAGICIAN + "\nSus-O-Meter — your malware-triage magician\n"
                "No disappearing acts: every scan step is shown below.",
                style="cyan",
            ),
            title="Sus-O-Meter",
            border_style="magenta",
            expand=False,
        )
    )


class ScanDisplay:
    """Print durable step messages while Rich refreshes the live progress bar."""

    def __init__(self, console: Console, *, heartbeat_interval: float = 15, clock=time.monotonic):
        if heartbeat_interval <= 0:
            raise ValueError("Heartbeat interval must be positive")
        self.console = console
        self.interval = heartbeat_interval
        self.clock = clock
        self.display = Progress(
            SpinnerColumn(),
            TextColumn("{task.description}", markup=False),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        )
        self.task = self.display.add_task("Preparing the scan", total=None)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None
        self.current_file: Path | None = None
        self.current_step = "Preparing the scan"
        self.step_started = self.last_reminder = self.clock()

    def _print(self, message: str) -> None:
        timestamp = datetime.now().astimezone().strftime("%H:%M:%S")
        location = (
            json.dumps(str(self.current_file), ensure_ascii=True) if self.current_file else "-"
        )
        # Text prevents Rich markup interpretation; JSON also escapes terminal controls.
        safe_message = json.dumps(message, ensure_ascii=True)[1:-1]
        self.console.print(Text(f"{timestamp} | File: {location} | {safe_message}"))

    def status(self, message: str, path: Path | None = None) -> None:
        with self.lock:
            if path is not None:
                self.current_file = path
            self.current_step = message
            self.step_started = self.last_reminder = self.clock()
            self._print(message)
            self.display.update(self.task, description=json.dumps(message, ensure_ascii=True)[1:-1])

    def progress(self, phase: str, done: int, total: int) -> None:
        with self.lock:
            self.display.update(
                self.task,
                description=phase,
                completed=done,
                total=total if total else (None if phase == "Discovering" else 0),
            )

    def notify(self, path: Path, message: str) -> None:
        self.status(f"Result: {message}", path)

    def heartbeat(self) -> None:
        """One heartbeat tick, exposed for deterministic tests without sleeping."""
        with self.lock:
            now = self.clock()
            if now - self.last_reminder >= self.interval:
                elapsed = int(now - self.step_started)
                self._print(
                    f"We are still working on this ({elapsed}s in this step). "
                    f"Current step: {self.current_step}"
                )
                self.last_reminder = now

    def _watch(self) -> None:
        while not self.stop.wait(min(1, self.interval)):
            self.heartbeat()

    def __enter__(self) -> "ScanDisplay":
        self.display.start()
        self.thread = threading.Thread(target=self._watch, name="scan-heartbeat", daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.stop.set()
        if self.thread is not None:
            self.thread.join()
        self.display.stop()
