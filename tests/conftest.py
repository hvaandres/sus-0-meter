import pytest
import requests


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Live HTTP is forbidden in tests")

    monkeypatch.setattr(requests.sessions.Session, "request", blocked)


@pytest.fixture
def sample(tmp_path):
    # Resolve the OS-provided temporary root (macOS may return /var).
    path = tmp_path.resolve() / "harmless.txt"
    path.write_bytes(b"harmless fixture, not malware\n")
    return path
