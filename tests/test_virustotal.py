from unittest.mock import Mock

import pytest
import requests

from sus_o_meter.engines import Verdict
from sus_o_meter.files import SafeFile
from sus_o_meter.virustotal import MAX_UPLOAD_BYTES, VirusTotal, VirusTotalError


def stats(malicious=0, suspicious=0, undetected=8):
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": 0,
        "undetected": undetected,
    }


def response(code=200, payload=None, headers=None):
    result = Mock(status_code=code, headers=headers or {})
    result.json.return_value = payload
    return result


def report(counts=None):
    return {"data": {"attributes": {"last_analysis_stats": counts or stats()}}}


def client(*responses, **kwargs):
    session = Mock()
    session.request.side_effect = responses
    return VirusTotal("test-placeholder", session=session, **kwargs)


def run(vt, sample):
    with SafeFile(sample) as file:
        return vt.scan(file, file.sha256())


def test_hash_first_and_no_upload_for_known_file(sample):
    vt = client(response(payload=report()), upload_unknown=True)
    assert run(vt, sample).verdict == Verdict.CLEAN
    args, kwargs = vt.session.request.call_args
    assert args[0] == "GET"
    assert "/files/" in args[1]
    assert "files" not in kwargs
    assert kwargs["allow_redirects"] is False
    assert vt.session.request.call_count == 1


def test_unknown_requires_consent(sample):
    vt = client(response(404))
    assert run(vt, sample).verdict == Verdict.UNKNOWN
    assert vt.session.request.call_count == 1


def test_upload_and_poll(sample):
    vt = client(
        response(404),
        response(payload={"data": {"id": "analysis-id"}}),
        response(payload={"data": {"attributes": {"status": "queued"}}}),
        response(payload={"data": {"attributes": {"status": "completed", "stats": stats(2)}}}),
        upload_unknown=True,
        sleep=Mock(),
    )
    assert run(vt, sample).verdict == Verdict.MALICIOUS
    calls = vt.session.request.call_args_list
    assert [call.args[0] for call in calls] == ["GET", "POST", "GET", "GET"]
    assert calls[1].kwargs["files"]["file"][0] == "sample.bin"
    vt.sleep.assert_called_once_with(15)


def test_large_unknown_not_uploaded(sample):
    with sample.open("wb") as stream:
        stream.truncate(MAX_UPLOAD_BYTES + 1)
    vt = client(response(404), upload_unknown=True)
    assert run(vt, sample).verdict == Verdict.UNKNOWN
    assert vt.session.request.call_count == 1


def test_rate_limit_retry(sample):
    first = response(429, headers={"Retry-After": "4"})
    vt = client(first, response(payload=report()), sleep=Mock())
    assert run(vt, sample).verdict == Verdict.CLEAN
    vt.sleep.assert_called_once_with(4)
    first.close.assert_called_once()


def test_rate_limit_exhaustion(sample):
    vt = client(response(429), response(429), retries=1, sleep=Mock())
    with pytest.raises(VirusTotalError, match="retry limit"):
        run(vt, sample)
    assert vt.session.request.call_count == 2


def test_long_retry_after_stops_without_early_retry(sample):
    vt = client(response(429, headers={"Retry-After": "600"}), sleep=Mock())
    with pytest.raises(VirusTotalError, match="budget"):
        run(vt, sample)
    vt.sleep.assert_not_called()


@pytest.mark.parametrize("code", [401, 403, 302, 400])
def test_http_failures_are_sanitized(sample, code):
    vt = client(response(code, payload={"secret": "do not display"}))
    with pytest.raises(VirusTotalError) as error:
        run(vt, sample)
    assert "do not display" not in str(error.value)
    assert "test-placeholder" not in str(error.value)


def test_network_failure_sanitized(sample):
    vt = client(requests.ConnectionError("request with sensitive headers"))
    with pytest.raises(VirusTotalError, match="network request failed") as error:
        run(vt, sample)
    assert "sensitive" not in str(error.value)


@pytest.mark.parametrize("payload", [None, [], {}, {"data": {"attributes": {}}}])
def test_malformed_reports_fail_closed(sample, payload):
    vt = client(response(payload=payload))
    with pytest.raises(VirusTotalError):
        run(vt, sample)


def test_invalid_json(sample):
    invalid = response()
    invalid.json.side_effect = ValueError("private response")
    with pytest.raises(VirusTotalError, match="invalid JSON"):
        run(client(invalid), sample)


@pytest.mark.parametrize(
    ("counts", "threshold", "expected"),
    [
        (stats(1), 1, Verdict.MALICIOUS),
        (stats(1), 2, Verdict.SUSPICIOUS),
        (stats(suspicious=1), 1, Verdict.SUSPICIOUS),
        (stats(undetected=0), 1, Verdict.UNKNOWN),
        (stats(), 1, Verdict.CLEAN),
    ],
)
def test_classification(counts, threshold, expected):
    assert client(threshold=threshold)._classify(counts).verdict == expected


@pytest.mark.parametrize(
    "counts", [{}, {"malicious": 0}, stats(malicious=-1), stats(malicious=True)]
)
def test_bad_stats_rejected(counts):
    with pytest.raises(VirusTotalError):
        client()._classify(counts)


def test_poll_timeout(sample):
    ticks = [0]

    def sleep(seconds):
        ticks[0] += seconds

    vt = client(
        response(404),
        response(payload={"data": {"id": "id"}}),
        response(payload={"data": {"attributes": {"status": "queued"}}}),
        upload_unknown=True,
        analysis_timeout=1,
        sleep=sleep,
        clock=lambda: ticks[0],
    )
    with pytest.raises(VirusTotalError, match="timed out"):
        run(vt, sample)


@pytest.mark.parametrize(
    "kwargs", [{"timeout": 0}, {"poll_interval": float("nan")}, {"threshold": 0}]
)
def test_invalid_configuration(kwargs):
    with pytest.raises(ValueError):
        client(**kwargs)


@pytest.mark.parametrize("status", [[], {}, None, "unexpected"])
def test_malformed_analysis_status(sample, status):
    vt = client(
        response(404),
        response(payload={"data": {"id": "id"}}),
        response(payload={"data": {"attributes": {"status": status}}}),
        upload_unknown=True,
    )
    with pytest.raises(VirusTotalError, match="invalid status"):
        run(vt, sample)


def test_server_error_retried(sample):
    vt = client(response(503), response(payload=report()), sleep=Mock())
    assert run(vt, sample).verdict == Verdict.CLEAN
    vt.sleep.assert_called_once_with(2)


def test_bad_upload_response(sample):
    vt = client(response(404), response(payload={"data": {}}), upload_unknown=True)
    with pytest.raises(VirusTotalError, match="analysis ID"):
        run(vt, sample)


def test_missing_analysis(sample):
    vt = client(
        response(404),
        response(payload={"data": {"id": "id"}}),
        response(404),
        upload_unknown=True,
    )
    with pytest.raises(VirusTotalError, match="analysis not found"):
        run(vt, sample)


def test_upload_retry_rewinds_file(sample):
    methods = []

    def request(method, url, **kwargs):
        methods.append(method)
        if method == "GET" and "/files/" in url:
            return response(404)
        if method == "POST":
            stream = kwargs["files"]["file"][1]
            assert stream.read() == sample.read_bytes()
            if methods.count("POST") == 1:
                return response(429)
            return response(payload={"data": {"id": "id"}})
        return response(payload={"data": {"attributes": {"status": "completed", "stats": stats()}}})

    vt = client(upload_unknown=True, sleep=Mock())
    vt.session.request.side_effect = request
    assert run(vt, sample).verdict == Verdict.CLEAN
    assert methods == ["GET", "POST", "POST", "GET"]


def test_status_reports_hash_lookup_and_rate_limit(sample):
    updates = Mock()
    vt = client(
        response(429, headers={"Retry-After": "4"}),
        response(payload=report()),
        sleep=Mock(),
        status=updates,
    )
    assert run(vt, sample).verdict == Verdict.CLEAN
    messages = [call.args[0] for call in updates.call_args_list]
    assert "no file bytes sent" in messages[0]
    assert any("rate limit; waiting 4s" in message for message in messages)
    assert any("attempt 2/4" in message for message in messages)
    assert messages[-1] == "Hash report received; evaluating engine detection counts"
    assert "test-placeholder" not in " ".join(messages)


def test_status_reports_upload_and_analysis_wait(sample):
    updates = Mock()
    vt = client(
        response(404),
        response(payload={"data": {"id": "id"}}),
        response(payload={"data": {"attributes": {"status": "queued"}}}),
        response(payload={"data": {"attributes": {"status": "completed", "stats": stats()}}}),
        upload_unknown=True,
        sleep=Mock(),
        status=updates,
    )
    assert run(vt, sample).verdict == Verdict.CLEAN
    messages = [call.args[0] for call in updates.call_args_list]
    assert any("--upload-unknown consent" in message for message in messages)
    assert any("analysis queued; waiting 15s" in message for message in messages)
    assert messages[-1] == "VirusTotal analysis complete; evaluating detection counts"
