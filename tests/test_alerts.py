import io

from aiwarden.alerts import ConsoleSink, EventBus, SqliteSink, WebhookSink
from aiwarden.events import Event, Severity


def ev(sev=Severity.HIGH, key="k", ts=1000.0):
    return Event("egress", "egress.cross_border", sev, "x -> US", {"country": "US"}, dedupe_key=key, ts=ts)


def test_dedupe_window():
    got = []

    class S:
        min_severity = Severity.INFO

        def emit(self, e):
            got.append(e)

    bus = EventBus([S()], dedupe_window=60)
    assert bus.publish(ev(ts=1000))
    assert not bus.publish(ev(ts=1030))
    assert bus.publish(ev(ts=1100))
    assert bus.publish(ev(key="other", ts=1101))
    assert len(got) == 3


def test_min_severity_filter():
    out = io.StringIO()
    bus = EventBus([ConsoleSink(Severity.MEDIUM, stream=out, color=False)])
    bus.publish(ev(Severity.LOW, key="a"))
    bus.publish(ev(Severity.HIGH, key="b"))
    text = out.getvalue()
    assert text.count("cross_border") == 1 and "HIGH" in text


def test_sqlite_roundtrip(tmp_path):
    db = tmp_path / "e.db"
    sink = SqliteSink(db)
    sink.emit(ev(Severity.INFO, ts=1))
    sink.emit(ev(Severity.HIGH, ts=2))
    rows = SqliteSink.query(db, min_severity=Severity.LOW)
    assert len(rows) == 1 and rows[0]["severity"] == "high" and rows[0]["details"]["country"] == "US"


def test_webhook_formats():
    e = ev()
    assert b'"text"' in WebhookSink("http://x", "slack")._request(e).data
    r = WebhookSink("http://x", "ntfy")._request(e)
    assert r.headers["Priority"] == "high"
    assert b'"rule": "egress.cross_border"' in WebhookSink("http://x")._request(e).data
