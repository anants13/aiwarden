import ipaddress

import pytest

from aiwarden.egress import ConnInfo, EgressPolicy, domain_matches, process_matches
from aiwarden.events import Severity
from aiwarden.geo import GeoInfo, ip_scope


def conn(ip="203.0.113.5", silent=False, age=10.0, name="ollama"):
    return ConnInfo(pid=10, proc_name=name, cmdline=[name, "serve"], root_pid=10, root_name=name,
                    root_age=age, root_is_silent=silent, raddr=ip, rport=443)


@pytest.fixture
def policy():
    return EgressPolicy(allowed_countries={"IN"}, home_country="IN",
                        allow_domains=["huggingface.co"], allow_asns={64500},
                        allow_cidrs=[ipaddress.ip_network("198.51.100.0/24")], silent_grace_seconds=60)


def test_cross_border_is_high(policy):
    e = policy.evaluate(conn(), GeoInfo("203.0.113.5", "US", 1, "Example"), None)
    assert e.rule == "egress.cross_border" and e.severity == Severity.HIGH
    assert "US" in e.title


def test_domestic_is_info(policy):
    e = policy.evaluate(conn(), GeoInfo("203.0.113.5", "IN"), None)
    assert e.rule == "egress.connection" and e.severity == Severity.INFO


def test_silent_server_domestic_is_medium(policy):
    e = policy.evaluate(conn(silent=True, age=600), GeoInfo("203.0.113.5", "IN"), None)
    assert e.rule == "egress.inference_server_outbound" and e.severity == Severity.MEDIUM


def test_silent_server_within_grace_is_ok(policy):
    e = policy.evaluate(conn(silent=True, age=5), GeoInfo("203.0.113.5", "IN"), None)
    assert e.severity == Severity.INFO


def test_allowlists(policy):
    assert policy.evaluate(conn(), GeoInfo("x", "US"), "cdn.huggingface.co").rule == "egress.allowed"
    assert policy.evaluate(conn(), GeoInfo("x", "US", asn=64500), None).rule == "egress.allowed"
    assert policy.evaluate(conn("198.51.100.9"), GeoInfo("198.51.100.9", "US"), None).rule == "egress.allowed"
    policy.resolved_allow = {"203.0.113.5": "huggingface.co"}
    assert policy.evaluate(conn(), GeoInfo("203.0.113.5", "US"), None).rule == "egress.allowed"


def test_lan_and_loopback_ignored_by_default(policy):
    assert policy.evaluate(conn("192.168.1.4"), GeoInfo("192.168.1.4", scope="private"), None) is None
    assert policy.evaluate(conn("127.0.0.1"), GeoInfo("127.0.0.1", scope="loopback"), None) is None
    policy.alert_on_lan = True
    assert policy.evaluate(conn("192.168.1.4"), GeoInfo("192.168.1.4", scope="private"), None).rule == "egress.lan"


def test_unverified_without_geo():
    p = EgressPolicy(allowed_countries={"IN"}, home_country="IN", geo_available=False)
    e = p.evaluate(conn(), GeoInfo("203.0.113.5"), None)
    assert e.rule == "egress.unverified"


def test_process_matching():
    assert process_matches("ollama", ["ollama", "serve"], ["ollama"])
    assert process_matches("python3", ["python3", "-m", "vllm.entrypoints.openai.api_server"], ["cmd:vllm"])
    assert not process_matches("python3", ["python3", "app.py"], ["ollama", "cmd:vllm"])


def test_domain_matching():
    assert domain_matches("cdn-lfs.huggingface.co", ["huggingface.co"]) == "huggingface.co"
    assert domain_matches("x.hf.co", ["*.hf.co"]) == "hf.co"
    assert domain_matches("evilhuggingface.co", ["huggingface.co"]) is None


def test_ip_scope():
    assert ip_scope("127.0.0.1") == "loopback"
    assert ip_scope("10.1.2.3") == "private"
    assert ip_scope("100.64.0.1") == "private"
    assert ip_scope("::ffff:192.168.0.1") == "private"
    assert ip_scope("fe80::1%en0") == "link_local"
    assert ip_scope("8.8.8.8") == "public"
