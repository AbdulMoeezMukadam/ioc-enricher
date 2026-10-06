"""Offline unit tests. No network: providers are stubbed."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from iocenricher.indicators import IndicatorType, classify
from iocenricher.scoring import Band, ProviderResult, aggregate, band_for
from iocenricher.engine import Engine
from iocenricher.providers import Provider


def test_classify_ipv4():
    assert classify("8.8.8.8").type == IndicatorType.IPV4


def test_classify_private_ipv4_flagged():
    ind = classify("10.0.0.5")
    assert ind.type == IndicatorType.IPV4 and ind.is_private
    assert classify("172.16.4.4").is_private
    assert not classify("172.32.0.1").is_private


def test_classify_hashes():
    assert classify("d41d8cd98f00b204e9800998ecf8427e").type == IndicatorType.MD5
    assert classify("a" * 40).type == IndicatorType.SHA1
    assert classify("b" * 64).type == IndicatorType.SHA256


def test_classify_domain_and_url():
    assert classify("evil-domain.com").type == IndicatorType.DOMAIN
    assert classify("https://evil-domain.com/x").type == IndicatorType.URL


def test_refang():
    assert classify("hxxps://bad[.]com").type == IndicatorType.URL
    assert classify("1.2.3[.]4").type == IndicatorType.IPV4


def test_unknown():
    assert classify("not an indicator !!").type == IndicatorType.UNKNOWN


def test_band_thresholds():
    assert band_for(90) == Band.MALICIOUS
    assert band_for(50) == Band.SUSPICIOUS
    assert band_for(20) == Band.LOW
    assert band_for(0) == Band.CLEAN
    assert band_for(None) == Band.UNKNOWN


def test_aggregate_blend():
    results = [
        ProviderResult("a", 100, ""),
        ProviderResult("b", 0, ""),
        ProviderResult("c", None, "skipped"),
    ]
    score, band = aggregate(results)
    # 0.6*100 + 0.4*50 = 80
    assert score == 80.0 and band == Band.MALICIOUS


class _FakeProvider(Provider):
    name = "fake"

    def supports(self, ind):
        return True

    def enrich(self, ind):
        return ProviderResult(self.name, 100.0, "stubbed malicious")


def test_engine_with_stub_provider():
    eng = Engine(providers=[_FakeProvider()])
    out = eng.enrich_one("9.9.9.9")
    assert out.band == Band.MALICIOUS and out.score == 100.0


def test_engine_skips_private_without_calling_providers():
    eng = Engine(providers=[_FakeProvider()])
    out = eng.enrich_one("192.168.1.10")
    assert out.band == Band.CLEAN
    assert out.results[0].provider == "input"


def test_engine_dedupes():
    eng = Engine(providers=[_FakeProvider()])
    out = eng.enrich_many(["9.9.9.9", "9.9.9.9", "  9.9.9.9 "])
    assert len(out) == 1
