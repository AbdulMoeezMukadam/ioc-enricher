"""Threat-intelligence providers.

Each provider knows how to query one feed and flatten the response into a
ProviderResult. Providers are best-effort: a missing API key or a failed call
degrades to a ProviderResult with score=None and an error string, never a crash,
so the tool still runs with whatever feeds the analyst has configured.

Supported (all have free tiers):
  * VirusTotal   - IPs, domains, URLs, hashes
  * AbuseIPDB    - IPs
  * AlienVault OTX - IPs, domains, hashes

Keys are read from the environment:
  VT_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY
"""
from __future__ import annotations

import base64
import os
from typing import Optional

import requests

from .indicators import Indicator, IndicatorType
from .scoring import ProviderResult

_TIMEOUT = 20


class Provider:
    name = "base"

    def supports(self, ind: Indicator) -> bool:
        raise NotImplementedError

    def enrich(self, ind: Indicator) -> ProviderResult:
        raise NotImplementedError

    def _missing_key(self) -> ProviderResult:
        return ProviderResult(self.name, None, "skipped (no API key configured)")


class VirusTotal(Provider):
    name = "virustotal"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VT_API_KEY")

    def supports(self, ind: Indicator) -> bool:
        return ind.type in {
            IndicatorType.IPV4, IndicatorType.DOMAIN, IndicatorType.URL,
            IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256,
        }

    def _endpoint(self, ind: Indicator) -> str:
        base = "https://www.virustotal.com/api/v3"
        if ind.type == IndicatorType.IPV4:
            return f"{base}/ip_addresses/{ind.value}"
        if ind.type == IndicatorType.DOMAIN:
            return f"{base}/domains/{ind.value}"
        if ind.type == IndicatorType.URL:
            url_id = base64.urlsafe_b64encode(ind.value.encode()).decode().strip("=")
            return f"{base}/urls/{url_id}"
        return f"{base}/files/{ind.value}"  # any hash type

    def enrich(self, ind: Indicator) -> ProviderResult:
        if not self.api_key:
            return self._missing_key()
        try:
            resp = requests.get(
                self._endpoint(ind),
                headers={"x-apikey": self.api_key},
                timeout=_TIMEOUT,
            )
            if resp.status_code == 404:
                return ProviderResult(self.name, 0.0, "not found in VT dataset")
            resp.raise_for_status()
            stats = (
                resp.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1
            score = round(100 * (malicious + 0.5 * suspicious) / total, 1)
            summary = f"{malicious} malicious / {suspicious} suspicious of {total} engines"
            return ProviderResult(self.name, score, summary, {"stats": stats})
        except requests.RequestException as exc:
            return ProviderResult(self.name, None, "lookup failed", error=str(exc))


class AbuseIPDB(Provider):
    name = "abuseipdb"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")

    def supports(self, ind: Indicator) -> bool:
        return ind.type == IndicatorType.IPV4

    def enrich(self, ind: Indicator) -> ProviderResult:
        if not self.api_key:
            return self._missing_key()
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ind.value, "maxAgeInDays": 90},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score = float(data.get("abuseConfidenceScore", 0))
            reports = data.get("totalReports", 0)
            country = data.get("countryCode", "??")
            summary = f"abuse confidence {score:.0f}%, {reports} reports, {country}"
            return ProviderResult(self.name, score, summary, {"data": data})
        except requests.RequestException as exc:
            return ProviderResult(self.name, None, "lookup failed", error=str(exc))


class OTX(Provider):
    name = "otx"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("OTX_API_KEY")

    def supports(self, ind: Indicator) -> bool:
        return ind.type in {
            IndicatorType.IPV4, IndicatorType.DOMAIN,
            IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256,
        }

    def _section(self, ind: Indicator) -> str:
        base = "https://otx.alienvault.com/api/v1/indicators"
        if ind.type == IndicatorType.IPV4:
            return f"{base}/IPv4/{ind.value}/general"
        if ind.type == IndicatorType.DOMAIN:
            return f"{base}/domain/{ind.value}/general"
        return f"{base}/file/{ind.value}/general"

    def enrich(self, ind: Indicator) -> ProviderResult:
        if not self.api_key:
            return self._missing_key()
        try:
            resp = requests.get(
                self._section(ind),
                headers={"X-OTX-API-KEY": self.api_key},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            pulses = resp.json().get("pulse_info", {}).get("count", 0)
            # OTX has no single verdict; pulse membership is the signal. Map
            # pulse count onto a saturating curve: 0 -> 0, 1 -> 30, 5+ -> ~90.
            score = round(min(90.0, 30 * (pulses ** 0.5)), 1) if pulses else 0.0
            summary = f"referenced in {pulses} OTX pulse(s)"
            return ProviderResult(self.name, score, summary, {"pulses": pulses})
        except requests.RequestException as exc:
            return ProviderResult(self.name, None, "lookup failed", error=str(exc))


def default_providers() -> list[Provider]:
    return [VirusTotal(), AbuseIPDB(), OTX()]
