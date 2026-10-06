"""Indicator detection and normalisation.

Takes a raw string and works out whether it is an IPv4 address, a domain,
a URL, or a file hash (md5 / sha1 / sha256). Everything downstream keys off
the IndicatorType returned here, so the detection rules live in one place.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    UNKNOWN = "unknown"


HASH_TYPES = {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}

_IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)
_HASH_RES = {
    IndicatorType.MD5: re.compile(r"^[A-Fa-f0-9]{32}$"),
    IndicatorType.SHA1: re.compile(r"^[A-Fa-f0-9]{40}$"),
    IndicatorType.SHA256: re.compile(r"^[A-Fa-f0-9]{64}$"),
}

# Reserved / non-routable ranges we flag so an analyst does not waste a lookup
# (and a free-tier API quota) on something that can never be attacker infra.
_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "0.", "169.254.", "255.")


def _is_private_ipv4(ip: str) -> bool:
    if ip.startswith(_PRIVATE_PREFIXES):
        return True
    # 172.16.0.0 - 172.31.255.255
    if ip.startswith("172."):
        second = int(ip.split(".")[1])
        return 16 <= second <= 31
    return False


@dataclass
class Indicator:
    raw: str
    value: str          # normalised value actually sent to providers
    type: IndicatorType
    is_private: bool = False

    @property
    def is_hash(self) -> bool:
        return self.type in HASH_TYPES


def classify(raw: str) -> Indicator:
    """Return an :class:`Indicator` describing ``raw``.

    Defanged indicators (hxxp, [.]) are re-fanged first so a copy-paste from a
    threat report or an email header Just Works.
    """
    value = _refang(raw.strip())

    if _IPV4_RE.match(value):
        return Indicator(raw, value, IndicatorType.IPV4, _is_private_ipv4(value))

    for htype, rx in _HASH_RES.items():
        if rx.match(value):
            return Indicator(raw, value.lower(), htype)

    if value.lower().startswith(("http://", "https://")):
        host = urlparse(value).hostname or ""
        return Indicator(raw, value, IndicatorType.URL, _is_private_ipv4(host))

    if _DOMAIN_RE.match(value):
        return Indicator(raw, value.lower(), IndicatorType.DOMAIN)

    return Indicator(raw, value, IndicatorType.UNKNOWN)


def _refang(text: str) -> str:
    return (
        text.replace("hxxps", "https")
        .replace("hxxp", "http")
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
        .replace("[at]", "@")
    )
