"""Normalise provider verdicts into a single 0-100 risk score + band.

Each provider returns results in its own shape and scale. We flatten every
provider response to a ProviderResult, then combine them into one score so an
analyst gets a consistent, explainable verdict regardless of which feeds
answered.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Band(str, Enum):
    CLEAN = "clean"
    LOW = "low"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


@dataclass
class ProviderResult:
    provider: str
    # 0-100 contribution this provider makes to the risk score, or None if the
    # provider had nothing to say (no key, no data, lookup failed).
    score: Optional[float]
    summary: str
    raw: dict = field(default_factory=dict)
    error: Optional[str] = None


def band_for(score: Optional[float]) -> Band:
    if score is None:
        return Band.UNKNOWN
    if score >= 75:
        return Band.MALICIOUS
    if score >= 40:
        return Band.SUSPICIOUS
    if score >= 10:
        return Band.LOW
    return Band.CLEAN


def aggregate(results: list[ProviderResult]) -> tuple[Optional[float], Band]:
    """Weighted blend of provider scores.

    We take the max as a floor (if any reputable feed is confident something is
    bad, the indicator is at least suspicious) and the mean as the body, so a
    single noisy feed cannot by itself push an indicator to "malicious".
    """
    scored = [r.score for r in results if r.score is not None]
    if not scored:
        return None, Band.UNKNOWN

    mean = sum(scored) / len(scored)
    peak = max(scored)
    blended = round(0.6 * peak + 0.4 * mean, 1)
    return blended, band_for(blended)
