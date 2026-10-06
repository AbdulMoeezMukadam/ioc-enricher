"""Enrichment engine: tie indicators, providers and scoring together."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .indicators import Indicator, IndicatorType, classify
from .providers import Provider, default_providers
from .scoring import Band, ProviderResult, aggregate


@dataclass
class Enrichment:
    indicator: Indicator
    score: float | None
    band: Band
    results: list[ProviderResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator.value,
            "type": self.indicator.type.value,
            "score": self.score,
            "band": self.band.value,
            "providers": [
                {
                    "provider": r.provider,
                    "score": r.score,
                    "summary": r.summary,
                    "error": r.error,
                }
                for r in self.results
            ],
        }


class Engine:
    def __init__(self, providers: list[Provider] | None = None, workers: int = 4):
        self.providers = providers if providers is not None else default_providers()
        self.workers = workers

    def enrich_one(self, raw: str) -> Enrichment:
        ind = classify(raw)

        if ind.type == IndicatorType.UNKNOWN:
            return Enrichment(ind, None, Band.UNKNOWN,
                              [ProviderResult("input", None, "unrecognised indicator format")])
        if ind.is_private:
            return Enrichment(ind, 0.0, Band.CLEAN,
                              [ProviderResult("input", 0.0, "private / non-routable address, not queried")])

        active = [p for p in self.providers if p.supports(ind)]
        results: list[ProviderResult] = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            results = list(pool.map(lambda p: p.enrich(ind), active))

        score, band = aggregate(results)
        return Enrichment(ind, score, band, results)

    def enrich_many(self, raws: list[str]) -> list[Enrichment]:
        # De-dupe while preserving order so a 500-line IOC dump does not burn
        # quota on repeats.
        seen, ordered = set(), []
        for r in raws:
            key = r.strip().lower()
            if key and key not in seen:
                seen.add(key)
                ordered.append(r.strip())
        return [self.enrich_one(r) for r in ordered]
