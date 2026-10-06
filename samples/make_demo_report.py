"""Generate a demo HTML report with canned verdicts (no API keys / network).

Useful for README screenshots. Run: python3 samples/make_demo_report.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iocenricher.engine import Engine
from iocenricher.providers import Provider
from iocenricher.scoring import ProviderResult
from iocenricher.report import to_html

CANNED = {
    "185.220.101.1": [ProviderResult("virustotal", 88.0, "11 malicious / 2 suspicious of 94 engines"),
                       ProviderResult("abuseipdb", 100.0, "abuse confidence 100%, 430 reports, DE"),
                       ProviderResult("otx", 72.0, "referenced in 6 OTX pulse(s)")],
    "example.com":   [ProviderResult("virustotal", 0.0, "0 malicious / 0 suspicious of 90 engines"),
                      ProviderResult("otx", 0.0, "referenced in 0 OTX pulse(s)")],
    "44d88612fea8a8f36de82e1278abb02f": [ProviderResult("virustotal", 61.0, "58 malicious of 72 engines (EICAR test)"),
                       ProviderResult("otx", 45.0, "referenced in 2 OTX pulse(s)")],
}

class Canned(Provider):
    name = "canned"
    def supports(self, ind): return True
    def enrich(self, ind): return ProviderResult("canned", None, "")

eng = Engine(providers=[])
items = []
from iocenricher.indicators import classify
from iocenricher.scoring import aggregate
from iocenricher.engine import Enrichment
for ioc, results in CANNED.items():
    ind = classify(ioc)
    score, band = aggregate(results)
    items.append(Enrichment(ind, score, band, results))

open(os.path.join(os.path.dirname(__file__), "demo-report.html"), "w").write(to_html(items))
print("wrote samples/demo-report.html")
