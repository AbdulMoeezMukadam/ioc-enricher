# Screenshots to capture for your portfolio / README

1. Terminal table output: run against a mix of clean + malicious indicators.
2. The HTML report (samples/demo-report.png is already generated).
3. A JSON snippet piped into `jq`, to show it composes with other tooling.
4. The passing test run (`pytest -q`).

Tip: use a known-bad test indicator from a feed's own documentation, plus the
EICAR test-file hash (44d88612fea8a8f36de82e1278abb02f), so screenshots show
real verdicts without you touching live malware.
