# ioc-enrich

Threat-intel triage from the command line: the indicator enrichment a SOC analyst does by hand, scripted.

A small Python CLI that takes a list of IOCs (IPs, domains, URLs, file hashes), enriches each one via the [VirusTotal](https://www.virustotal.com/) and [AbuseIPDB](https://www.abuseipdb.com/) APIs, gives every IOC a verdict (malicious / suspicious / clean / unknown), and outputs a triage report in Markdown, JSON or CSV.

## Features

- Accepts messy input: mixed IOC types, comments, duplicates, and **defanged** indicators (`bad[.]com`, `hxxp://…`) as commonly shared in threat feeds and IR reports
- URLs are reduced to their host and checked as a domain or IP
- VirusTotal lookups for IPs, domains and hashes; AbuseIPDB for IPs
- Simple, explainable verdict logic (see below)
- Report sorted worst-first, so the things needing attention are at the top
- Respects the VirusTotal free-tier rate limit (4 requests/min) out of the box

## Setup

```
python -m venv .venv
.venv\Scripts\activate        # or source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env         # then paste your API keys in
```

Both APIs have free tiers: [VirusTotal](https://www.virustotal.com/gui/join-us) and [AbuseIPDB](https://www.abuseipdb.com/register).

## Usage

```
python ioc_enrich.py examples/iocs.txt                  # markdown report to stdout
python ioc_enrich.py examples/iocs.txt -o report.md     # write report to file
python ioc_enrich.py iocs.txt --json out.json --csv out.csv
python ioc_enrich.py iocs.txt --dry-run                 # just parse + type, no API calls
echo 8.8.8.8 | python ioc_enrich.py -                   # read from stdin
```

Example report:

```markdown
# IOC Enrichment Report

**4 IOCs checked** — 1 clean, 1 malicious, 1 suspicious, 1 unknown

| IOC | Type | Verdict | VirusTotal | AbuseIPDB | Notes |
|---|---|---|---|---|---|
| `185.220.101.34` | ip | **malicious** | 9 mal / 2 sus | 100% (312 reports) | |
| `login-verify-account.com` | domain | **suspicious** | 2 mal / 1 sus | - | |
| `44d88612fea8a8f36de82e1278abb02f` | hash | **unknown** | not found | - | not found on VT |
| `8.8.8.8` | ip | **clean** | 0 mal / 0 sus | 0% (0 reports) | |
```

## Verdict logic

| Verdict | Rule |
|---|---|
| malicious | ≥3 VirusTotal engines flag it malicious, or AbuseIPDB confidence ≥75% |
| suspicious | ≥1 VT engine flags malicious or suspicious, or AbuseIPDB ≥25% |
| clean | looked up successfully, nothing flagged |
| unknown | no data (not found, or the relevant source wasn't available) |

Thresholds live in one function (`classify`) so they're easy to tune per environment.

## Design & trade-offs

- **Sequential requests with a sleep, not asyncio.** The VirusTotal free tier allows 4 lookups/minute, so concurrency buys nothing — the rate limit is the bottleneck, not I/O. A `--delay` flag exists for paid keys.
- **`requests` over an async client** for the same reason: simpler code, same throughput at free-tier limits.
- **Verdicts are deliberately conservative** — a single engine detection is enough for "suspicious" because in triage a false positive costs a minute, a false negative costs an incident.
- **Defang parsing is built in** rather than left to the user, because real IOC lists arrive defanged and hand-refanging them is exactly the toil this tool removes.

## Tests

```
pytest
```

Covers the parser (types, defanging, dedupe), the verdict thresholds, and report ordering — everything that doesn't need the network.
