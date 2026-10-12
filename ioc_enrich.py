import argparse
import csv
import json
import os
import re
import sys
import time

import requests
from dotenv import load_dotenv

VT_URL = "https://www.virustotal.com/api/v3"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$", re.IGNORECASE)
HEX_RE = re.compile(r"^[a-f0-9]+$", re.IGNORECASE)
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


def refang(value):
    value = value.strip()
    value = value.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
    value = value.replace("[:]", ":").replace("[@]", "@")
    value = re.sub(r"^hxxps", "https", value, flags=re.IGNORECASE)
    value = re.sub(r"^hxxp", "http", value, flags=re.IGNORECASE)
    return value


def detect_type(value):
    value = refang(value)
    if value.lower().startswith(("http://", "https://")):
        host = value.split("//", 1)[1].split("/", 1)[0].split(":")[0]
        value = host
    m = IPV4_RE.match(value)
    if m:
        if all(int(octet) <= 255 for octet in m.groups()):
            return value, "ip"
        return value, None
    if len(value) in HASH_LENGTHS and HEX_RE.match(value):
        return value.lower(), "hash"
    if DOMAIN_RE.match(value):
        return value.lower(), "domain"
    return value, None


def parse_input(lines):
    seen = set()
    iocs = []
    skipped = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        value, kind = detect_type(line)
        if kind is None:
            skipped.append(line)
            continue
        if value in seen:
            continue
        seen.add(value)
        iocs.append({"ioc": value, "type": kind})
    return iocs, skipped


def vt_lookup(ioc, kind, key):
    paths = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}
    url = f"{VT_URL}/{paths[kind]}/{ioc}"
    r = requests.get(url, headers={"x-apikey": key}, timeout=30)
    if r.status_code == 404:
        return {"found": False}
    r.raise_for_status()
    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


def abuse_lookup(ip, key, max_age):
    params = {"ipAddress": ip, "maxAgeInDays": max_age}
    headers = {"Key": key, "Accept": "application/json"}
    r = requests.get(ABUSE_URL, params=params, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()["data"]
    return {
        "score": data.get("abuseConfidenceScore", 0),
        "reports": data.get("totalReports", 0),
        "country": data.get("countryCode") or "",
        "isp": data.get("isp") or "",
    }


def classify(vt, abuse):
    vt_mal = vt.get("malicious", 0) if vt else 0
    vt_sus = vt.get("suspicious", 0) if vt else 0
    score = abuse.get("score", 0) if abuse else 0
    if vt_mal >= 3 or score >= 75:
        return "malicious"
    if vt_mal >= 1 or vt_sus >= 1 or score >= 25:
        return "suspicious"
    if (vt and vt.get("found")) or abuse:
        return "clean"
    return "unknown"


def enrich(iocs, vt_key, abuse_key, delay, max_age):
    results = []
    for i, entry in enumerate(iocs):
        ioc, kind = entry["ioc"], entry["type"]
        print(f"[{i + 1}/{len(iocs)}] {ioc}", file=sys.stderr)
        vt = None
        abuse = None
        notes = []
        if vt_key:
            try:
                vt = vt_lookup(ioc, kind, vt_key)
            except requests.RequestException as e:
                notes.append(f"VT error: {e}")
        if abuse_key and kind == "ip":
            try:
                abuse = abuse_lookup(ioc, abuse_key, max_age)
            except requests.RequestException as e:
                notes.append(f"AbuseIPDB error: {e}")
        if vt is not None and not vt.get("found"):
            notes.append("not found on VT")
        results.append({
            "ioc": ioc,
            "type": kind,
            "verdict": classify(vt, abuse),
            "vt": vt,
            "abuse": abuse,
            "notes": "; ".join(notes),
        })
        if vt_key and i < len(iocs) - 1:
            time.sleep(delay)
    return results


def vt_cell(vt):
    if not vt:
        return "-"
    if not vt.get("found"):
        return "not found"
    return f"{vt['malicious']} mal / {vt['suspicious']} sus"


def abuse_cell(abuse):
    if not abuse:
        return "-"
    return f"{abuse['score']}% ({abuse['reports']} reports)"


def markdown_report(results, skipped):
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    lines = ["# IOC Enrichment Report", ""]
    summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
    lines.append(f"**{len(results)} IOCs checked** — {summary}")
    lines.append("")
    lines.append("| IOC | Type | Verdict | VirusTotal | AbuseIPDB | Notes |")
    lines.append("|---|---|---|---|---|---|")
    order = {"malicious": 0, "suspicious": 1, "unknown": 2, "clean": 3}
    for r in sorted(results, key=lambda x: order[x["verdict"]]):
        lines.append(
            f"| `{r['ioc']}` | {r['type']} | **{r['verdict']}** | "
            f"{vt_cell(r['vt'])} | {abuse_cell(r['abuse'])} | {r['notes']} |"
        )
    if skipped:
        lines.append("")
        lines.append(f"Skipped {len(skipped)} unrecognised lines: " + ", ".join(f"`{s}`" for s in skipped))
    lines.append("")
    return "\n".join(lines)


def write_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ioc", "type", "verdict", "vt_malicious", "vt_suspicious", "abuse_score", "abuse_reports", "notes"])
        for r in results:
            vt = r["vt"] or {}
            abuse = r["abuse"] or {}
            writer.writerow([
                r["ioc"], r["type"], r["verdict"],
                vt.get("malicious", ""), vt.get("suspicious", ""),
                abuse.get("score", ""), abuse.get("reports", ""),
                r["notes"],
            ])


def main():
    parser = argparse.ArgumentParser(description="Enrich IOCs (IPs, domains, hashes) via VirusTotal and AbuseIPDB.")
    parser.add_argument("input", help="file with one IOC per line, or - for stdin")
    parser.add_argument("-o", "--output", help="write markdown report to this file (default: stdout)")
    parser.add_argument("--json", help="also write full results as JSON to this file")
    parser.add_argument("--csv", help="also write results as CSV to this file")
    parser.add_argument("--delay", type=float, default=15, help="seconds between VirusTotal calls (free tier is 4/min, default 15)")
    parser.add_argument("--max-age", type=int, default=90, help="AbuseIPDB report window in days (default 90)")
    parser.add_argument("--dry-run", action="store_true", help="only parse and classify types, no API calls")
    args = parser.parse_args()

    load_dotenv()
    vt_key = os.getenv("VT_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")

    if args.input == "-":
        lines = sys.stdin.readlines()
    else:
        with open(args.input, encoding="utf-8") as f:
            lines = f.readlines()

    iocs, skipped = parse_input(lines)
    if not iocs:
        print("no valid IOCs found in input", file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        for entry in iocs:
            print(f"{entry['ioc']}  ->  {entry['type']}")
        if skipped:
            print(f"skipped: {skipped}", file=sys.stderr)
        return

    if not vt_key and not abuse_key:
        print("no API keys set - copy .env.example to .env and add VT_API_KEY / ABUSEIPDB_API_KEY", file=sys.stderr)
        sys.exit(1)

    results = enrich(iocs, vt_key, abuse_key, args.delay, args.max_age)
    report = markdown_report(results, skipped)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"report written to {args.output}", file=sys.stderr)
    else:
        print(report)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    if args.csv:
        write_csv(results, args.csv)


if __name__ == "__main__":
    main()
