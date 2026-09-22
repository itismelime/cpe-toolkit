#!/usr/bin/env python3
"""Check vulnerabilities (OSV.dev) and EoL/EoS status (endoflife.date) for cpe_map.py output.

Examples:
  python cpe_map.py products.csv | python check_status.py -
  python check_status.py cpes.json --eol-alias eol_aliases.json -o report.json
"""
import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import date

OSV_URL = "https://api.osv.dev/v1/query"
EOL_URL = "https://endoflife.date/api/{slug}.json"

SEVERITY_LEVELS = ["UNKNOWN", "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

_CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_CVSS3_PR_WEIGHTS = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}


def _roundup(x):
    """CVSS spec's Roundup: nearest 0.1, biased up."""
    int_x = round(x * 100000)
    if int_x % 10000 == 0:
        return int_x / 100000
    return (int_x // 10000 + 1) / 10


def cvss3_base_score(vector):
    """CVSS v3.x base score (0.0-10.0) from a 'CVSS:3.x/AV:.../...' vector string."""
    m = dict(p.split(":") for p in vector.split("/") if ":" in p)
    scope = m["S"]
    av, ac, ui = _CVSS3_WEIGHTS["AV"][m["AV"]], _CVSS3_WEIGHTS["AC"][m["AC"]], _CVSS3_WEIGHTS["UI"][m["UI"]]
    pr = _CVSS3_PR_WEIGHTS[scope][m["PR"]]
    c, i, a = _CVSS3_WEIGHTS["C"][m["C"]], _CVSS3_WEIGHTS["I"][m["I"]], _CVSS3_WEIGHTS["A"][m["A"]]

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    base = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    return _roundup(min(base, 10.0))


def score_to_severity(score):
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def vuln_severity(vuln_raw):
    """Prefer the source's own severity label (e.g. GHSA's database_specific.severity);
    fall back to computing a CVSS v3 base score; UNKNOWN if neither is available."""
    label = (vuln_raw.get("database_specific") or {}).get("severity")
    if isinstance(label, str) and label.upper() in SEVERITY_LEVELS:
        return label.upper()
    for sev in vuln_raw.get("severity", []):
        if sev.get("type") == "CVSS_V3" and sev.get("score"):
            return score_to_severity(cvss3_base_score(sev["score"]))
    return "UNKNOWN"


def http_post_json(url, payload, timeout=15):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def http_get_json(url, timeout=15):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def query_osv(product, version, min_severity=None):
    """Best-effort: no ecosystem given, so OSV name-matches across all ecosystems
    rather than precisely filtering by version range. Inspect 'affected' yourself."""
    try:
        data = http_post_json(OSV_URL, {"package": {"name": product.lower()}, "version": version})
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"error": str(e)}
    min_rank = SEVERITY_LEVELS.index(min_severity) if min_severity else 0
    vulns = []
    for v in data.get("vulns", []):
        severity = vuln_severity(v)
        if SEVERITY_LEVELS.index(severity) < min_rank:
            continue
        vulns.append(
            {
                "id": v.get("id"),
                "summary": v.get("summary") or (v.get("details") or "")[:200],
                "severity": severity,
                "published": v.get("published"),
                "aliases": v.get("aliases", []),
                "references": [r["url"] for r in v.get("references", []) if r.get("url")][:3],
            }
        )
    return vulns


def match_cycle(version, cycles):
    """Find the endoflife.date cycle matching version, trying longest prefix first
    (e.g. '9.0.65' -> '9.0.65', then '9.0', then '9')."""
    parts = str(version).split(".")
    for n in range(len(parts), 0, -1):
        candidate = ".".join(parts[:n])
        for cycle in cycles:
            if str(cycle.get("cycle")) == candidate:
                return cycle
    return None


def parse_eol_status(cycle):
    eol = cycle.get("eol")
    if isinstance(eol, bool):
        return {"is_eol": eol, "eol_date": None}
    if isinstance(eol, str):
        return {"is_eol": date.fromisoformat(eol) <= date.today(), "eol_date": eol}
    return {"is_eol": None, "eol_date": None}


def resolve_eol_slug(product, alias_map):
    key = product.strip().lower()
    return alias_map.get(key, key.replace(" ", "-"))


def query_eol(product, version, alias_map):
    slug = resolve_eol_slug(product, alias_map)
    try:
        cycles = http_get_json(EOL_URL.format(slug=slug))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"tracked": None, "slug": slug, "error": str(e)}
    if cycles is None:
        return {"tracked": False, "slug": slug}
    cycle = match_cycle(version, cycles)
    if cycle is None:
        return {"tracked": True, "slug": slug, "matched_cycle": None}
    status = parse_eol_status(cycle)
    return {
        "tracked": True,
        "slug": slug,
        "matched_cycle": cycle.get("cycle"),
        "latest": cycle.get("latest"),
        "is_eol": status["is_eol"],
        "eol_date": status["eol_date"],
    }


def check_rows(rows, alias_map, min_severity=None):
    results = []
    for row in rows:
        product, version = row.get("product", ""), row.get("version", "")
        results.append(
            {
                **row,
                "vulnerabilities": query_osv(product, version, min_severity),
                "eol": query_eol(product, version, alias_map),
            }
        )
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input_file", help="cpe_map.py JSON output file, or '-' for stdin")
    parser.add_argument("-o", "--output", help="output JSON file (default: stdout)")
    parser.add_argument("--eol-alias", help="JSON file mapping product name -> endoflife.date slug")
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        help="only include vulnerabilities at or above this severity",
    )
    args = parser.parse_args()

    alias_map = {}
    if args.eol_alias:
        with open(args.eol_alias, encoding="utf-8") as f:
            alias_map = {k.strip().lower(): v for k, v in json.load(f).items()}

    min_severity = args.severity.upper() if args.severity else None
    rows = json.load(sys.stdin) if args.input_file == "-" else json.load(open(args.input_file, encoding="utf-8"))
    text = json.dumps(check_rows(rows, alias_map, min_severity), indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)


def demo():
    assert match_cycle("9.0.65", [{"cycle": "9.0"}, {"cycle": "8.5"}])["cycle"] == "9.0"
    assert match_cycle("16", [{"cycle": "16"}, {"cycle": "15"}])["cycle"] == "16"
    assert match_cycle("99.9", [{"cycle": "9.0"}]) is None

    assert parse_eol_status({"eol": False}) == {"is_eol": False, "eol_date": None}
    assert parse_eol_status({"eol": True}) == {"is_eol": True, "eol_date": None}
    past = parse_eol_status({"eol": "2000-01-01"})
    assert past == {"is_eol": True, "eol_date": "2000-01-01"}
    future = parse_eol_status({"eol": "2999-01-01"})
    assert future == {"is_eol": False, "eol_date": "2999-01-01"}

    assert resolve_eol_slug("Tomcat", {}) == "tomcat"
    assert resolve_eol_slug("Rocket.Chat Support", {"rocket.chat support": "rocketchat"}) == "rocketchat"

    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8  # known reference vector
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert score_to_severity(9.8) == "CRITICAL"
    assert score_to_severity(0.0) == "NONE"
    assert vuln_severity({"database_specific": {"severity": "HIGH"}}) == "HIGH"
    assert vuln_severity({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}) == "CRITICAL"
    assert vuln_severity({}) == "UNKNOWN"
    print("demo: all checks passed")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        demo()
    else:
        main()
