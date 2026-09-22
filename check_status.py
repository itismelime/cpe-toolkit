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


def query_osv(product, version):
    """Best-effort: no ecosystem given, so OSV name-matches across all ecosystems
    rather than precisely filtering by version range. Inspect 'affected' yourself."""
    try:
        data = http_post_json(OSV_URL, {"package": {"name": product.lower()}, "version": version})
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"error": str(e)}
    vulns = []
    for v in data.get("vulns", []):
        vulns.append(
            {
                "id": v.get("id"),
                "summary": v.get("summary") or (v.get("details") or "")[:200],
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


def check_rows(rows, alias_map):
    results = []
    for row in rows:
        product, version = row.get("product", ""), row.get("version", "")
        results.append(
            {
                **row,
                "vulnerabilities": query_osv(product, version),
                "eol": query_eol(product, version, alias_map),
            }
        )
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input_file", help="cpe_map.py JSON output file, or '-' for stdin")
    parser.add_argument("-o", "--output", help="output JSON file (default: stdout)")
    parser.add_argument("--eol-alias", help="JSON file mapping product name -> endoflife.date slug")
    args = parser.parse_args()

    alias_map = {}
    if args.eol_alias:
        with open(args.eol_alias, encoding="utf-8") as f:
            alias_map = {k.strip().lower(): v for k, v in json.load(f).items()}

    rows = json.load(sys.stdin) if args.input_file == "-" else json.load(open(args.input_file, encoding="utf-8"))
    text = json.dumps(check_rows(rows, alias_map), indent=2)

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
    print("demo: all checks passed")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        demo()
    else:
        main()
