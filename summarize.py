#!/usr/bin/env python3
"""Print a human-readable summary table from check_status.py's JSON output.

Example:
  python cpe_map.py products.csv --vendor-alias aliases.json | \\
    python check_status.py - --eol-alias eol_aliases.json | \\
    python summarize.py -
"""
import json
import sys


def severity_counts(vulns):
    if not isinstance(vulns, list):
        return f"error: {vulns.get('error')}"
    counts = {}
    for v in vulns:
        counts[v["severity"]] = counts.get(v["severity"], 0) + 1
    return ", ".join(f"{k}:{v}" for k, v in sorted(counts.items())) or "none found"


def eol_summary(eol):
    if not eol.get("tracked"):
        return "not tracked on endoflife.date"
    if eol.get("matched_cycle") is None:
        return "tracked, but no matching release cycle found"
    verdict = "EOL" if eol["is_eol"] else "not EOL"
    return f"cycle {eol['matched_cycle']}, {verdict} (date: {eol['eol_date']})"


def print_summary(rows, out=sys.stdout):
    for r in rows:
        vulns = r["vulnerabilities"]
        total = len(vulns) if isinstance(vulns, list) else 0
        print(f"{r['product']} {r['version']}", file=out)
        print(f"  vulns: {severity_counts(vulns)}  (total {total})", file=out)
        print(f"  eol:   {eol_summary(r['eol'])}", file=out)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: summarize.py <check_status.py output file, or '-' for stdin>")
    rows = json.load(sys.stdin) if sys.argv[1] == "-" else json.load(open(sys.argv[1], encoding="utf-8"))
    print_summary(rows)


def demo():
    import io

    sample = [
        {
            "product": "Tomcat",
            "version": "9.0.65",
            "vulnerabilities": [{"severity": "HIGH"}, {"severity": "HIGH"}, {"severity": "LOW"}],
            "eol": {"tracked": True, "matched_cycle": "9.0", "is_eol": False, "eol_date": "2027-03-31"},
        },
        {
            "product": "Rocket.Chat",
            "version": "4.13.0.0",
            "vulnerabilities": [],
            "eol": {"tracked": False},
        },
    ]
    buf = io.StringIO()
    print_summary(sample, out=buf)
    output = buf.getvalue()
    assert "HIGH:2, LOW:1" in output
    assert "not EOL (date: 2027-03-31)" in output
    assert "not tracked on endoflife.date" in output
    print("demo: all checks passed")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        demo()
    else:
        main()
