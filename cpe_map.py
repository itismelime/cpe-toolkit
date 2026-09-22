#!/usr/bin/env python3
"""Map vendor/product/version rows (CSV) to CPE 2.3 strings (JSON).

Examples:
  python cpe_map.py products.csv -o cpes.json
  python cpe_map.py products.json --vendor-alias aliases.json --dry-run
"""
import argparse
import csv
import json
import re
import sys

# CPE 2.3 formatted-string reserved characters (escaped with backslash).
_RESERVED = re.compile(r'[!"#$%&\'()*+,/:;<=>?@\[\]^`{|}~\\]')


def normalize_cpe_field(value: str) -> str:
    """Lowercase, space->underscore, escape reserved chars; blank -> '*'."""
    if not value or not value.strip():
        return "*"
    value = value.strip().lower().replace(" ", "_")
    return _RESERVED.sub(lambda m: "\\" + m.group(0), value)


def resolve_vendor(vendor: str, alias_map: dict) -> str:
    """Case-insensitive lookup of raw vendor in alias_map; falls back to vendor itself."""
    return alias_map.get(vendor.strip().lower(), vendor) if vendor else vendor


def build_cpe(vendor: str, product: str, version: str, alias_map: dict = None) -> str:
    vendor = resolve_vendor(vendor, alias_map or {})
    v, p, ver = (normalize_cpe_field(x) for x in (vendor, product, version))
    return f"cpe:2.3:a:{v}:{p}:{ver}:*:*:*:*:*:*:*"


def map_rows(rows, alias_map: dict = None):
    return [
        {
            "vendor": row.get("vendor", ""),
            "product": row.get("product", ""),
            "version": row.get("version", ""),
            "cpe": build_cpe(row.get("vendor", ""), row.get("product", ""), row.get("version", ""), alias_map),
        }
        for row in rows
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input_file", help="CSV or JSON file with vendor,product,version rows")
    parser.add_argument("-o", "--output", help="output JSON file (default: stdout)")
    parser.add_argument(
        "--vendor-alias",
        help="JSON file mapping raw vendor name -> canonical vendor (e.g. {\"Microsoft Corporation\": \"microsoft\"})",
    )
    parser.add_argument("--dry-run", action="store_true", help="print result to stdout, never write -o's file")
    args = parser.parse_args()

    alias_map = {}
    if args.vendor_alias:
        with open(args.vendor_alias, encoding="utf-8") as f:
            alias_map = {k.strip().lower(): v for k, v in json.load(f).items()}

    with open(args.input_file, newline="", encoding="utf-8") as f:
        if args.input_file.lower().endswith(".json"):
            rows = map_rows(json.load(f), alias_map)
        else:
            rows = map_rows(csv.DictReader(f), alias_map)

    text = json.dumps(rows, indent=2)
    if args.output and not args.dry_run:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)


def demo():
    assert normalize_cpe_field("Apache Tomcat") == "apache_tomcat"
    assert normalize_cpe_field("") == "*"
    assert normalize_cpe_field("C++") == "c\\+\\+"
    assert build_cpe("Apache", "Tomcat", "9.0.65") == "cpe:2.3:a:apache:tomcat:9.0.65:*:*:*:*:*:*:*"
    assert build_cpe("Vendor", "Product", "") == "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"
    aliases = {"microsoft corporation": "microsoft"}
    assert build_cpe("Microsoft Corporation", "Windows", "11", aliases) == "cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*"
    print("demo: all checks passed")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        demo()
    else:
        main()
