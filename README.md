# cpe-toolkit

[![License check](https://github.com/itismelime/cpe-toolkit/actions/workflows/license-check.yml/badge.svg)](https://github.com/itismelime/cpe-toolkit/actions/workflows/license-check.yml)

Four scripts, no dependencies (Python stdlib only), MIT licensed:

- `cpe_map.py` — map `vendor,product,version` rows to CPE 2.3 strings.
- `check_status.py` — take `cpe_map.py`'s output and check each product for known vulnerabilities (OSV.dev) and EoL/EoS status (endoflife.date). Add `--offline` to check without ever sending your product names to those services — see `sync_offline.py`.
- `sync_offline.py` — build a local cache of OSV.dev + endoflife.date's full public datasets for private/offline checking. First run downloads everything; later runs only fetch what changed.
- `summarize.py` — turn `check_status.py`'s output into a human-readable per-product summary table.

`aliases.json`, `eol_aliases.json`, and `test.json` in this repo are working example data (Rocket.Chat, Tomcat, OpenSSL, NGINX, Jenkins) — try the full pipeline below against them.

## cpe_map.py

### Usage

```
python3 cpe_map.py INPUT_FILE [-o OUTPUT.json] [--vendor-alias ALIASES.json] [--dry-run]
```

- `INPUT_FILE` — CSV (`vendor,product,version` header) or JSON (list of `{"vendor", "product", "version"}` objects). Detected by `.json` extension, otherwise treated as CSV.
- `-o OUTPUT.json` — write result here instead of stdout.
- `--vendor-alias ALIASES.json` — JSON object mapping raw vendor name to canonical vendor (case-insensitive), e.g. `{"Microsoft Corporation": "microsoft"}`.
- `--dry-run` — print to stdout, never write `-o`'s file. Useful for previewing.

Run with no arguments to execute the built-in self-check instead.

### Examples

**products.csv**
```csv
vendor,product,version
Apache,Tomcat,9.0.65
Microsoft Corporation,Windows,11
```

**aliases.json**
```json
{"Microsoft Corporation": "microsoft"}
```

```
$ python3 cpe_map.py products.csv --vendor-alias aliases.json
[
  {
    "vendor": "Apache",
    "product": "Tomcat",
    "version": "9.0.65",
    "cpe": "cpe:2.3:a:apache:tomcat:9.0.65:*:*:*:*:*:*:*"
  },
  {
    "vendor": "Microsoft Corporation",
    "product": "Windows",
    "version": "11",
    "cpe": "cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*"
  }
]
```

Write to a file instead of stdout:
```
python3 cpe_map.py products.csv -o cpes.json
```

Preview what would be written, without touching the file:
```
python3 cpe_map.py products.csv -o cpes.json --dry-run
```

JSON input instead of CSV:
```
python3 cpe_map.py products.json
```

### Notes

- Fields are normalized for CPE 2.3: lowercased, spaces → underscores, reserved characters (`: ; ( ) ! " # $ % & ' * + , / < = > ? @ [ ] ^ \` { | } ~ \`) backslash-escaped, blank → `*`.
- Always builds part `a` (application) CPEs — no support for `h` (hardware) or `o` (OS) parts.
- Formats a CPE string; it does not verify the result against the real NVD CPE dictionary.

## sync_offline.py — private/offline vuln & EoL checking

By default, `check_status.py` sends each product's name and version to OSV.dev and endoflife.date, which necessarily tells those services (and anyone able to observe that traffic) what software you run. If you'd rather not disclose that, `sync_offline.py` downloads each source's **entire public dataset** once — not filtered to your products, so the download itself reveals nothing about your inventory — into a local SQLite cache. `check_status.py --offline` then matches against that cache with no further network calls naming your specific software.

### Usage

```
python3 sync_offline.py [--cache-dir DIR] [--skip-osv] [--skip-eol] [--full]
```

- `--cache-dir DIR` — where to store `offline.db` (default `~/.cache/cpe-toolkit`).
- `--skip-osv` — skip OSV sync and sync endoflife.date only.
- `--skip-eol` — skip endoflife.date (small, ~477 products) and sync OSV only.
- `--full` — force a full OSV re-download instead of an incremental update (see below).

**Only the first run downloads everything.** The initial OSV sync is a full download (~**2.5GB**, all ecosystems). Every run after that fetches only what changed since the last sync, via OSV's `modified_id.csv` (which lists every currently-known record's last-modified time, newest first) — typically a few hundred to a few thousand small requests instead of re-downloading the whole dataset. `check_status.py --offline` itself never triggers a re-sync or any network call at all; only re-running `sync_offline.py` does, and only for what's changed. Run it periodically (e.g. weekly, via cron) to keep the cache fresh. endoflife.date has no equivalent "what changed" API, but its ~477 products is small enough that a full re-fetch each run is still cheap. Run `sync_offline.py` with no arguments to execute the built-in self-check instead (uses an in-memory synthetic dataset, no network calls).

### Example

```
python3 sync_offline.py
python3 check_status.py test.json --eol-alias eol_aliases.json --offline
```

## check_status.py

### Usage

```
python3 check_status.py INPUT_FILE [-o OUTPUT.json] [--eol-alias EOL_ALIASES.json] [--severity {low,medium,high,critical}] [--offline] [--cache-dir DIR]
```

- `INPUT_FILE` — a `cpe_map.py` JSON output file, or `-` to read from stdin (so it chains directly onto `cpe_map.py`).
- `-o OUTPUT.json` — write result here instead of stdout.
- `--eol-alias EOL_ALIASES.json` — JSON object mapping product name to its [endoflife.date](https://endoflife.date) product slug (case-insensitive), e.g. `{"Tomcat": "tomcat"}`. Needed because slugs don't always match product names, and some products (e.g. Rocket.Chat) aren't tracked there at all.
- `--severity {low,medium,high,critical}` — only include vulnerabilities at or above this severity. Severity is taken from the source's own label when present (e.g. GHSA advisories), otherwise computed as a CVSS v3 base score from the vulnerability's CVSS vector; vulnerabilities with neither are labeled `UNKNOWN` and excluded whenever a `--severity` filter is set.
- `--offline` — match against a local cache built by `sync_offline.py` instead of calling OSV.dev/endoflife.date live, so your specific product/vendor/version never leaves this machine. Requires `--cache-dir` to point at an existing cache (see below) — errors clearly if it's missing.
- `--cache-dir DIR` — offline cache location (default `~/.cache/cpe-toolkit`), must match what you passed to `sync_offline.py`.

Requires internet access (queries OSV.dev and endoflife.date live) unless `--offline` is set. Run with no arguments to execute the built-in self-check instead (pure logic only, no network calls).

### Examples

Chain directly onto `cpe_map.py`:
```
python3 cpe_map.py products.csv --vendor-alias aliases.json | python3 check_status.py - --eol-alias eol_aliases.json
```

Or from a saved file:
```
python3 cpe_map.py products.csv -o cpes.json --vendor-alias aliases.json
python3 check_status.py cpes.json --eol-alias eol_aliases.json -o report.json
```

Each output row looks like:
```json
{
  "vendor": "Apache Software Foundation",
  "product": "Tomcat",
  "version": "9.0.65",
  "cpe": "cpe:2.3:a:apache:tomcat:9.0.65:*:*:*:*:*:*:*",
  "vulnerabilities": [
    {"id": "GHSA-...", "summary": "...", "severity": "HIGH", "published": "...", "aliases": ["CVE-..."], "references": ["..."]}
  ],
  "eol": {
    "tracked": true,
    "slug": "tomcat",
    "matched_cycle": "9.0",
    "latest": "9.0.122",
    "is_eol": false,
    "eol_date": "2027-03-31"
  }
}
```

### Notes

- Vulnerabilities come from OSV.dev, queried by product name (lowercased) and version, with no ecosystem specified — this lets it cover non-package-manager software (Tomcat, nginx, OpenSSL) by searching across all ecosystems OSV knows, but means results are name-matched rather than precisely version-filtered the way an ecosystem-scoped query would be. Check each result's `references` if precision matters.
- EoL/EoS comes from endoflife.date, matched to the closest release-cycle prefix of your version (e.g. `9.0.65` → cycle `9.0`). `"tracked": false` means the product isn't in endoflife.date's dataset (with or without an alias).
- `eol_date` may be `null` even when `"is_eol": true` — some products are flagged EoL without a specific date on record.
- Duplicate `(product, version)` rows in one input file are only looked up once per run (results are reused) — repeating a row doesn't cost extra requests.

## summarize.py

### Usage

```
python3 summarize.py INPUT_FILE
```

- `INPUT_FILE` — a `check_status.py` JSON output file, or `-` to read from stdin.

Run with no arguments to execute the built-in self-check instead.

### Example

```
$ python3 summarize.py test_report.json
Rocket.Chat 4.13.0.0
  vulns: HIGH:1  (total 1)
  eol:   not tracked on endoflife.date
Tomcat 9.0.65
  vulns: CRITICAL:28, HIGH:137, LOW:1, MEDIUM:29, UNKNOWN:135  (total 330)
  eol:   cycle 9.0, not EOL (date: 2027-03-31)
```

## Full pipeline

Using the example data already in this repo:

```
python3 cpe_map.py test.json --vendor-alias aliases.json \
  | python3 check_status.py - --eol-alias eol_aliases.json \
  | python3 summarize.py -
```

`test_report.json` is a saved `check_status.py` run over `test.json`, committed as a worked example.
