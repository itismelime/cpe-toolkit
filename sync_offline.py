#!/usr/bin/env python3
"""Build a local offline cache of OSV.dev + endoflife.date data for check_status.py --offline.

Downloads the FULL public datasets (not filtered to any specific product), so the
sync itself never reveals what software you run. check_status.py --offline then
matches your products against this local cache with no further network calls.

Examples:
  python sync_offline.py                  # full sync (~2.5GB OSV download)
  python sync_offline.py --cache-dir ./cache
"""
import argparse
import io
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
import zipfile

OSV_ALL_ZIP_URL = "https://storage.googleapis.com/osv-vulnerabilities/all.zip"
EOL_ALL_SLUGS_URL = "https://endoflife.date/api/all.json"
EOL_PRODUCT_URL = "https://endoflife.date/api/{slug}.json"

DEFAULT_CACHE_DIR = os.path.expanduser("~/.cache/cpe-toolkit")


def db_path_for(cache_dir):
    return os.path.join(cache_dir, "offline.db")


def init_db(db_path):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS vulns (id TEXT PRIMARY KEY, data TEXT);
        CREATE TABLE IF NOT EXISTS package_index (name TEXT, vuln_id TEXT);
        CREATE INDEX IF NOT EXISTS idx_package_name ON package_index(name);
        CREATE TABLE IF NOT EXISTS eol (slug TEXT PRIMARY KEY, data TEXT);
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
        """
    )
    return conn


def package_names_in_record(vuln):
    """Every distinct (lowercased) package name referenced by a vuln record's 'affected' list."""
    names = set()
    for affected in vuln.get("affected", []):
        name = (affected.get("package") or {}).get("name")
        if name:
            names.add(name.lower())
    return names


def index_zip_bytes(zip_bytes, conn, progress_every=20000):
    """Parse every vuln JSON entry in a zip file's bytes and index it into conn. Returns count indexed."""
    count = 0
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                vuln = json.loads(zf.read(name))
            except (json.JSONDecodeError, zipfile.BadZipFile):
                continue
            vuln_id = vuln.get("id")
            if not vuln_id:
                continue
            conn.execute(
                "INSERT OR REPLACE INTO vulns (id, data) VALUES (?, ?)", (vuln_id, json.dumps(vuln))
            )
            conn.executemany(
                "INSERT INTO package_index (name, vuln_id) VALUES (?, ?)",
                [(n, vuln_id) for n in package_names_in_record(vuln)],
            )
            count += 1
            if count % progress_every == 0:
                conn.commit()
                print(f"  indexed {count} vulnerability records...", file=sys.stderr)
    conn.commit()
    return count


def sync_osv(conn, url=OSV_ALL_ZIP_URL):
    print(f"Downloading OSV data from {url} ...", file=sys.stderr)
    conn.execute("DELETE FROM vulns")
    conn.execute("DELETE FROM package_index")
    conn.commit()
    with urllib.request.urlopen(url, timeout=300) as resp:
        zip_bytes = resp.read()
    print(f"Downloaded {len(zip_bytes) / 1_000_000:.1f} MB, indexing...", file=sys.stderr)
    count = index_zip_bytes(zip_bytes, conn)
    print(f"Indexed {count} OSV vulnerability records.", file=sys.stderr)


def http_get_json(url, timeout=15):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read())


def sync_eol(conn):
    print("Downloading endoflife.date product list...", file=sys.stderr)
    slugs = http_get_json(EOL_ALL_SLUGS_URL)
    conn.execute("DELETE FROM eol")
    for i, slug in enumerate(slugs, 1):
        try:
            cycles = http_get_json(EOL_PRODUCT_URL.format(slug=slug))
        except urllib.error.URLError:
            continue
        conn.execute("INSERT OR REPLACE INTO eol (slug, data) VALUES (?, ?)", (slug, json.dumps(cycles)))
        if i % 50 == 0:
            conn.commit()
            print(f"  synced {i}/{len(slugs)} products...", file=sys.stderr)
    conn.commit()
    print(f"Synced {len(slugs)} endoflife.date products.", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR, help=f"where to store offline.db (default: {DEFAULT_CACHE_DIR})")
    parser.add_argument("--skip-osv", action="store_true", help="skip the ~2.5GB OSV download, sync endoflife.date only")
    parser.add_argument("--skip-eol", action="store_true", help="skip endoflife.date sync, OSV only")
    args = parser.parse_args()

    conn = init_db(db_path_for(args.cache_dir))
    if not args.skip_osv:
        sync_osv(conn)
    if not args.skip_eol:
        sync_eol(conn)
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('synced_at', ?)", (str(int(time.time())),))
    conn.commit()
    conn.close()
    print(f"Done. Offline cache ready at {db_path_for(args.cache_dir)}", file=sys.stderr)


def demo():
    import tempfile

    fake_vuln = {
        "id": "TEST-0001",
        "summary": "fake",
        "affected": [{"package": {"name": "Widget", "ecosystem": "Test"}}],
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Test/TEST-0001.json", json.dumps(fake_vuln))
        zf.writestr("Test/not-json.txt", "ignore me")

    with tempfile.TemporaryDirectory() as tmp:
        conn = init_db(os.path.join(tmp, "offline.db"))
        count = index_zip_bytes(buf.getvalue(), conn)
        assert count == 1
        rows = conn.execute("SELECT vuln_id FROM package_index WHERE name = ?", ("widget",)).fetchall()
        assert rows == [("TEST-0001",)]
        data = json.loads(conn.execute("SELECT data FROM vulns WHERE id = ?", ("TEST-0001",)).fetchone()[0])
        assert data["summary"] == "fake"
        conn.close()

    assert package_names_in_record({"affected": [{"package": {"name": "A"}}, {"package": {"name": "a"}}]}) == {"a"}
    print("demo: all checks passed")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        demo()
    else:
        main()
