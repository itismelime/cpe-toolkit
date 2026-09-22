#!/usr/bin/env python3
"""Build/update a local offline cache of OSV.dev + endoflife.date data for check_status.py --offline.

Downloads the FULL public datasets (not filtered to any specific product), so the
sync itself never reveals what software you run. check_status.py --offline then
matches your products against this local cache with no further network calls.

The first sync downloads everything (~2.5GB for OSV). After that, re-running this
script only fetches what changed since the last sync (via OSV's modified_id.csv),
not the whole database again. Use --full to force a full re-download.

Examples:
  python sync_offline.py                  # first run: full sync; later runs: incremental
  python sync_offline.py --cache-dir ./cache
  python sync_offline.py --full           # force a full OSV re-download
"""
import argparse
import io
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone

OSV_ALL_ZIP_URL = "https://storage.googleapis.com/osv-vulnerabilities/all.zip"
OSV_MODIFIED_CSV_URL = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
OSV_RECORD_URL = "https://storage.googleapis.com/osv-vulnerabilities/{eco_id}.json"
EOL_ALL_SLUGS_URL = "https://endoflife.date/api/all.json"
EOL_PRODUCT_URL = "https://endoflife.date/api/{slug}.json"

DEFAULT_CACHE_DIR = os.path.expanduser("~/.cache/cpe-toolkit")

# Above this many changed records, an incremental sync stops being much cheaper
# than a full one — the gap since the last sync is probably too large.
INCREMENTAL_WARN_THRESHOLD = 100_000


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


def get_meta(conn, key):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def set_meta(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))


def utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


def package_names_in_record(vuln):
    """Every distinct (lowercased) package name referenced by a vuln record's 'affected' list."""
    names = set()
    for affected in vuln.get("affected", []):
        name = (affected.get("package") or {}).get("name")
        if name:
            names.add(name.lower())
    return names


def store_vuln(conn, vuln):
    """Insert/replace one vuln record and its package-name index entries. Idempotent."""
    vuln_id = vuln.get("id")
    if not vuln_id:
        return False
    conn.execute("INSERT OR REPLACE INTO vulns (id, data) VALUES (?, ?)", (vuln_id, json.dumps(vuln)))
    conn.execute("DELETE FROM package_index WHERE vuln_id = ?", (vuln_id,))
    conn.executemany(
        "INSERT INTO package_index (name, vuln_id) VALUES (?, ?)",
        [(n, vuln_id) for n in package_names_in_record(vuln)],
    )
    return True


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
            if store_vuln(conn, vuln):
                count += 1
            if count % progress_every == 0:
                conn.commit()
                print(f"  indexed {count} vulnerability records...", file=sys.stderr)
    conn.commit()
    return count


def sync_osv_full(conn, url=OSV_ALL_ZIP_URL):
    """Download and index the entire OSV export. Needed once; sync_osv_incremental covers later runs."""
    started_at = utcnow_iso()
    print(f"Downloading OSV data from {url} ...", file=sys.stderr)
    conn.execute("DELETE FROM vulns")
    conn.execute("DELETE FROM package_index")
    conn.commit()
    with urllib.request.urlopen(url, timeout=300) as resp:
        zip_bytes = resp.read()
    print(f"Downloaded {len(zip_bytes) / 1_000_000:.1f} MB, indexing...", file=sys.stderr)
    count = index_zip_bytes(zip_bytes, conn)
    set_meta(conn, "osv_synced_at", started_at)
    conn.commit()
    print(f"Indexed {count} OSV vulnerability records.", file=sys.stderr)


def sync_osv_incremental(conn, csv_url=OSV_MODIFIED_CSV_URL, record_url=OSV_RECORD_URL):
    """Fetch only the OSV records modified since the last sync, via modified_id.csv
    (newest-first: <ISO timestamp>,<ECOSYSTEM>/<ID> per line). Much cheaper than a
    full re-download once the cache is already close to current."""
    last = get_meta(conn, "osv_synced_at")
    if last is None:
        raise ValueError("no prior osv_synced_at — run a full sync first")
    started_at = utcnow_iso()
    cutoff = datetime.fromisoformat(last)

    print("Checking OSV for changes since last sync...", file=sys.stderr)
    to_update = []
    with urllib.request.urlopen(csv_url, timeout=60) as resp:
        for raw_line in resp:
            line = raw_line.decode("utf-8").strip()
            if not line:
                continue
            ts_str, eco_id = line.split(",", 1)
            modified = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if modified <= cutoff:
                break  # sorted newest-first: everything after this is already synced
            to_update.append(eco_id)

    to_update = list(dict.fromkeys(to_update))  # dedup, keep order
    if not to_update:
        print("Already up to date.", file=sys.stderr)
        set_meta(conn, "osv_synced_at", started_at)
        conn.commit()
        return

    if len(to_update) > INCREMENTAL_WARN_THRESHOLD:
        print(
            f"  {len(to_update)} records changed since last sync — that's a lot; "
            "--full may be faster than this many individual requests.",
            file=sys.stderr,
        )

    print(f"Fetching {len(to_update)} changed records...", file=sys.stderr)
    count = 0
    for i, eco_id in enumerate(to_update, 1):
        try:
            with urllib.request.urlopen(record_url.format(eco_id=eco_id), timeout=15) as resp:
                vuln = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue  # withdrawn/removed record
            raise
        if store_vuln(conn, vuln):
            count += 1
        if i % 500 == 0:
            conn.commit()
            print(f"  fetched {i}/{len(to_update)}...", file=sys.stderr)

    set_meta(conn, "osv_synced_at", started_at)
    conn.commit()
    print(f"Updated {count} OSV vulnerability records.", file=sys.stderr)


def sync_osv(conn, force_full=False, url=OSV_ALL_ZIP_URL):
    """Full sync if there's no prior cache (or force_full), incremental otherwise."""
    if force_full or get_meta(conn, "osv_synced_at") is None:
        sync_osv_full(conn, url=url)
    else:
        sync_osv_incremental(conn)


def http_get_json(url, timeout=15):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read())


def sync_eol(conn):
    """endoflife.date has no incremental/modified-since API, but this is ~477 small
    requests total (not 2.5GB), so a full re-fetch each time is cheap enough to keep."""
    started_at = utcnow_iso()
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
    set_meta(conn, "eol_synced_at", started_at)
    conn.commit()
    print(f"Synced {len(slugs)} endoflife.date products.", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR, help=f"where to store offline.db (default: {DEFAULT_CACHE_DIR})")
    parser.add_argument("--skip-osv", action="store_true", help="skip OSV sync, endoflife.date only")
    parser.add_argument("--skip-eol", action="store_true", help="skip endoflife.date sync, OSV only")
    parser.add_argument("--full", action="store_true", help="force a full OSV re-download instead of an incremental update")
    args = parser.parse_args()

    conn = init_db(db_path_for(args.cache_dir))
    if not args.skip_osv:
        sync_osv(conn, force_full=args.full)
    if not args.skip_eol:
        sync_eol(conn)
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

    # store_vuln is idempotent and re-indexes package names on update
    with tempfile.TemporaryDirectory() as tmp:
        conn = init_db(os.path.join(tmp, "offline.db"))
        store_vuln(conn, {"id": "T-1", "affected": [{"package": {"name": "old-name"}}]})
        store_vuln(conn, {"id": "T-1", "affected": [{"package": {"name": "new-name"}}]})
        names = [r[0] for r in conn.execute("SELECT name FROM package_index WHERE vuln_id = 'T-1'")]
        assert names == ["new-name"]

        set_meta(conn, "osv_synced_at", "2020-01-01T00:00:00+00:00")
        assert get_meta(conn, "osv_synced_at") == "2020-01-01T00:00:00+00:00"
        assert get_meta(conn, "nonexistent") is None
        conn.close()
    print("demo: all checks passed")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        demo()
    else:
        main()
