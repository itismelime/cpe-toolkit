# cpe_map.py

Map `vendor,product,version` rows to CPE 2.3 strings.

No dependencies (Python stdlib only).

## Usage

```
python3 cpe_map.py INPUT_FILE [-o OUTPUT.json] [--vendor-alias ALIASES.json] [--dry-run]
```

- `INPUT_FILE` — CSV (`vendor,product,version` header) or JSON (list of `{"vendor", "product", "version"}` objects). Detected by `.json` extension, otherwise treated as CSV.
- `-o OUTPUT.json` — write result here instead of stdout.
- `--vendor-alias ALIASES.json` — JSON object mapping raw vendor name to canonical vendor (case-insensitive), e.g. `{"Microsoft Corporation": "microsoft"}`.
- `--dry-run` — print to stdout, never write `-o`'s file. Useful for previewing.

Run with no arguments to execute the built-in self-check instead.

## Examples

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

## Notes

- Fields are normalized for CPE 2.3: lowercased, spaces → underscores, reserved characters (`: ; ( ) ! " # $ % & ' * + , / < = > ? @ [ ] ^ \` { | } ~ \`) backslash-escaped, blank → `*`.
- Always builds part `a` (application) CPEs — no support for `h` (hardware) or `o` (OS) parts.
- Formats a CPE string; it does not verify the result against the real NVD CPE dictionary.
