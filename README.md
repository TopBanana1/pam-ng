# pamng
**Parsed Address Mapper – Next Generation**  
Flexible, fast, and script-friendly parser for Nmap `.gnmap` and `.xml` outputs.

`pamng` reads Nmap scan results and outputs filtered, formatted lists for reporting or as input to other tools (e.g., `httpx`, `nuclei`, `gowitness`).

---

## Features
- **Supports both `.gnmap` and `.xml`**
  - Auto-detects format.
  - XML parsing includes product, version, extrainfo, CPEs, OS guess.
- **Version-safe `.gnmap` parsing**
  - Handles commas and `/` characters inside version strings.
- **IPv6 support** with correct URL formatting (`[IPv6]:PORT`).
- **Flexible templating**
  - Output tokens: `{IP}`, `{PORT}`, `{PROTO}`, `{SERVICE}`, `{VERSION}`, `{HOSTNAME}`, `{URL}`, `{SERVICE_INFO}`, `{CPE}`, `{OS}`, `{SEP}`.
  - Presets: `ip`, `service`, `service_version`, `url`, `ip_port`, `triplet`, `full`.
- **Filtering**
  - Regex filters for service, port, and protocol.
  - Pick services/ports interactively with `fzf`.
  - `--web` mode filters for HTTP(S) services.
  - `--well-known` fills blank services from common port mappings.
- **Profiles**
  - `httpx` – Clean URL list for `httpx`.
  - `nuclei` – Prefer hostnames; collapse defaults for `nuclei` templates.
  - `gowitness` – Screenshot targets from URLs.
- **Output formats**
  - Plain text (template-based), JSONL (`--json`), CSV (`--csv`).
  - NUL-terminated (`--print0`) for `xargs -0`.
- **Grouping**
  - Group by IP with aggregated services/URLs (`--group ip`).
- **Performance**
  - Fast single-pass parsing.
  - Streaming mode (`--stream`) for immediate output.
  - Index pre-scan only when needed (disable with `--no-index`).
- **Robustness**
  - Strict input validation.
  - Graceful empty result handling.
  - Deterministic sorting (`LC_ALL=C`).

---

## Installation
```bash
# Clone repository
git clone https://github.com/yourname/pamng.git
cd pamng

# Make executable
chmod +x pamng

# Optionally move to PATH
sudo mv pamng /usr/local/bin/
```

---

## Usage
```bash
pamng [INPUT.gnmap|INPUT.xml|-] [options]
```

### Common Examples
```bash
# Extract all open HTTP(S) URLs from GNMAP
pamng scan.gnmap --web

# Output for httpx (URL list)
pamng scan.xml --profile httpx > targets.txt

# Nuclei: prefer hostnames, collapse default ports
pamng scan.gnmap --profile nuclei > nuclei_targets.txt

# Group services by host
pamng scan.xml --group ip

# JSON for jq filtering
pamng scan.xml --json | jq -r 'select(.service|test("ssh")) | .ip'

# Pick services interactively with fzf
pamng scan.gnmap --pick-services
```

---

## Options
| Option | Description |
|--------|-------------|
| `-o`, `--output FILE` | Append output to file |
| `-f`, `--format STR`  | Template or preset (`ip`, `service`, `service_version`, `url`, `ip_port`, `triplet`, `full`) |
| `--pick-services`     | fzf picker for services |
| `--pick-ports`        | fzf picker for ports |
| `-s`, `--service REGEX` | Filter by service name |
| `-p`, `--port REGEX`  | Filter by port |
| `--proto REGEX`       | Filter by protocol |
| `--web`               | Only HTTP(S) services; format defaults to `{URL}` |
| `-i`, `--ignore-case` | Case-insensitive filters |
| `--no-unique`         | Disable deduplication |
| `--no-sort`           | Preserve input order |
| `--prefer-hostname`   | Use hostname in `{URL}` if present |
| `--well-known`        | Fill missing services from common ports |
| `--json`              | Output JSONL |
| `--csv`               | Output CSV |
| `--no-header`         | Omit CSV header |
| `--sep CHAR`          | CSV separator (default: `,`) |
| `--print0`            | NUL-terminate output |
| `--group ip`          | Group output by IP |
| `--stream`            | Stream results without sorting/deduplication |
| `--index`             | Force index build for pickers |
| `--no-index`          | Disable index build |
| `--profile NAME`      | Profile for tool output: `httpx`, `nuclei`, `gowitness` |
| `-v`, `--verbose`     | Increase verbosity |
| `-h`, `--help`        | Show help |

---

## Templates
You can use any combination of tokens in `--format`. Example:
```bash
pamng scan.gnmap -f "{IP}:{PORT} ({SERVICE} {VERSION})"
```
Available tokens:
- `{IP}`, `{PORT}`, `{PROTO}`, `{SERVICE}`, `{VERSION}`
- `{HOSTNAME}`, `{URL}`, `{SERVICE_INFO}`, `{CPE}`, `{OS}`
- `{SEP}` – replaced with the CSV separator

---

## Well-Known Ports Map
Used with `--well-known` to fill missing service names:
```
80     -> http
443    -> https
8080   -> http
8443   -> https
...
```

---

## Dependencies
- `awk` (POSIX, `mawk` or `gawk`)
- [`fzf`](https://github.com/junegunn/fzf) (for interactive pickers)
- [`xmlstarlet`](http://xmlstar.sourceforge.net/) (only for XML input)

---

## License
MIT License – see [LICENSE](LICENSE) for details.
