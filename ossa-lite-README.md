# ossa-lite

A single-file, read-only demo of OSSA (Open Source Security Assessment).
It scans the Ubuntu system it runs on and writes one self-contained HTML
report, a CycloneDX 1.6 SBOM, and per-component package manifests.
Nothing is installed, nothing is modified, nothing leaves the machine.

> This is the demo precursor to the full OSSA (a Go binary — see
> `ossa-spec.md` in ThinGuy/ossa). The full build adds CVE/OVAL scanning,
> SPDX, bundle signing, GeoLite2, and the upgrade-drift view.

## Prerequisites

### Required

| What | Why | Check |
|------|-----|-------|
| Ubuntu 18.04 or later | provenance and component analysis are Ubuntu-specific | `lsb_release -ds` |
| Python 3.6+ (stdlib only) | preinstalled on every supported release | `python3 -V` |
| Populated apt lists | provenance, census, security-update checks | `sudo apt update` beforehand |
| A writable current directory | report, SBOM, and manifests are written to `.` | `cd` somewhere writable |

No pip packages, no snaps, no network access at runtime.

### Strongly recommended

| What | Why |
|------|-----|
| root (`sudo`) | resolving every process's binary, reading `/etc/shadow` (counts and hash algorithms only), kernel lockdown, AppArmor profiles, Secure Boot state. Without root the script runs anyway and marks what it could not see. |

### Optional

| What | Enables | Install |
|------|---------|---------|
| `lz4` | reading lz4-compressed apt indices (default on noble minimized/cloud images) | `sudo apt install lz4` — usually already present |
| `geoip-bin` + `geoip-database` | country flags and `--geo-allow` verdicts on the Connections card | `sudo apt install geoip-bin geoip-database` |
| a MaxMind-format `.mmdb` + a reader | newer geo data than the legacy db; preferred when both exist | data: GeoLite2 (via `geoipupdate`) or db-ip Country Lite, auto-found in `/var/lib/GeoIP`, `/usr/share/GeoIP`, `/usr/local/share/GeoIP`, `/opt/geoip`, or pass `--geoip-db PATH`. Reader: `python3-maxminddb` **or** `mmdb-bin` |
| color-emoji font on the **viewing** machine | rendering the country flags | stock on Ubuntu desktop, macOS, Windows |

Anything optional that is missing degrades gracefully and is named in the
report's honesty note — the report never silently pretends.

**Geo troubleshooting:** the `maxminddb` Python module is only the
*reader* — it still needs a database file. And a `pip install --user
maxminddb` done as your own user is invisible to `sudo python3` (root's
home has no `~/.local` copy); install it system-wide
(`sudo apt install python3-maxminddb`) or use `mmdb-bin` instead. The
warnings name exactly which piece is missing.

## Quick start

```
scp ossa-lite.py demo-box:
ssh demo-box
sudo apt update          # refresh the lists ossa-lite will read
sudo python3 ossa-lite.py
# open ossa-report-<hostname>.html in any browser
```

Run without sudo and it explains what it needs, offers to re-exec under
sudo, and otherwise continues with reduced evidence.

## Usage

```
sudo python3 ossa-lite.py [--out FILE] [--geo-allow CC,CC] [--yes] [--read-scope]
```

| Flag | Meaning |
|------|---------|
| `--out FILE` | report path (default `ossa-report-<hostname>.html`) |
| `--geo-allow US,GB,DE` | countries considered expected; connections elsewhere get a red "outside geography" verdict and a Geo-violations stat card |
| `--read-scope` | print every path the tool reads, then exit (show this to the customer first) |
| `--yes` | skip the sudo prompt and run with current privileges |

## Outputs (all in the current directory)

| File | Contents |
|------|----------|
| `ossa-report-<host>.html` | the full report, self-contained, mode 0600 |
| `ossa-report-<host>.cdx.json` | CycloneDX 1.6 SBOM; `supplier` carries the provenance verdict, mode 0600 |
| `ubuntu-<Rel>_<component>_<arch>.installed.manifest` | installed packages per component, `name<TAB>version` |
| `ubuntu-<Rel>_<component>_<arch>.all.manifest` | every package available per component from the Canonical archive indices |
| `ubuntu-<Rel>_other_<arch>.installed.manifest` | installed packages not attributable to the Canonical archive (PPA, upstream, unknown) — only when non-empty |

Runtime: roughly 5–10 seconds on a typical server.

## What it will not do

- run `apt update`, or change any system state — it reads what is there
  and warns when the lists are missing or more than 30 days old
- send anything anywhere — geo lookups use a local db or are skipped
- claim a package is "unused" — absence of evidence is reported as
  "no evidence of use", never as safe-to-remove
- replace a CIS/STIG benchmark — the hardening card is a 60-second
  posture read; the Ubuntu Security Guide row points at the real thing

## Demo tips

- Open with `--read-scope` in front of the customer — transparency about
  privilege is the product.
- The Connections card is the attention-getter; `--geo-allow US` makes it
  sing. An "unowned binary, investigate now" row on a box the customer
  thought was clean does your talking for you.
- The census card pairs with the tier recommendation: available →
  installed → in use is the right-sizing story in three columns.
