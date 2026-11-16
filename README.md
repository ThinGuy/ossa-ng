# OSSA — Open Source Security Assessment

**An honest look at what is really installed, really used, and really
supportable on an Ubuntu system.**

`dpkg -l` is an optimist. It will happily list 1,412 packages on a server
that is actually running 187, including 23 that are just leftover config
files and 9 that didn't come from Ubuntu at all. People make expensive
decisions off that list. OSSA exists so they don't have to.

## The origin story

A rep once spotted a single universe package on a customer estate and
quoted Pro with Apps coverage — an extra $1,750 per node, per year. The
package was `ntp`. Its drop-in replacement, `chrony`, sits in main,
covered by the base tier, and has been the Ubuntu default since 18.04.
The customer did the math before we did.

OSSA is the tool that makes that conversation impossible to get wrong.

## What it answers

1. **What is actually installed** — not merely listed by dpkg
2. **What is actually used** — live processes, bound sockets, modified
   configs. Evidence, not vibes
3. **Where it actually came from** — Canonical archive, Pro/ESM, PPA,
   upstream, or "nobody knows", resolved per installed version, offline
4. **What that means** — supportability, the right Pro tier, security
   posture, crypto and hardening, and an SBOM whose `supplier` field
   tells the truth

## House rules

- **It never says "unused."** OSSA can prove a package *is* used; it can
  almost never prove one isn't. Absence of evidence is reported as
  "no evidence of use" — and that's final.
- **It suggests. It never sells.** Every recommendation ships with the
  package list that drives it, including when the recommendation is
  "buy less."
- **It reads. It never phones home.** One command, root (announced,
  explained, and listable via `--read-scope`), zero network calls,
  everything written locally. Paranoia is a feature in our market.
- **It knows its own limits.** Signals that can lie (looking at you,
  atime) label their reliability per mount, and every report carries an
  honesty note naming what the tool could not see.

## Try it today

A single-file, stdlib-only demo lives in [`demo/`](demo/):

```
sudo apt update
sudo python3 demo/ossa-lite.py --geo-allow US
```

~6 seconds later: a report in the Canonical style, a CycloneDX SBOM, and
per-component package manifests. See [`demo/ossa-lite-README.md`](demo/ossa-lite-README.md)
for prerequisites and the full tour.


## Lineage

Successor to [canonical/ossa](https://github.com/canonical/ossa) — same
mission, fewer ceilings. GPL-3.0, like its ancestor.

---

*OSSA suggests. It never sells. The selling part is your job.*
