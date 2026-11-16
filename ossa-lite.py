#!/usr/bin/env python3
# ossa-lite — Open Source Security Assessment, demo edition.
#
# A single-file, stdlib-only preview of OSSA (ThinGuy/ossa). Real collection,
# real analysis, one self-contained HTML report in the OSSA/boom chrome.
# The production tool is a Go binary (see ossa-spec.md); this exists so a
# field engineer can demo the idea on any Ubuntu 18.04+ box today:
#
#   scp ossa-lite.py box:  &&  ssh box sudo python3 ossa-lite.py
#
# Honesty rules carried over from the spec, non-negotiable:
#   - absence of evidence is "no evidence of use", never "unused"
#   - atime is never trusted without per-mount reliability
#   - anything this demo cannot do is said plainly in the report
#
# Reads only. Writes the report (and a CycloneDX SBOM) to the current
# directory. Sends nothing anywhere.

import argparse
import glob
import gzip
import hashlib
import ipaddress
import json
import lzma
import os
import pwd
import re
import shutil
import subprocess
import sys
import time

VERSION = "0.4.2-lite"
DEMO_PRICE_NODE_YEAR = 1750  # illustrative only — pricing is config, not code

READ_SCOPE = [
    "/etc/os-release", "/etc/hostname", "/etc/passwd", "/etc/shadow (count of empty passwords only)",
    "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf",
    "/etc/ufw/ufw.conf", "/etc/apt/apt.conf.d/20auto-upgrades",
    "/etc/systemd/system/*.wants/*",
    "/var/lib/dpkg/status", "/var/lib/dpkg/info/*.list",
    "/var/lib/apt/extended_states", "/var/lib/apt/lists/*_Release", "/var/lib/apt/lists/*_Packages*",
    "/var/lib/snapd/state.json",
    "/proc/*/exe, /proc/*/comm, /proc/*/cmdline, /proc/*/status, /proc/*/fd/*",
    "/proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6",
    "/proc/self/mountinfo", "/proc/sys/crypto/fips_enabled",
    "/home/*/.config/*, /home/*/.local/share/*, /root/.config/*",
    "conffiles named in dpkg status (md5 comparison)",
    "/bin /sbin /usr/bin /usr/sbin /usr/local/*bin /opt (SUID/SGID scan)",
    "/etc/machine-info, /sys/class/dmi/id/sys_vendor, /sys/class/dmi/id/product_name",
    "GeoIP country db if present (GeoLite2-Country.mmdb or geoiplookup) — remote IPs resolved locally, never sent anywhere",
    "/proc/cmdline, /proc/sys/kernel/* and /proc/sys/net/* hardening sysctls, /proc/sys/fs/protected_*",
    "/sys/kernel/security/lockdown, /sys/kernel/security/apparmor/profiles, /sys/module/apparmor/parameters/enabled",
    "/sys/firmware/efi/efivars/SecureBoot-*, /sys/class/tpm, /sys/block/dm-*/dm/uuid (LUKS detection)",
    "/etc/ssh/ssh_host_*_key.pub (public keys only), /etc/ssl/openssl.cnf",
    "/etc/machine-id (or /var/lib/dbus/machine-id)",
]

W = []  # warnings surfaced verbatim in the report

def warn(msg):
    W.append(msg)
    print("  ! %s" % msg, file=sys.stderr)

def step(msg):
    print("  - %s" % msg, file=sys.stderr)

# --------------------------------------------------------------------------
# debian version comparison (dpkg algorithm)
# --------------------------------------------------------------------------

def _order(c):
    if c == "~": return -1
    if c.isdigit(): return 0
    if c.isalpha(): return ord(c)
    return ord(c) + 256

def _verrevcmp(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1; j += 1
        while i < len(a) and a[i] == "0": i += 1
        while j < len(b) and b[j] == "0": j += 1
        first_diff = 0
        while i < len(a) and j < len(b) and a[i].isdigit() and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1; j += 1
        if i < len(a) and a[i].isdigit(): return 1
        if j < len(b) and b[j].isdigit(): return -1
        if first_diff:
            return first_diff
    return 0

def _split_ver(v):
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        if e.isdigit():
            epoch = int(e)
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, ""
    return epoch, up, rev

def dpkg_vercmp(a, b):
    ea, ua, ra = _split_ver(a)
    eb, ub, rb = _split_ver(b)
    if ea != eb:
        return ea - eb
    c = _verrevcmp(ua, ub)
    if c:
        return c
    return _verrevcmp(ra, rb)

# --------------------------------------------------------------------------
# collectors (capture + joins only; judgments happen in analyze())
# --------------------------------------------------------------------------

def host_info():
    osr = {}
    try:
        for line in open("/etc/os-release"):
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                osr[k] = v.strip('"')
    except OSError as e:
        warn("could not read /etc/os-release: %s" % e)
    u = os.uname()
    users = 0
    try:
        for p in pwd.getpwall():
            if (p.pw_uid == 0 or p.pw_uid >= 1000) and not p.pw_shell.endswith(("nologin", "false")):
                users += 1
    except Exception:
        pass
    pretty_host = ""
    try:
        for line in open("/etc/machine-info"):
            if line.startswith("PRETTY_HOSTNAME="):
                pretty_host = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    hw = ""
    try:
        vend = open("/sys/class/dmi/id/sys_vendor").read().strip()
        prod = open("/sys/class/dmi/id/product_name").read().strip()
        hw = " ".join(x for x in (vend, prod) if x and x.lower() not in ("to be filled by o.e.m.",))
    except OSError:
        pass
    mid = ""
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            mid = open(p).read().strip()
            break
        except OSError:
            pass
    deb_arch = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "armhf",
                "ppc64le": "ppc64el", "s390x": "s390x", "riscv64": "riscv64"}.get(u.machine, u.machine)
    return {
        "hostname": pretty_host or u.nodename, "nodename": u.nodename,
        "kernel": u.release, "arch": u.machine, "hw": hw,
        "mid": mid or "unknown", "deb_arch": deb_arch,
        "pretty": osr.get("PRETTY_NAME", "unknown"),
        "codename": osr.get("VERSION_CODENAME", osr.get("UBUNTU_CODENAME", "?")),
        "is_ubuntu": osr.get("ID", "") == "ubuntu", "users": users,
    }

def dpkg_status():
    pkgs = {}
    path = "/var/lib/dpkg/status"
    try:
        cur = None
        for raw in open(path, encoding="utf-8", errors="replace"):
            line = raw.rstrip("\n")
            if line.startswith("Package:"):
                cur = {"name": line[8:].strip(), "conffiles": []}
                pkgs[cur["name"]] = cur
            elif cur is None:
                continue
            elif line.startswith("Status:"):
                cur["status"] = line[7:].strip()
            elif line.startswith("Version:"):
                cur["version"] = line[8:].strip()
            elif line.startswith("Architecture:"):
                cur["arch"] = line[13:].strip()
            elif line.startswith("Conffiles:"):
                cur["in_conf"] = True
            elif line.startswith(" ") and cur.get("in_conf"):
                parts = line.split()
                if len(parts) >= 2 and parts[0].startswith("/"):
                    cur["conffiles"].append((parts[0], parts[1]))
            elif line and not line.startswith(" "):
                cur["in_conf"] = False
    except OSError as e:
        warn("could not read %s: %s — package analysis unavailable" % (path, e))
    return pkgs

def extended_states():
    auto = set()
    try:
        name = None
        for line in open("/var/lib/apt/extended_states"):
            if line.startswith("Package:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Auto-Installed:") and line.split(":")[1].strip() == "1" and name:
                auto.add(name)
    except OSError:
        warn("no /var/lib/apt/extended_states — manual-vs-dependency unavailable")
    return auto

def _open_index(path):
    if path.endswith(".lz4"):
        if shutil.which("lz4"):
            p = subprocess.run(["lz4", "-dc", path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            if p.returncode == 0:
                return p.stdout.decode("utf-8", "replace").splitlines()
        return None
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace").read().splitlines()
    if path.endswith(".xz"):
        return lzma.open(path, "rt", encoding="utf-8", errors="replace").read().splitlines()
    return open(path, encoding="utf-8", errors="replace")

def apt_indices(installed_names):
    """Returns (hits, n_files, avail):
    hits:  name -> [(version, origin_class, component, suite)] for installed names
    avail: component -> {name: newest_version} across Canonical-archive indices"""
    hits = {}
    avail = {}
    files = [f for f in glob.glob("/var/lib/apt/lists/*_Packages*")
             if "partial" not in f and re.search(r"_Packages(\.(gz|xz|lz4))?$", f)]
    if not files:
        warn("apt lists are empty (run apt update) — provenance will read unknown")
        return hits, 0, avail
    skipped = 0
    newest = 0
    for f in files:
        newest = max(newest, os.path.getmtime(f))
        base = re.sub(r"_Packages(\.(gz|xz|lz4))?$", "", f)
        m = re.search(r"_dists_([^_]+)_(.+)_binary-[^_]+$", base)
        suite, component = (m.group(1), m.group(2)) if m else ("?", "?")
        origin = ""
        for rel in (re.sub(r"_(.+)_binary-[^_]+$", "_Release", base),
                    re.sub(r"_binary-[^_]+$", "", base) + "_Release",
                    base.split("_dists_")[0] + "_dists_" + suite + "_Release" if "_dists_" in base else None,
                    base.split("_dists_")[0] + "_dists_" + suite + "_InRelease" if "_dists_" in base else None):
            if rel and os.path.exists(rel):
                try:
                    for line in open(rel, encoding="utf-8", errors="replace"):
                        if line.startswith("Origin:"):
                            origin = line.split(":", 1)[1].strip(); break
                        if line.startswith("Package:"):
                            break
                except OSError:
                    pass
                if origin:
                    break
        lo = origin.lower()
        host = os.path.basename(base).split("_")[0]
        if "esm" in lo or "esm" in host or "fips" in lo:
            oc = "pro"
        elif origin == "Ubuntu":
            oc = "archive"
        elif lo.startswith("lp-ppa") or "ppa.launchpad" in host:
            oc = "ppa"
        elif origin or "_dists_" in base:
            oc = "thirdparty"
        else:
            oc = "unknown"
        lines = _open_index(f)
        if lines is None:
            skipped += 1
            continue
        census = (oc == "archive" and component in ("main", "universe", "multiverse", "restricted"))
        comp_avail = avail.setdefault(component, {}) if census else None
        name = None
        for line in lines:
            if line.startswith("Package:"):
                name = line[8:].strip()
            elif line.startswith("Version:") and name:
                ver = line[8:].strip()
                if name in installed_names:
                    hits.setdefault(name, []).append((ver, oc, component, suite))
                if census:
                    cur = comp_avail.get(name)
                    if cur is None or dpkg_vercmp(ver, cur) > 0:
                        comp_avail[name] = ver
    if skipped:
        warn("%d lz4-compressed indices skipped (lz4 tool missing) — provenance partial" % skipped)
    if newest and (time.time() - newest) > 30 * 86400:
        warn("apt lists are %d days old — provenance and update checks may be stale"
             % int((time.time() - newest) / 86400))
    return hits, len(files), avail

def processes():
    procs, denied = [], 0
    for d in glob.glob("/proc/[0-9]*"):
        pid = os.path.basename(d)
        try:
            exe = os.readlink(d + "/exe").split(" (deleted)")[0]
        except PermissionError:
            denied += 1
            exe = ""
        except OSError:
            continue
        try:
            comm = open(d + "/comm").read().strip()
        except OSError:
            comm = "?"
        procs.append({"pid": int(pid), "comm": comm, "exe": exe})
    if denied:
        warn("%d processes unreadable without root — usage evidence is incomplete" % denied)
    return procs

def _hexip(h):
    try:
        if len(h) == 8:
            return str(ipaddress.IPv4Address(bytes(reversed(bytes.fromhex(h)))))
        words = [h[i:i + 8] for i in range(0, 32, 8)]
        b = b"".join(bytes(reversed(bytes.fromhex(w))) for w in words)
        a = ipaddress.IPv6Address(b)
        return str(a.ipv4_mapped or a)
    except Exception:
        return "?"

def sockets():
    listeners, established = [], []
    inode_pid = {}
    for d in glob.glob("/proc/[0-9]*"):
        try:
            for fd in os.listdir(d + "/fd"):
                try:
                    t = os.readlink("%s/fd/%s" % (d, fd))
                    if t.startswith("socket:["):
                        inode_pid[t[8:-1]] = int(os.path.basename(d))
                except OSError:
                    pass
        except OSError:
            pass
    for proto, path in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6"),
                        ("udp", "/proc/net/udp"), ("udp6", "/proc/net/udp6")):
        try:
            lines = open(path).read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            f = line.split()
            if len(f) < 10:
                continue
            lip, lport = f[1].split(":"); rip, rport = f[2].split(":")
            st = f[3]
            rec = {"proto": proto.rstrip("6"),
                   "lip": _hexip(lip), "lport": int(lport, 16),
                   "rip": _hexip(rip), "rport": int(rport, 16),
                   "pid": inode_pid.get(f[9])}
            if (proto.startswith("tcp") and st == "0A") or (proto.startswith("udp") and st == "07"):
                listeners.append(rec)
            elif proto.startswith("tcp") and st == "01":
                established.append(rec)
    return listeners, established

def owners_for(paths):
    """Resolve path -> owning package for exactly the paths we care about."""
    need = set(paths)
    owner = {}
    if not need:
        return owner
    for f in glob.glob("/var/lib/dpkg/info/*.list"):
        pkg = os.path.basename(f)[:-5].split(":")[0]
        try:
            for line in open(f, encoding="utf-8", errors="replace"):
                p = line.rstrip("\n")
                if p in need:
                    owner[p] = pkg
        except OSError:
            pass
    return owner

def conffile_drift(pkgs):
    modified = {}
    for name, p in pkgs.items():
        for path, md5 in p.get("conffiles", []):
            try:
                h = hashlib.md5(open(path, "rb").read()).hexdigest()
                if h != md5:
                    modified.setdefault(name, []).append(path)
            except OSError:
                pass
    return modified

def systemd_wants():
    units = []
    for link in glob.glob("/etc/systemd/system/*.wants/*"):
        units.append(os.path.basename(link))
    return units

def user_state(installed_names):
    found = {}
    homes = glob.glob("/home/*") + ["/root"]
    for h in homes:
        for sub in (".config", ".local/share"):
            try:
                for entry in os.listdir(os.path.join(h, sub)):
                    if entry in installed_names:
                        found.setdefault(entry, set()).add(h)
            except OSError:
                pass
    return found

def mounts():
    out = []
    real_fs = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs", "overlay"}
    try:
        for line in open("/proc/self/mountinfo"):
            parts = line.split()
            if "-" not in parts:
                continue
            dash = parts.index("-")
            fstype, source = parts[dash + 1], parts[dash + 2]
            if fstype not in real_fs and not source.startswith("/dev"):
                continue
            opts = parts[5].split(",")
            atime = "noatime" if "noatime" in opts else ("relatime" if "relatime" in opts else "strictatime")
            out.append({"target": parts[4], "fstype": fstype, "atime": atime})
    except OSError as e:
        warn("could not read mountinfo: %s" % e)
    return out

def snaps():
    out = []
    try:
        data = json.load(open("/var/lib/snapd/state.json"))
        for name, s in (data.get("data", {}).get("snaps", {}) or {}).items():
            seq = s.get("sequence") or [{}]
            out.append({"name": name, "channel": s.get("channel", "?"),
                        "revision": str(seq[-1].get("revision", "?"))})
    except Exception:
        pass
    return out

def suid_scan():
    hits = set()
    roots = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt"]
    for root in roots:
        for dirpath, dirs, files in os.walk(root):
            for fn in files:
                p = os.path.join(dirpath, fn)
                try:
                    st = os.lstat(p)
                    if st.st_mode & 0o6000 and not os.path.islink(p):
                        hits.add(os.path.realpath(p))
                except OSError:
                    pass
    return sorted(hits)

def sshd_effective():
    """OpenSSH semantics: first obtained value wins; Includes processed in place."""
    vals = {}
    def walk(path):
        try:
            for line in open(path):
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split(None, 1)
                key = parts[0].lower()
                val = parts[1] if len(parts) > 1 else ""
                if key == "include":
                    for g in sorted(glob.glob(val if val.startswith("/") else "/etc/ssh/" + val)):
                        walk(g)
                elif key not in vals:
                    vals[key] = val
        except OSError:
            pass
    walk("/etc/ssh/sshd_config")
    return vals

def security_misc():
    out = {}
    try:
        out["fips"] = open("/proc/sys/crypto/fips_enabled").read().strip() == "1"
    except OSError:
        out["fips"] = False
    out["livepatch"] = os.path.exists("/var/snap/canonical-livepatch") or os.path.exists("/snap/canonical-livepatch")
    out["ufw"] = False
    try:
        out["ufw"] = "ENABLED=yes" in open("/etc/ufw/ufw.conf").read()
    except OSError:
        pass
    out["unattended"] = False
    try:
        t = open("/etc/apt/apt.conf.d/20auto-upgrades").read()
        out["unattended"] = 'Unattended-Upgrade "1"' in t
    except OSError:
        pass
    out["uid0"] = []
    out["empty_pw"] = -1
    try:
        for p in pwd.getpwall():
            if p.pw_uid == 0 and p.pw_name != "root":
                out["uid0"].append(p.pw_name)
    except Exception:
        pass
    out["hash_algos"] = {}
    out["legacy_hash"] = []
    try:
        n = 0
        for line in open("/etc/shadow"):
            f = line.split(":")
            if len(f) < 2:
                continue
            h = f[1]
            if h == "":
                n += 1
            elif h and h not in ("*", "!", "!!", "!*") and not h.startswith("!$"):
                if h.startswith("$y$") or h.startswith("$7$"):
                    algo = "yescrypt"
                elif h.startswith("$6$"):
                    algo = "sha512"
                elif h.startswith("$5$"):
                    algo = "sha256"
                elif h.startswith("$2"):
                    algo = "bcrypt"
                elif h.startswith("$1$"):
                    algo = "md5"
                else:
                    algo = "descrypt"
                out["hash_algos"][algo] = out["hash_algos"].get(algo, 0) + 1
                if algo in ("md5", "descrypt"):
                    out["legacy_hash"].append(f[0])
        out["empty_pw"] = n
    except OSError:
        warn("cannot read /etc/shadow without root — password hash and empty-password checks skipped")
    return out

def _read(path):
    try:
        return open(path).read().strip()
    except OSError:
        return None

def _sysctl(name):
    v = _read("/proc/sys/" + name.replace(".", "/"))
    try:
        return int(v)
    except (TypeError, ValueError):
        return None

def ssh_hostkeys():
    import base64
    keys = []
    for pub in sorted(glob.glob("/etc/ssh/ssh_host_*_key.pub")):
        try:
            parts = open(pub).read().split()
            alg, blob = parts[0], base64.b64decode(parts[1])
            def rd(off):
                ln = int.from_bytes(blob[off:off + 4], "big")
                return blob[off + 4:off + 4 + ln], off + 4 + ln
            if alg == "ssh-rsa":
                _, off = rd(0); _, off = rd(off); n, off = rd(off)
                keys.append(("rsa", int.from_bytes(n, "big").bit_length()))
            elif "ed25519" in alg:
                keys.append(("ed25519", 256))
            elif "ecdsa" in alg:
                m = re.search(r"nistp(\d+)", alg)
                keys.append(("ecdsa", int(m.group(1)) if m else 0))
            elif "dss" in alg or "dsa" in alg:
                keys.append(("dsa", 1024))
        except Exception:
            pass
    return keys

WEAK_SSH = ("3des", "arcfour", "-cbc", "hmac-md5", "hmac-sha1-96", "hmac-sha1,", "group1-sha1", "group14-sha1")

def crypto_hardening(installed_names, sshd):
    c = {}
    cmdline = _read("/proc/cmdline") or ""
    c["fips"] = (_read("/proc/sys/crypto/fips_enabled") == "1") or (" fips=1" in " " + cmdline)
    c["hostkeys"] = ssh_hostkeys()
    weak = []
    for key in ("ciphers", "macs", "kexalgorithms", "hostkeyalgorithms"):
        val = (sshd.get(key) or "").lower()
        if val and any(w in val + "," for w in WEAK_SSH):
            weak.append(key)
    c["ssh_weak"] = weak
    c["ssh_pinned"] = [k for k in ("ciphers", "macs", "kexalgorithms") if sshd.get(k)]
    c["tls_min"], c["seclevel"] = None, None
    try:
        for line in open("/etc/ssl/openssl.cnf"):
            s = line.split("#")[0].strip()
            m = re.match(r"MinProtocol\s*=\s*(\S+)", s)
            if m:
                c["tls_min"] = m.group(1)
            m = re.search(r"SECLEVEL=(\d)", s)
            if m:
                c["seclevel"] = int(m.group(1))
    except OSError:
        pass
    c["luks"] = sum(1 for u in glob.glob("/sys/block/dm-*/dm/uuid")
                    if (_read(u) or "").startswith("CRYPT-LUKS"))
    c["tpm"] = os.path.exists("/sys/class/tpm/tpm0") or os.path.exists("/dev/tpm0")
    if not os.path.isdir("/sys/firmware/efi"):
        c["secureboot"] = "legacy"
    else:
        c["secureboot"] = "unknown"
        for f in glob.glob("/sys/firmware/efi/efivars/SecureBoot-*"):
            try:
                c["secureboot"] = "enabled" if open(f, "rb").read()[-1] == 1 else "disabled"
            except OSError:
                pass
    ld = _read("/sys/kernel/security/lockdown")
    m = re.search(r"\[(\w+)\]", ld or "")
    c["lockdown"] = m.group(1) if m else None
    c["apparmor"] = _read("/sys/module/apparmor/parameters/enabled") == "Y"
    prof = _read("/sys/kernel/security/apparmor/profiles")
    c["aa_enforce"] = prof.count("(enforce)") if prof else None
    c["sysctl"] = {name: _sysctl(name) for name in (
        "kernel.randomize_va_space", "kernel.yama.ptrace_scope", "kernel.kptr_restrict",
        "kernel.dmesg_restrict", "kernel.unprivileged_bpf_disabled",
        "fs.protected_symlinks", "fs.protected_hardlinks", "net.ipv4.tcp_syncookies")}
    c["usg"] = "usg" in installed_names or "usg-cisbenchmark" in installed_names
    c["fips_pkgs"] = sorted(n for n in installed_names if "fips" in n)[:4]
    return c

GEO_DIRS = ["/var/lib/GeoIP", "/usr/share/GeoIP", "/usr/local/share/GeoIP", "/opt/geoip"]

def find_mmdb(override=None):
    """Any usable .mmdb, preferring Country over City over the rest."""
    if override:
        if os.path.exists(override):
            return override
        warn("--geoip-db %s does not exist — falling back to auto-detection" % override)
    cands = []
    for d in GEO_DIRS:
        cands += glob.glob(os.path.join(d, "*.mmdb"))
    def rank(p):
        b = os.path.basename(p).lower()
        return (0 if "country" in b else 1 if "city" in b else 2, b)
    return sorted(cands, key=rank)[0] if cands else None

def geo_resolver(db_override=None):
    """Country lookup, strictly local: mmdb via maxminddb module or mmdblookup,
    else legacy geoiplookup, else none — with warnings that name the missing piece."""
    db = find_mmdb(db_override)
    if db:
        try:
            import maxminddb
            rdr = maxminddb.open_database(db)
            def look(ip, _r=rdr):
                try:
                    d = _r.get(ip) or {}
                    return (d.get("country") or {}).get("iso_code", "") or ""
                except Exception:
                    return ""
            return look, "%s via maxminddb" % os.path.basename(db)
        except ImportError:
            mml = shutil.which("mmdblookup")
            if mml:
                cache = {}
                def look(ip, _db=db, _t=mml):
                    if ip in cache:
                        return cache[ip]
                    cc = ""
                    try:
                        out = subprocess.run([_t, "--file", _db, "--ip", ip, "country", "iso_code"],
                                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                             universal_newlines=True, timeout=3).stdout
                        m = re.search(r'"([A-Z]{2})"', out)
                        cc = m.group(1) if m else ""
                    except Exception:
                        pass
                    cache[ip] = cc
                    return cc
                return look, "%s via mmdblookup" % os.path.basename(db)
            warn("found %s but no reader for it — install python3-maxminddb or mmdb-bin "
                 "(note: a pip --user install of maxminddb is not visible under sudo)" % db)
    g4, g6 = shutil.which("geoiplookup"), shutil.which("geoiplookup6")
    if g4:
        cache = {}
        def look(ip):
            if ip in cache:
                return cache[ip]
            tool = g6 if (":" in ip and g6) else g4
            cc = ""
            try:
                out = subprocess.run([tool, ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     universal_newlines=True, timeout=3).stdout
                m = re.search(r"Edition[^:]*:\s*([A-Z]{2}),", out)
                cc = m.group(1) if m else ""
            except Exception:
                pass
            cache[ip] = cc
            return cc
        return look, "geoiplookup (legacy MaxMind db)"
    if db:
        pass  # already warned about the missing reader above
    else:
        try:
            import maxminddb  # noqa: F401 — reader present, data absent
            warn("maxminddb module is installed but no .mmdb database was found in %s — "
                 "add a GeoLite2/db-ip Country db or pass --geoip-db PATH" % ", ".join(GEO_DIRS))
        except ImportError:
            warn("no local geo source: no .mmdb database, no maxminddb module, no geoiplookup — "
                 "quickest fix: apt install geoip-bin geoip-database")
    return None, ""

def flag(cc):
    if len(cc) == 2 and cc.isalpha():
        return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper())
    return ""

# --------------------------------------------------------------------------
# analysis
# --------------------------------------------------------------------------

SUBSTITUTIONS = {  # curated + sourced; config, not code, in the real build
    "ntp": ("chrony", "main", "default Ubuntu time daemon since 18.04; drop-in replacement"),
    "ntpsec": ("chrony", "main", "default Ubuntu time daemon since 18.04"),
}

def analyze(ctx):
    pkgs = ctx["pkgs"]
    installed = {n: p for n, p in pkgs.items() if p.get("status") == "install ok installed"}
    residual = [n for n, p in pkgs.items() if p.get("status", "").endswith("config-files")]
    broken = [n for n, p in pkgs.items()
              if p.get("status", "").split()[-1:] and p["status"].split()[-1]
              in ("half-configured", "half-installed", "unpacked", "triggers-awaited", "triggers-pending")
              and p.get("status") != "install ok installed"]

    # provenance: exact installed version vs indices
    prov = {}
    sec_updates = {}
    rank = {"archive": 0, "pro": 1, "ppa": 2, "thirdparty": 3}
    for name, p in installed.items():
        v = p.get("version", "")
        entries = ctx["indices"].get(name, [])
        best = None
        for ver, oc, comp, suite in entries:
            if ver == v and (best is None or rank.get(oc, 9) < rank.get(best[0], 9)):
                best = (oc, comp, suite)
            if suite.endswith("-security") and v and dpkg_vercmp(ver, v) > 0:
                cur = sec_updates.get(name)
                if cur is None or dpkg_vercmp(ver, cur) > 0:
                    sec_updates[name] = ver
        prov[name] = best if best else ("unknown", "?", "?")

    # usage evidence
    exes = sorted({pr["exe"] for pr in ctx["procs"] if pr["exe"]}
                  | {os.path.realpath(s) for s in ctx["suid"]}
                  | {"/lib/systemd/system/%s" % u for u in ctx["wants"]}
                  | {"/usr/lib/systemd/system/%s" % u for u in ctx["wants"]})
    owner = owners_for(exes)
    pid_pkg = {}
    in_use = set()
    for pr in ctx["procs"]:
        pkg = owner.get(pr["exe"])
        if pkg:
            base = pkg.split(":")[0]
            pid_pkg[pr["pid"]] = base
            in_use.add(base)
    for rec in ctx["listeners"]:
        if rec["pid"] in pid_pkg:
            in_use.add(pid_pkg[rec["pid"]])
    likely = set()
    for name in ctx["modified"]:
        likely.add(name)
    for u in ctx["wants"]:
        pkg = owner.get("/lib/systemd/system/%s" % u) or owner.get("/usr/lib/systemd/system/%s" % u)
        if pkg:
            likely.add(pkg.split(":")[0])
    for name in ctx["userstate"]:
        likely.add(name)
    likely -= in_use
    likely &= set(installed)
    in_use &= set(installed)

    # component cross-tab (canonical archive/pro only)
    comp_tab = {}
    for name in installed:
        oc, comp, _ = prov[name]
        if oc in ("archive", "pro"):
            c = "main" if comp in ("main", "?") and oc == "archive" else comp
            c = comp if comp != "?" else "main"
            d = comp_tab.setdefault(c, {"installed": 0, "in_use": 0, "likely": 0})
            d["installed"] += 1
            if name in in_use:
                d["in_use"] += 1
            elif name in likely:
                d["likely"] += 1

    # tier logic
    driving = sorted(n for n in (in_use | likely)
                     if prov[n][0] in ("archive", "pro") and prov[n][1] not in ("main", "?"))
    subs = [(n,) + SUBSTITUTIONS[n] for n in driving if n in SUBSTITUTIONS]
    no_sub = [n for n in driving if n not in SUBSTITUTIONS]

    # listeners beyond loopback + unowned
    ext_listen = []
    for rec in ctx["listeners"]:
        ip = rec["lip"]
        if ip in ("127.0.0.1", "::1") or ip.startswith("127."):
            continue
        pkg = pid_pkg.get(rec["pid"])
        exe = next((p["exe"] for p in ctx["procs"] if p["pid"] == rec["pid"]), "")
        ext_listen.append({"rec": rec, "pkg": pkg, "exe": exe,
                           "prov": prov.get(pkg, ("unknown",))[0] if pkg else "none"})
    unowned_suid = sorted(s for s in ctx["suid"] if s not in owner)

    # established connections, classified + geo-resolved (locally)
    geo_look = ctx["geo"][0]
    conns = []
    for rec in ctx["established"]:
        try:
            ip = ipaddress.ip_address(rec["rip"])
            if ip.is_loopback:
                continue
            scope = "internal" if (ip.is_private or ip.is_link_local) else "public"
        except ValueError:
            continue
        pkg = pid_pkg.get(rec["pid"])
        exe = next((p["exe"] for p in ctx["procs"] if p["pid"] == rec["pid"]), "")
        comm = next((p["comm"] for p in ctx["procs"] if p["pid"] == rec["pid"]), "?")
        cc = geo_look(rec["rip"]) if (geo_look and scope == "public") else ""
        conns.append({"remote": "%s:%d" % (rec["rip"], rec["rport"]), "scope": scope, "cc": cc,
                      "comm": comm, "pkg": pkg, "exe": exe,
                      "prov": prov.get(pkg, ("unknown",))[0] if pkg else ("none" if exe else "unresolved")})
    # aggregate duplicate (remote, process) pairs
    agg = {}
    for c in conns:
        key = (c["remote"], c["comm"], c["pkg"], c["prov"], c["scope"])
        if key in agg:
            agg[key]["n"] += 1
        else:
            agg[key] = dict(c, n=1)
    geo_allow = {c.strip().upper() for c in ctx["geo_allow"].split(",") if c.strip()}
    conns = sorted(agg.values(), key=lambda c: (c["scope"] != "public", c["prov"] not in ("none", "unknown")))
    geo_viol = [c for c in conns if geo_allow and c["cc"] and c["cc"] not in geo_allow]
    for c in conns:
        c["geo_viol"] = c in geo_viol

    sec_in_use = sorted(set(sec_updates) & (in_use | likely))
    prov_counts = {}
    for name in installed:
        prov_counts[prov[name][0]] = prov_counts.get(prov[name][0], 0) + 1

    return {
        "installed": installed, "residual": residual, "broken": broken,
        "prov": prov, "prov_counts": prov_counts,
        "in_use": in_use, "likely": likely, "comp_tab": comp_tab,
        "driving": driving, "subs": subs, "no_sub": no_sub,
        "sec_updates": sec_updates, "sec_in_use": sec_in_use,
        "ext_listen": ext_listen, "unowned_suid": unowned_suid, "conns": conns,
        "geo_viol": geo_viol, "auto": ctx["auto"] & set(installed),
    }

# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

CSS = """
@font-face{font-family:"Ubuntu variable";font-style:normal;font-weight:100 800;src:url("https://assets.ubuntu.com/v1/f1ea362b-Ubuntu[wdth,wght]-latin-v0.896a.woff2") format("woff2");font-display:swap;}
@font-face{font-family:"Ubuntu Mono variable";font-style:normal;font-weight:100 800;src:url("https://assets.ubuntu.com/v1/d5fc1819-UbuntuMono[wght]-latin-v0.869.woff2") format("woff2");font-display:swap;}
:root{--orange:#e95420;--dark:#262626;--active:#313131;--bg:#ffffff;--bg-alt:#f7f7f7;--bg-paper:#f3f3f3;
--green:#0e8420;--amber:#f99b11;--red:#c7162b;--gray:#757575;--teal:#0f95a1;
--border:rgba(0,0,0,0.2);--border-lt:rgba(0,0,0,0.1);
--sans:"Ubuntu variable","Ubuntu",-apple-system,"Segoe UI",Roboto,sans-serif;
--mono:"Ubuntu Mono variable","Ubuntu Mono",Consolas,Monaco,Courier,monospace;}
*{margin:0;padding:0;box-sizing:border-box;border-radius:0;}
body{font-family:var(--sans);background:var(--bg-alt);color:#111;font-size:14px;}
a{color:#06c;text-decoration:none;}
.topbar{height:48px;background:var(--dark);display:flex;align-items:center;padding:0 24px;gap:16px;position:sticky;top:0;z-index:10;}
.topbar h1{color:#fff;font-size:18px;font-weight:300;}
.hostbadge{background:rgba(255,255,255,0.2);color:#fff;font-size:12px;padding:2px 8px;font-family:var(--mono);}
.topmeta{color:#bbb;font-size:12px;}
.layout{display:flex;min-height:calc(100vh - 48px);}
.sidebar{width:208px;flex-shrink:0;background:var(--dark);border-left:4px solid var(--orange);display:flex;flex-direction:column;}
.sb-logo{padding:16px;display:flex;align-items:center;gap:8px;}
.sb-logo .mark{width:22px;height:22px;background:var(--orange);flex-shrink:0;}
.sb-logo span{color:#fff;font-size:14px;font-weight:300;white-space:nowrap;}
.sb-head{font-size:10px;text-transform:uppercase;letter-spacing:0.12em;color:#6f6f6f;padding:16px 16px 4px;}
.nav-item{display:flex;align-items:center;gap:8px;padding:8px 16px;font-size:13px;color:#9a9a9a;border-left:2px solid transparent;}
a.nav-item:hover{color:#fff;}
.nav-item.active{background:var(--active);color:#fff;border-left:2px solid var(--orange);}
.sb-version{margin-top:auto;padding:16px;font-size:10px;color:#5c5c5c;}
.content{flex:1;min-width:0;padding:24px;display:flex;flex-direction:column;gap:16px;}
.pagehead{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;}
.pagehead h2{font-size:24px;font-weight:300;}
.pagehead .meta{font-size:12px;color:var(--gray);}
.chip{font-size:10px;font-weight:500;padding:2px 8px;}
.chip.green{background:#e6f2e9;color:var(--green);}
.chip.gray{background:#efefef;color:var(--gray);}
.alert{padding:12px 16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
.alert.red{background:#fbebed;border-left:4px solid var(--red);}
.alert.red strong{color:var(--red);}
.alert.amber{background:#fdf3e1;border-left:4px solid var(--amber);}
.alert.amber strong{color:#b5720c;}
.alert.green{background:#e6f2e9;border-left:4px solid var(--green);}
.alert.green strong{color:var(--green);}
.alert strong{font-weight:500;}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;}
.card{background:#fff;border:1px solid var(--border);box-shadow:0 1px 2px rgba(0,0,0,0.05);padding:16px;}
.stat .label{font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:var(--gray);}
.stat .value{font-size:26px;font-weight:300;margin:2px 0;}
.stat .sub{font-size:11px;color:#9a9a9a;}
.card h3{font-size:14px;font-weight:500;margin-bottom:12px;}
.card h3 .note{font-weight:400;color:var(--gray);font-size:12px;}
.two-col{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:12px;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{background:var(--bg-alt);text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.06em;color:var(--gray);font-weight:500;padding:8px 10px;border-bottom:2px solid var(--border);}
td{padding:9px 10px;border-bottom:1px solid var(--border-lt);vertical-align:middle;}
tr:hover td{background:var(--bg-alt);}
.mono{font-family:var(--mono);font-size:12px;word-break:break-all;}
.badge{display:inline-flex;align-items:center;padding:1px 8px;font-size:11px;white-space:nowrap;}
.b-green{background:#e6f2e9;color:var(--green);}
.b-amber{background:#fdf3e1;color:#b5720c;}
.b-red{background:#fbebed;color:var(--red);}
.b-gray{background:#efefef;color:var(--gray);}
.b-teal{background:#e5f4f5;color:#0b6f78;}
.sq{display:inline-block;width:9px;height:9px;margin-right:6px;}
.provbar{display:flex;height:20px;width:100%;}
.legend{display:flex;gap:16px;flex-wrap:wrap;margin-top:8px;font-size:12px;color:#444;}
.xtab{display:grid;grid-template-columns:88px minmax(0,1fr) 170px;gap:8px 12px;align-items:center;font-size:12px;}
.bar{background:#ececec;height:15px;position:relative;}
.bar .fill{background:#d9d9d9;height:15px;}
.bar .use{position:absolute;top:0;left:0;background:var(--green);height:15px;}
.ciso{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;}
.ciso .card{border-top:3px solid var(--border);}
.ciso .t-red{border-top-color:var(--red);}
.ciso .t-amber{border-top-color:var(--amber);}
.ciso .t-green{border-top-color:var(--green);}
.ciso .t-teal{border-top-color:var(--teal);}
.ciso .k{font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:var(--gray);margin-bottom:4px;}
.ciso .v{font-size:16px;font-weight:400;margin-bottom:4px;}
.ciso .d{font-size:11.5px;color:#666;line-height:1.5;}
.rec{border-left:4px solid var(--green);}
.rec h3{color:var(--green);}
.rec.amber{border-left-color:var(--amber);}
.rec.amber h3{color:#b5720c;}
.subchip{font-family:var(--mono);font-size:11px;background:var(--bg-paper);border:1px solid rgba(0,0,0,0.15);padding:2px 8px;display:inline-block;margin:2px 4px 0 0;}
.honesty{background:#fff;border:1px solid var(--border);border-left:4px solid var(--teal);padding:10px 16px;font-size:12px;color:#444;line-height:1.6;}
.honesty ul{margin:6px 0 0 18px;}
.footer{font-size:11px;color:#9a9a9a;font-family:var(--mono);padding:4px 0 12px;}
"""

def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def badge(cls, txt):
    return '<span class="badge %s">%s</span>' % (cls, esc(txt))

PROV_BADGE = {"archive": ("b-green", "Canonical archive"), "pro": ("b-teal", "Canonical Pro/ESM"),
              "ppa": ("b-amber", "PPA"), "thirdparty": ("b-red", "third-party"),
              "unknown": ("b-gray", "unknown origin"), "none": ("b-red", "unowned binary"),
              "unresolved": ("b-gray", "unresolved")}

def render(host, a, ctx, self_sha):
    n_inst = len(a["installed"])
    n_use, n_likely = len(a["in_use"]), len(a["likely"])
    n_sec, n_sec_use = len(a["sec_updates"]), len(a["sec_in_use"])
    third = a["prov_counts"].get("thirdparty", 0) + a["prov_counts"].get("ppa", 0)
    unknown = a["prov_counts"].get("unknown", 0)

    # ---- alert ----
    pub_unowned = [c for c in a["conns"] if c["scope"] == "public" and c["prov"] == "none"]
    if pub_unowned:
        n_bin = len({c["comm"] for c in pub_unowned})
        n_sess = sum(c["n"] for c in pub_unowned)
        alert = ('red', "%d binar%s owned by no installed package %s outbound connections"
                 % (n_bin, "y" if n_bin == 1 else "ies", "has" if n_sess == 1 else "hold %d" % n_sess),
                 "— see Connections. This is the first thing to explain.")
    elif a["geo_viol"]:
        ccs = sorted({c["cc"] for c in a["geo_viol"]})
        alert = ('red', "%d active connection(s) outside expected geography" % sum(c["n"] for c in a["geo_viol"]),
                 "— destinations in %s. See Connections." % ", ".join("%s %s" % (flag(c), c) for c in ccs))
    elif a["unowned_suid"]:
        alert = ('red', "%d SUID/SGID binaries owned by no installed package" % len(a["unowned_suid"]),
                 "— " + ", ".join(a["unowned_suid"][:3]))
    elif n_sec_use:
        alert = ('amber', "%d of %d pending security updates affect packages in use" % (n_sec_use, n_sec),
                 "— patch these first: " + ", ".join(a["sec_in_use"][:5]))
    elif n_sec:
        alert = ('amber', "%d pending security updates" % n_sec, "— none in packages proven in use.")
    else:
        alert = ('green', "No urgent findings", "— triage below; evidence attached to every verdict.")

    # ---- stat cards ----
    stats = [
        ("Installed", "%s" % "{:,}".format(n_inst), "%d snaps alongside" % len(ctx["snaps"]), ""),
        ("Proven in use", str(n_use), "process or socket evidence", "color:var(--green);"),
        ("Likely used", str(n_likely), "config, unit, or user state", "color:var(--green);"),
        ("Config-residual", str(len(a["residual"])), "awaiting purge — not installed", "color:var(--gray);"),
        ("Outside coverage", str(third + unknown), "third-party, PPA, or unknown", "color:var(--red);" if third + unknown else ""),
        ("Security updates", str(n_sec), "%d in in-use packages" % n_sec_use, "color:var(--red);" if n_sec_use else ("color:var(--amber);" if n_sec else "")),
    ]
    if ctx["geo_allow"]:
        nv = sum(c["n"] for c in a["geo_viol"])
        stats.append(("Geo violations", str(nv), "expected: %s" % ctx["geo_allow"].upper(),
                      "color:var(--red);" if nv else "color:var(--green);"))
    stat_html = "".join(
        '<div class="card stat"><div class="label">%s</div><div class="value" style="%s">%s</div>'
        '<div class="sub">%s</div></div>' % (esc(l), sty, esc(v), esc(s)) for l, v, s, sty in stats)

    # ---- connections ----
    pub = [c for c in a["conns"] if c["scope"] == "public"]
    internal = [c for c in a["conns"] if c["scope"] == "internal"]
    rows = []
    for c in (a["conns"][:9]):
        cls, txt = PROV_BADGE.get(c["prov"], ("b-gray", c["prov"]))
        verdict = badge("b-red", "investigate now") if (c["scope"] == "public" and c["prov"] == "none") else \
                  badge("b-red", "outside geography") if c.get("geo_viol") else \
                  badge("b-amber", "review") if (c["scope"] == "public" and c["prov"] in ("thirdparty", "ppa", "unknown", "unresolved")) else \
                  badge("b-green", "expected")
        proc = "%s → %s" % (c["comm"], c["pkg"] or ('<span style="color:var(--red);">none</span>' if c["exe"] else "?"))
        remote = c["remote"] + (" ×%d" % c["n"] if c.get("n", 1) > 1 else "")
        if c["scope"] == "internal":
            geo = '<span style="color:var(--gray);">internal</span>'
        elif c["cc"]:
            geo = "%s %s" % (flag(c["cc"]), c["cc"])
        else:
            geo = '<span style="color:var(--gray);">—</span>'
        rows.append("<tr><td class='mono'>%s</td><td>%s</td><td class='mono'>%s</td><td>%s</td><td>%s</td></tr>"
                    % (esc(remote), geo, proc, badge(cls, txt), verdict))
    more = len(a["conns"]) - 9
    if more > 0:
        rows.append("<tr><td class='mono'>+ %d more</td><td></td><td></td><td></td><td></td></tr>" % more)
    n_sess_all = sum(c.get("n", 1) for c in a["conns"])
    geo_src = ctx["geo"][1]
    geo_note = ("geo: %s" % geo_src) if geo_src else "no local geo db found — install geoip-bin or a GeoLite2 db"
    if ctx["geo_allow"]:
        geo_note += " · expected geography: %s" % ctx["geo_allow"].upper()
    conn_note = ("%d established sessions · %d public, %d internal destinations · %s"
                 % (n_sess_all, len(pub), len(internal), geo_note))
    conn_rows = "".join(rows) or "<tr><td colspan='5' style='color:var(--gray);'>no established external sessions at scan time</td></tr>"

    # ---- ciso row ----
    ciso = []
    ciso.append(("t-red" if n_sec_use else ("t-amber" if n_sec else "t-green"), "Security updates",
                 ("%d pending · %d in running code" % (n_sec, n_sec_use)) if n_sec else "none pending",
                 "Patch order is weighted by what actually runs, not alphabetical."))
    ciso.append(("t-green" if ctx["sec"]["livepatch"] else "t-amber", "Livepatch",
                 "enrolled" if ctx["sec"]["livepatch"] else "not enrolled",
                 "Kernel CVEs patched live — zero reboots, zero maintenance windows." if ctx["sec"]["livepatch"]
                 else "Kernel CVEs currently require reboots. Ubuntu Pro enables Livepatch."))
    ciso.append(("t-green" if ctx["crypto"]["fips"] else "t-amber", "FIPS 140-3",
                 "enabled" if ctx["crypto"]["fips"] else "not enabled",
                 "Kernel crypto is running in FIPS mode." if ctx["crypto"]["fips"]
                 else "Certified modules are one command away via Ubuntu Pro where required."))
    ciso.append(("t-teal", "Evidence bundle", "this report + SBOM",
                 "CycloneDX SBOM written alongside. Signed .ossa bundle and SPDX land in the full build."))
    ciso_html = "".join('<div class="card %s"><div class="k">%s</div><div class="v">%s</div><div class="d">%s</div></div>'
                        % (c, esc(k), esc(v), esc(d)) for c, k, v, d in ciso)

    # ---- provenance bar ----
    order = [("archive", "var(--green)", "Canonical archive"), ("pro", "var(--teal)", "Canonical Pro/ESM"),
             ("ppa", "var(--amber)", "PPA"), ("thirdparty", "var(--red)", "Third-party"),
             ("unknown", "var(--gray)", "Unknown")]
    segs, legend = [], []
    for key, color, label in order:
        cnt = a["prov_counts"].get(key, 0)
        if cnt:
            segs.append('<div style="width:%.2f%%;background:%s;"></div>' % (100.0 * cnt / max(n_inst, 1), color))
            legend.append('<span><span class="sq" style="background:%s;"></span>%s %s</span>'
                          % (color, label, "{:,}".format(cnt)))

    # ---- cross-tab ----
    xt = []
    for comp in ("main", "universe", "multiverse", "restricted"):
        d = a["comp_tab"].get(comp)
        if not d:
            continue
        w_inst = 100.0 * d["installed"] / max(n_inst, 1)
        w_use = 100.0 * (d["in_use"] + d["likely"]) / max(n_inst, 1)
        xt.append('<span class="mono">%s</span>'
                  '<div class="bar"><div class="fill" style="width:%.1f%%;"></div>'
                  '<div class="use" style="width:%.1f%%;"></div></div>'
                  '<span>%s · <span style="color:var(--green);font-weight:500;">%d in use</span></span>'
                  % (comp, w_inst, w_use, "{:,}".format(d["installed"]), d["in_use"] + d["likely"]))

    # ---- package census + manifests ----
    cen = []
    tot_av = tot_in = tot_use = 0
    for comp in COMPONENTS:
        av = len(ctx["avail"].get(comp, {}))
        d = a["comp_tab"].get(comp, {"installed": 0, "in_use": 0, "likely": 0})
        use = d["in_use"] + d["likely"]
        tot_av += av; tot_in += d["installed"]; tot_use += use
        share = ("%.1f%%" % (100.0 * d["installed"] / av)) if av else "—"
        cen.append("<tr><td class='mono'>%s</td><td style='text-align:right;'>%s</td>"
                   "<td style='text-align:right;'>%s</td><td style='text-align:right;color:var(--green);font-weight:500;'>%d</td>"
                   "<td style='text-align:right;color:var(--gray);'>%s</td></tr>"
                   % (comp, "{:,}".format(av) if av else "—", "{:,}".format(d["installed"]), use, share))
    n_other = len(a["installed"]) - tot_in
    if n_other:
        cen.append("<tr><td class='mono'>other origins</td><td style='text-align:right;color:var(--gray);'>—</td>"
                   "<td style='text-align:right;'>%d</td><td style='text-align:right;color:var(--green);font-weight:500;'>%d</td>"
                   "<td style='text-align:right;color:var(--gray);'>—</td></tr>"
                   % (n_other, len((a['in_use'] | a['likely'])) - tot_use))
    cen.append("<tr><td style='font-weight:500;'>Totals</td><td style='text-align:right;font-weight:500;'>%s</td>"
               "<td style='text-align:right;font-weight:500;'>%s</td><td style='text-align:right;font-weight:500;color:var(--green);'>%d</td><td></td></tr>"
               % ("{:,}".format(tot_av), "{:,}".format(len(a["installed"])), len(a["in_use"] | a["likely"])))
    man_rows = "".join("<tr><td class='mono'>%s</td><td style='text-align:right;color:var(--gray);'>%s</td></tr>"
                       % (esc(f), "{:,}".format(n)) for f, n in ctx.get("manifests", []))

    # ---- recommendation ----
    if not a["driving"]:
        rec_cls, rec_title = "", "Recommendation: the base tier fits"
        rec_body = ("No universe, multiverse, or restricted packages are in use on this host. "
                    "Everything running is in main — Applications coverage adds nothing here.")
        rec_chips = ""
    elif not a["no_sub"]:
        rec_cls, rec_title = "", "Recommendation: stay on the base tier"
        rec_body = ("All %d in-use non-main packages have main-component equivalents. "
                    "Estimated avoided cost: <strong style='font-weight:500;'>$%s / node / year</strong> "
                    "<span style='color:#9a9a9a;'>(illustrative — pricing is configurable)</span>."
                    % (len(a["driving"]), "{:,}".format(DEMO_PRICE_NODE_YEAR)))
        rec_chips = "".join('<span class="subchip">%s → %s</span>' % (esc(n), esc(r))
                            for n, r, _c, _note in a["subs"])
    else:
        rec_cls, rec_title = "amber", "Recommendation: Applications coverage earns its keep"
        n_ns = len(a["no_sub"])
        rec_body = ("%d in-use package%s outside main with no main-component substitute. "
                    "This is the evidence-backed case for the higher tier — auditable line by line."
                    % (n_ns, " sits" if n_ns == 1 else "s sit"))
        rec_chips = "".join('<span class="subchip">%s</span>' % esc(n) for n in a["no_sub"][:8]) + \
                    "".join('<span class="subchip">%s → %s</span>' % (esc(n), esc(r)) for n, r, _c, _n2 in a["subs"])

    # ---- triage table ----
    tri = []
    def trow(color, text, b):
        tri.append("<tr><td><span class='sq' style='background:var(--%s);'></span>%s</td>"
                   "<td style='text-align:right;'>%s</td></tr>" % (color, text, b))
    if a["unowned_suid"]:
        trow("red", "Unowned SUID binary " + " ".join("<span class='mono'>%s</span>" % esc(s) for s in a["unowned_suid"][:2]),
             badge("b-red", "action required"))
    for e in a["ext_listen"][:4]:
        sev = ("red", "action required") if e["prov"] in ("none", "thirdparty") else ("amber", "review")
        who = e["pkg"] or os.path.basename(e["exe"] or "") or \
              ("pid %d" % e["rec"]["pid"] if e["rec"]["pid"] else "unresolved process")
        trow(sev[0], "%s (%s) listening on <span class='mono'>%s:%d</span>"
             % (esc(who), PROV_BADGE.get(e["prov"], ("", e["prov"]))[1], esc(e["rec"]["lip"]), e["rec"]["lport"]),
             badge("b-" + sev[0], sev[1]))
    if n_sec:
        trow("amber" if n_sec_use else "amber", "%d pending security updates · %d in in-use packages" % (n_sec, n_sec_use),
             badge("b-amber", "attention"))
    sshd = ctx["sshd"]
    ssh_bad = []
    if sshd.get("permitrootlogin", "").lower() == "yes":
        ssh_bad.append("PermitRootLogin yes")
    if sshd.get("passwordauthentication", "yes" if "passwordauthentication" not in sshd else "").lower() == "yes" \
       or sshd.get("passwordauthentication", "").lower() == "yes":
        ssh_bad.append("PasswordAuthentication yes")
    elif "passwordauthentication" not in sshd and os.path.exists("/etc/ssh/sshd_config"):
        ssh_bad.append("PasswordAuthentication unset (defaults to yes)")
    if ssh_bad:
        trow("amber", "SSH posture: " + ", ".join(ssh_bad), badge("b-amber", "attention"))
    else:
        trow("green", "SSH posture", badge("b-green", "pass"))
    if ctx["sec"]["uid0"]:
        trow("red", "Non-root UID 0 accounts: " + ", ".join(ctx["sec"]["uid0"]), badge("b-red", "action required"))
    if ctx["sec"]["empty_pw"] > 0:
        trow("red", "%d account(s) with empty password" % ctx["sec"]["empty_pw"], badge("b-red", "action required"))
    elif ctx["sec"]["empty_pw"] == 0 and not ctx["sec"]["uid0"]:
        trow("green", "Account hygiene", badge("b-green", "pass"))
    trow("green" if ctx["sec"]["ufw"] else "amber", "Firewall (ufw) %s" % ("active" if ctx["sec"]["ufw"] else "not active"),
         badge("b-green", "pass") if ctx["sec"]["ufw"] else badge("b-amber", "attention"))
    trow("green" if ctx["sec"]["unattended"] else "amber",
         "Unattended security upgrades %s" % ("enabled" if ctx["sec"]["unattended"] else "not enabled"),
         badge("b-green", "pass") if ctx["sec"]["unattended"] else badge("b-amber", "attention"))

    # ---- crypto posture + hardening ----
    cr = ctx["crypto"]
    def prow(acc, color, text, b):
        acc.append("<tr><td><span class='sq' style='background:var(--%s);'></span>%s</td>"
                   "<td style='text-align:right;'>%s</td></tr>" % (color, text, b))
    cx = []
    if cr["fips"]:
        extra = (" · " + ", ".join(cr["fips_pkgs"])) if cr["fips_pkgs"] else ""
        prow(cx, "green", "FIPS mode enabled%s" % esc(extra), badge("b-green", "pass"))
    else:
        prow(cx, "amber", "FIPS mode not enabled" + (" (FIPS packages present)" if cr["fips_pkgs"] else ""),
             badge("b-amber", "attention" if cr["fips_pkgs"] else "info"))
    hk = cr["hostkeys"]
    if hk:
        desc = ", ".join("%s-%d" % (t, b) if t in ("rsa", "ecdsa") else t for t, b in hk)
        bad = [t for t, b in hk if t == "dsa" or (t == "rsa" and b < 2048)]
        prow(cx, "red" if bad else "green", "SSH host keys: <span class='mono'>%s</span>" % esc(desc),
             badge("b-red", "weak key present") if bad else badge("b-green", "pass"))
    if cr["ssh_weak"]:
        prow(cx, "red", "Weak SSH algorithms pinned in sshd_config (%s)" % esc(", ".join(cr["ssh_weak"])),
             badge("b-red", "action required"))
    else:
        prow(cx, "green", "SSH ciphers/MACs/KEX: %s" %
             ("explicitly pinned, no weak entries" if cr["ssh_pinned"] else "OpenSSH defaults (strong)"),
             badge("b-green", "pass"))
    if cr["seclevel"] is not None and cr["seclevel"] < 2 or (cr["tls_min"] or "").lower() in ("tlsv1", "tlsv1.1"):
        prow(cx, "red", "System OpenSSL policy downgraded (MinProtocol %s, SECLEVEL %s)"
             % (esc(cr["tls_min"] or "default"), cr["seclevel"]), badge("b-red", "action required"))
    else:
        prow(cx, "green", "System TLS policy: %s, SECLEVEL %s"
             % (esc(cr["tls_min"] or "distribution default (≥ TLS 1.2)"),
                cr["seclevel"] if cr["seclevel"] is not None else "2 (default)"),
             badge("b-green", "pass"))
    ha = ctx["sec"].get("hash_algos", {})
    if ctx["sec"].get("legacy_hash"):
        prow(cx, "red", "Legacy password hashes (md5/descrypt): %s" % esc(", ".join(ctx["sec"]["legacy_hash"][:3])),
             badge("b-red", "action required"))
    elif ha:
        prow(cx, "green", "Password hashes: %s" % esc(", ".join("%s ×%d" % kv for kv in sorted(ha.items()))),
             badge("b-green", "pass"))
    prow(cx, "green" if cr["luks"] else "amber",
         ("%d LUKS-encrypted volume(s)" % cr["luks"]) if cr["luks"] else "No LUKS-encrypted volumes detected",
         badge("b-green", "pass") if cr["luks"] else badge("b-amber", "review"))
    sb = cr["secureboot"]
    prow(cx, {"enabled": "green", "disabled": "amber", "legacy": "gray", "unknown": "gray"}[sb],
         "Secure Boot %s" % ("not applicable (legacy BIOS boot)" if sb == "legacy" else sb),
         badge("b-green", "pass") if sb == "enabled" else
         badge("b-amber", "review") if sb == "disabled" else badge("b-gray", "n/a" if sb == "legacy" else "unknown"))
    prow(cx, "green" if cr["tpm"] else "gray", "TPM %s" % ("present" if cr["tpm"] else "not detected"),
         badge("b-green", "pass") if cr["tpm"] else badge("b-gray", "info"))

    hd = []
    if cr["apparmor"]:
        en = cr["aa_enforce"]
        prow(hd, "green", "AppArmor enabled" + (" · %d profiles in enforce mode" % en if en is not None else ""),
             badge("b-green", "pass"))
    else:
        prow(hd, "red", "AppArmor not enabled", badge("b-red", "action required"))
    ld = cr["lockdown"]
    prow(hd, "green" if ld in ("integrity", "confidentiality") else ("gray" if ld is None else "amber"),
         "Kernel lockdown: %s" % (ld or "unknown without root"),
         badge("b-green", "pass") if ld in ("integrity", "confidentiality") else
         badge("b-gray", "unknown") if ld is None else badge("b-amber", "review"))
    sc = cr["sysctl"]
    def sysrow(label, key, good):
        v = sc.get(key)
        ok = v is not None and v >= good
        prow(hd, "green" if ok else ("gray" if v is None else "amber"),
             "%s (<span class='mono'>%s=%s</span>)" % (label, esc(key), "?" if v is None else v),
             badge("b-green", "pass") if ok else badge("b-gray", "unknown") if v is None else badge("b-amber", "review"))
    sysrow("ASLR", "kernel.randomize_va_space", 2)
    sysrow("ptrace scope restricted", "kernel.yama.ptrace_scope", 1)
    sysrow("Kernel pointers hidden", "kernel.kptr_restrict", 1)
    sysrow("dmesg restricted", "kernel.dmesg_restrict", 1)
    sysrow("Unprivileged BPF disabled", "kernel.unprivileged_bpf_disabled", 1)
    sysrow("Symlink/hardlink protection", "fs.protected_symlinks", 1)
    sysrow("TCP SYN cookies", "net.ipv4.tcp_syncookies", 1)
    prow(hd, "teal" if cr["usg"] else "gray",
         "Ubuntu Security Guide (CIS/STIG tooling) %s" % ("installed" if cr["usg"] else "not installed"),
         badge("b-teal", "present") if cr["usg"] else badge("b-gray", "via Ubuntu Pro"))

    # ---- honesty ----
    noatime = sum(1 for m in ctx["mounts"] if m["atime"] == "noatime")
    hon = ["atime evidence is not used in this demo build"
           + (" — %d of %d real mounts are noatime anyway" % (noatime, len(ctx["mounts"])) if ctx["mounts"] else "")
           + ". Usage verdicts rest on processes, sockets, configs, units, and user state only.",
           "“No evidence of use” never means “unused.”"]
    hon_w = "".join("<li>%s</li>" % esc(w) for w in W)

    sections = """
    <div class="pagehead" id="overview">
      <h2>%(host)s — assessment report</h2>
      <span class="meta">%(pretty)s · %(codename)s · %(arch)s · kernel %(kernel)s%(hw)s · %(mounts)d mounts · %(users)d users · machine-id <span class="mono">%(mid)s</span></span>
      <span class="chip green">CycloneDX 1.6</span><span class="chip gray">SPDX — full build</span>
    </div>
    <div class="alert %(acls)s"><strong>%(atitle)s</strong><span>%(abody)s</span></div>
    <div class="cards">%(stats)s</div>
    <div class="card" id="connections"><h3>Connections <span class="note">— %(conn_note)s</span></h3>
      <table><thead><tr><th>Remote</th><th>Geo</th><th>Process → package</th><th>Provenance</th><th>Verdict</th></tr></thead>
      <tbody>%(conn_rows)s</tbody></table></div>
    <div class="ciso" id="security">%(ciso)s</div>
    <div class="two-col" id="crypto">
      <div class="card"><h3>Cryptographic posture <span class="note">— read from the system, never inferred</span></h3>
        <table><tbody>%(cx)s</tbody></table></div>
      <div class="card"><h3>Hardening <span class="note">— kernel and platform controls</span></h3>
        <table><tbody>%(hd)s</tbody></table></div>
    </div>
    <div class="two-col">
      <div class="card" id="supportability"><h3>Software provenance <span class="note">— installed version vs apt indices, resolved offline</span></h3>
        <div class="provbar">%(segs)s</div><div class="legend">%(legend)s</div></div>
      <div class="card" id="usage"><h3>Component × usage <span class="note">— Canonical-origin packages, installed vs in use</span></h3>
        <div class="xtab">%(xt)s</div></div>
    </div>
    <div class="two-col" id="census">
      <div class="card"><h3>Package census <span class="note">— installed vs available, from the Canonical archive indices on this host</span></h3>
        <table><thead><tr><th>Component</th><th style="text-align:right;">Available</th><th style="text-align:right;">Installed</th><th style="text-align:right;">In use</th><th style="text-align:right;">Share installed</th></tr></thead>
        <tbody>%(cen)s</tbody></table></div>
      <div class="card"><h3>Package manifests <span class="note">— written beside this report, name + version per line</span></h3>
        <table><thead><tr><th>File</th><th style="text-align:right;">Packages</th></tr></thead>
        <tbody>%(man)s</tbody></table></div>
    </div>
    <div class="two-col">
      <div class="card rec %(rec_cls)s" id="tier"><h3>%(rec_title)s</h3>
        <div style="font-size:12.5px;color:#444;line-height:1.6;">%(rec_body)s</div>
        <div style="margin-top:10px;">%(rec_chips)s</div>
        <div style="margin-top:12px;font-size:11px;color:#9a9a9a;">Substitutions are curated and sourced; the full driving list is in the data below this report.</div></div>
      <div class="card"><h3>Security triage <span class="note">— 60-second posture, not a benchmark</span></h3>
        <table><tbody>%(tri)s</tbody></table></div>
    </div>
    <div class="honesty"><strong style="font-weight:500;">Honesty note.</strong> %(hon)s
      %(hon_list)s</div>
    <div class="footer">generated by ossa-lite v%(ver)s · script sha256:%(sha)s · %(ts)s · demo build — the full ossa adds SBOM signing, CVE/OVAL, and the upgrade-drift view</div>
    """ % {
        "host": esc(host["hostname"]), "pretty": esc(host["pretty"]), "codename": esc(host["codename"]),
        "arch": esc(host["arch"]), "kernel": esc(host["kernel"]), "mounts": len(ctx["mounts"]),
        "users": host["users"], "hw": (" · " + esc(host["hw"])) if host["hw"] else "",
        "mid": esc(host["mid"]),
        "acls": alert[0], "atitle": esc(alert[1]), "abody": esc(alert[2]),
        "stats": stat_html, "conn_note": esc(conn_note), "conn_rows": conn_rows,
        "ciso": ciso_html, "segs": "".join(segs), "legend": "".join(legend), "xt": "".join(xt),
        "rec_cls": rec_cls, "rec_title": esc(rec_title), "rec_body": rec_body, "rec_chips": rec_chips,
        "cx": "".join(cx), "hd": "".join(hd),
        "cen": "".join(cen), "man": man_rows or "<tr><td colspan='2' style='color:var(--gray);'>none written</td></tr>",
        "tri": "".join(tri), "hon": " ".join(esc(h) for h in hon),
        "hon_list": ("<ul>%s</ul>" % hon_w) if hon_w else "",
        "ver": VERSION, "sha": self_sha, "ts": time.strftime("%Y-%m-%d %H:%M %Z"),
    }

    nav = "".join('<a class="nav-item%s" href="#%s">%s</a>' % (" active" if i == 0 else "", anchor, label)
                  for i, (anchor, label) in enumerate([
                      ("overview", "Overview"), ("supportability", "Supportability"), ("usage", "Usage"),
                      ("connections", "Connections"), ("security", "Security"),
                      ("crypto", "Crypto & hardening"), ("tier", "Tier fit")]))

    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSSA report — %(host)s | Canonical</title><style>%(css)s</style></head><body>
<div class="topbar"><h1>Canonical OSSA</h1><span class="hostbadge">%(host)s</span>
<span class="topmeta">scanned %(ts)s · lite demo · read-only · nothing left this machine</span></div>
<div class="layout"><nav class="sidebar">
<div class="sb-logo"><span class="mark"></span><span>Canonical OSSA</span></div>
<div class="sb-head">Report</div>%(nav)s
<div class="sb-version">ossa-lite v%(ver)s</div></nav>
<main class="content">%(sections)s</main></div></body></html>
""" % {"host": esc(host["hostname"]), "css": CSS, "ts": time.strftime("%Y-%m-%d %H:%M %Z"),
       "nav": nav, "ver": VERSION, "sections": sections}

COMPONENTS = ("main", "universe", "multiverse", "restricted")

def write_manifests(host, a, avail):
    """Per-component package manifests, aws-pro-counter naming convention."""
    rel = host["codename"].capitalize()
    arch = host["deb_arch"]
    out = []
    by_comp = {c: [] for c in COMPONENTS}
    other = []
    for name, p in sorted(a["installed"].items()):
        oc, comp, _suite = a["prov"][name]
        row = (name, p.get("version", ""))
        if oc in ("archive", "pro") and comp in by_comp:
            by_comp[comp].append(row)
        else:
            other.append(row)
    for comp in COMPONENTS:
        f = "ubuntu-%s_%s_%s.installed.manifest" % (rel, comp, arch)
        with open(f, "w") as fh:
            fh.write("".join("%s\t%s\n" % r for r in by_comp[comp]))
        out.append((f, len(by_comp[comp])))
    if other:
        f = "ubuntu-%s_other_%s.installed.manifest" % (rel, arch)
        with open(f, "w") as fh:
            fh.write("".join("%s\t%s\n" % r for r in other))
        out.append((f, len(other)))
    for comp in COMPONENTS:
        names = avail.get(comp, {})
        if not names:
            continue
        f = "ubuntu-%s_%s_%s.all.manifest" % (rel, comp, arch)
        with open(f, "w") as fh:
            fh.write("".join("%s\t%s\n" % (n, v) for n, v in sorted(names.items())))
        out.append((f, len(names)))
    return out

def write_sbom(path, a):
    comps = []
    sup = {"archive": "Canonical (Ubuntu archive)", "pro": "Canonical (Ubuntu Pro/ESM)",
           "ppa": "Launchpad PPA", "thirdparty": "third-party repository", "unknown": "unknown origin"}
    for name, p in sorted(a["installed"].items()):
        oc = a["prov"][name][0]
        comps.append({"type": "library", "name": name, "version": p.get("version", ""),
                      "purl": "pkg:deb/ubuntu/%s@%s?arch=%s" % (name, p.get("version", ""), p.get("arch", "")),
                      "supplier": {"name": sup.get(oc, oc)}})
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"tools": [{"name": "ossa-lite", "version": VERSION}],
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z")},
           "components": comps}
    json.dump(bom, open(path, "w"), indent=1)

# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="ossa-lite — OSSA demo assessment (reads only, sends nothing)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  sudo python3 ossa-lite.py                  full assessment, report in current dir\n"
               "  sudo python3 ossa-lite.py --geo-allow US   flag connections outside the US\n"
               "  python3 ossa-lite.py --read-scope          show every path read, then exit\n"
               "\noutputs (current directory):\n"
               "  ossa-report-<host>.html        the report (mode 0600)\n"
               "  ossa-report-<host>.cdx.json    CycloneDX 1.6 SBOM (mode 0600)\n"
               "  ubuntu-<Rel>_<comp>_<arch>.{installed,all}.manifest\n"
               "\nfor best results run 'sudo apt update' first — ossa-lite never modifies\n"
               "apt state itself and will warn when the package lists are missing or stale.")
    ap.add_argument("--out", default=None, help="report path (default ossa-report-<host>.html)")
    ap.add_argument("--read-scope", action="store_true", help="print every path this tool reads, then exit")
    ap.add_argument("--yes", action="store_true", help="skip the sudo prompt and run with current privileges")
    ap.add_argument("--geo-allow", default="", metavar="CC,CC",
                    help="comma-separated ISO country codes considered expected geography "
                         "(e.g. US,GB,DE); connections elsewhere are flagged")
    ap.add_argument("--geoip-db", default=None, metavar="PATH",
                    help="path to a MaxMind-format .mmdb (GeoLite2 or db-ip, Country or City); "
                         "auto-detected from /var/lib/GeoIP, /usr/share/GeoIP, "
                         "/usr/local/share/GeoIP, /opt/geoip when omitted")
    args = ap.parse_args()

    if args.read_scope:
        print("ossa-lite reads the following, and writes only its report in the current directory:")
        for p in READ_SCOPE:
            print("  " + p)
        return 0

    if os.geteuid() != 0 and not args.yes:
        print("ossa needs sudo to read every process and config on this machine.")
        print("Here is exactly what it reads (nothing leaves this box):  ossa-lite.py --read-scope")
        if sys.stdin.isatty():
            r = input("Re-run with sudo now? [Y/n] ").strip().lower()
            if r in ("", "y", "yes"):
                os.execvp("sudo", ["sudo", sys.executable] + sys.argv + ["--yes"])
        warn("running without root — process, socket, and shadow evidence will be incomplete")

    t0 = time.time()
    print("ossa-lite v%s — collecting (reads only)" % VERSION, file=sys.stderr)
    host = host_info()
    if not host["is_ubuntu"]:
        warn("this is not Ubuntu (%s) — provenance and component analysis are Ubuntu-specific" % host["pretty"])
    step("dpkg database")
    pkgs = dpkg_status()
    auto = extended_states()
    installed_names = {n for n, p in pkgs.items() if p.get("status") == "install ok installed"}
    step("apt indices (%d packages to resolve)" % len(installed_names))
    indices, n_idx, avail = apt_indices(installed_names)
    step("processes and sockets")
    procs = processes()
    listeners, established = sockets()
    step("config drift (%d conffile sets)" % len(pkgs))
    modified = conffile_drift(pkgs)
    step("systemd, user state, mounts, snaps")
    geo = geo_resolver(args.geoip_db)
    ctx = {"pkgs": pkgs, "auto": auto, "indices": indices, "procs": procs,
           "listeners": listeners, "established": established, "modified": modified,
           "wants": systemd_wants(), "userstate": user_state(installed_names),
           "mounts": mounts(), "snaps": snaps(), "suid": suid_scan(),
           "sshd": sshd_effective(), "sec": security_misc(),
           "geo": geo, "geo_allow": args.geo_allow}
    ctx["crypto"] = crypto_hardening(installed_names, ctx["sshd"])
    ctx["avail"] = avail
    step("analyzing")
    a = analyze(ctx)
    step("writing package manifests")
    ctx["manifests"] = write_manifests(host, a, avail)

    try:
        self_sha = hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()[:12]
    except OSError:
        self_sha = "unknown"
    out = args.out or ("ossa-report-%s.html" % host["hostname"])
    open(out, "w").write(render(host, a, ctx, self_sha))
    os.chmod(out, 0o600)
    sbom = os.path.splitext(out)[0] + ".cdx.json"
    write_sbom(sbom, a)
    os.chmod(sbom, 0o600)

    dt = time.time() - t0
    print("\nossa-lite finished in %.1fs" % dt, file=sys.stderr)
    print("  report : %s" % out, file=sys.stderr)
    print("  sbom   : %s (CycloneDX 1.6)" % sbom, file=sys.stderr)
    for f, n in ctx.get("manifests", []):
        print("  %s (%s packages)" % (f, "{:,}".format(n)), file=sys.stderr)
    print("  %d installed · %d proven in use · %d likely used · %d security updates pending"
          % (len(a["installed"]), len(a["in_use"]), len(a["likely"]), len(a["sec_updates"])), file=sys.stderr)
    return 0

if __name__ == "__main__":
    sys.exit(main())
