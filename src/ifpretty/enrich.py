"""Enrich interfaces with derived, system, external and historical data."""

from __future__ import annotations

import csv
import gzip
import importlib.resources
import io
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from .model import Inet, Interface

_CACHE_DIR = Path(
    os.environ.get("IFPRETTY_CACHE") or Path.home() / ".cache" / "ifpretty"
)

_ULA = ipaddress.ip_network("fc00::/7")


def mac_kind(ether: str) -> str:
    """'universal' (burned-in) vs 'locally administered' (randomized/virtual)."""
    if not ether:
        return ""
    try:
        first = int(ether.split(":")[0], 16)
    except ValueError:
        return ""
    if first & 0x01:
        return "multicast"
    return "locally administered" if first & 0x02 else "universal"


_OUI: dict[str, str] | None = None


def _read_bundled_oui() -> str:
    """Decompressed text of the OUI table shipped inside the package."""
    try:
        res = importlib.resources.files("ifpretty").joinpath("data/oui.tsv.gz")
        return gzip.decompress(res.read_bytes()).decode("utf-8")
    except (OSError, FileNotFoundError, ModuleNotFoundError):
        return ""


def _load_oui() -> dict[str, str]:
    global _OUI
    if _OUI is None:
        _OUI = {}
        try:  # prefer the user-refreshed cache, fall back to the bundled copy
            with gzip.open(_CACHE_DIR / "oui.tsv.gz", "rt", encoding="utf-8") as f:
                text = f.read()
        except OSError:
            text = _read_bundled_oui()
        for line in text.splitlines():
            prefix, _, org = line.partition("\t")
            if org:
                _OUI[prefix] = org
    return _OUI


def mac_vendor(ether: str) -> str:
    """IEEE-registered vendor for a universal MAC; '' for local/multicast/unknown."""
    if mac_kind(ether) != "universal":
        return ""
    key = ether.replace(":", "").upper()[:6]
    return _load_oui().get(key, "")


def is_eui64(addr: str) -> bool:
    """True if an IPv6 interface ID is derived from a MAC (modified EUI-64: ff:fe)."""
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return False
    if ip.version != 6:
        return False
    iid = int(ip) & ((1 << 64) - 1)  # low 64 bits
    return (iid >> 24) & 0xFFFF == 0xFFFE  # bytes 3-4 of the interface identifier


def derive_shared_macs(interfaces: list[Interface]) -> None:
    """Tier 1: note interfaces that share an Ethernet address (e.g. bridge members)."""
    seen: dict[str, list[str]] = {}
    for i in interfaces:
        if i.ether:
            seen.setdefault(i.ether, []).append(i.name)
    for i in interfaces:
        peers = [n for n in seen.get(i.ether, []) if n != i.name]
        i.shares_mac_with = peers


def ip_scope(addr: str) -> str:
    """Classify an address: loopback / link-local / ULA / private / global."""
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return ""
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.version == 6 and ip in _ULA:
        return "ULA"
    if ip.is_private:
        return "private"
    if ip.is_global:
        return "global"
    return "reserved"


def ipv4_net_info(x: Inet) -> str:
    """'net 192.168.1.0/24 · 254 hosts' from an IPv4 address + netmask."""
    if "/" not in x.netmask:
        return ""
    try:
        net = ipaddress.ip_network(f"{x.addr}/{x.netmask.split('/')[-1]}", strict=False)
    except ValueError:
        return ""
    usable = net.num_addresses - 2 if net.prefixlen <= 30 else net.num_addresses
    return f"net {net.with_prefixlen} · {usable} hosts"


def link_mbps(media: str) -> int:
    m = re.search(r"(\d+)(G?)[Bb]ase", media or "")
    if not m:
        return 0
    return int(m.group(1)) * 1000 if m.group(2) == "G" else int(m.group(1))


def _run(cmd: list[str], timeout: float = 3.0) -> str | None:
    """Run a helper command; return stdout, or None (with a stderr note) on failure."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        print(f"ifpretty: --live: {cmd[0]} failed ({e})", file=sys.stderr)
        return None
    return r.stdout or None  # route(8) returns nonzero with no default route — tolerate


def _apply_default_route(by_name: dict[str, Interface]) -> None:
    out = _run(["route", "-n", "get", "default"])
    if not out:
        return
    gateway = iface = ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("gateway:"):
            gateway = line.split(":", 1)[1].strip()
        elif line.startswith("interface:"):
            iface = line.split(":", 1)[1].strip()
    if iface in by_name:
        by_name[iface].is_default = True
        by_name[iface].gateway = gateway


def _read_link_counters() -> dict[str, tuple[int, ...]]:
    """{ifname: (rx_pkts, rx_errs, rx_bytes, tx_pkts, tx_errs, tx_bytes, coll)}."""
    out: dict[str, tuple[int, ...]] = {}
    text = _run(["netstat", "-ib"], timeout=10.0)  # can be slow with many interfaces
    if not text:
        return out
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 6 or not f[2].startswith("<Link"):
            continue
        nums = f[3:]
        if nums and ":" in nums[0]:  # drop the MAC column when present
            nums = nums[1:]
        try:  # nums = [Ipkts, Ierrs, Ibytes, Opkts, Oerrs, Obytes, Coll]
            vals = tuple(int(nums[i]) for i in range(6))
        except (ValueError, IndexError):
            continue
        coll = int(nums[6]) if len(nums) > 6 and nums[6].isdigit() else 0
        out[f[0]] = vals + (coll,)
    return out


def _apply_traffic(by_name: dict[str, Interface]) -> None:
    for name, v in _read_link_counters().items():
        if name in by_name:
            i = by_name[name]
            (
                i.rx_pkts,
                i.rx_errs,
                i.rx_bytes,
                i.tx_pkts,
                i.tx_errs,
                i.tx_bytes,
                i.collisions,
            ) = v


def _apply_hw_ports(by_name: dict[str, Interface]) -> None:
    out = _run(["networksetup", "-listallhardwareports"])
    if not out:
        return
    port = ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:"):
            dev = line.split(":", 1)[1].strip()
            if dev in by_name:
                by_name[dev].hw_port = port


def _apply_dns(by_name: dict[str, Interface]) -> None:
    out = _run(["scutil", "--dns"])
    if not out:
        return
    for block in re.split(r"resolver #\d+", out):
        m = re.search(r"if_index\s*:\s*\d+\s*\(([^)]+)\)", block)
        if not m or m.group(1) not in by_name:
            continue
        iface = by_name[m.group(1)]
        for ns in re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", block):
            if ns not in iface.dns:
                iface.dns.append(ns)
        for sd in re.findall(r"search domain\[\d+\]\s*:\s*(\S+)", block):
            if sd not in iface.search_domains:
                iface.search_domains.append(sd)


def _apply_dhcp(by_name: dict[str, Interface]) -> None:
    for name, iface in by_name.items():
        if not iface.inet:  # only DHCP-capable (IPv4-configured) interfaces
            continue
        server = _run(["ipconfig", "getoption", name, "server_identifier"])
        if server and server.strip():
            iface.dhcp_server = server.strip()
        lease = _run(["ipconfig", "getoption", name, "lease_time"])
        if lease and lease.strip().isdigit():
            iface.dhcp_lease = int(lease.strip())


@dataclass(frozen=True)
class LinuxLiveFiles:
    """Where Linux keeps the --live data (overridable for tests)."""

    route_table: Path = Path("/proc/net/route")
    net_dev: Path = Path("/proc/net/dev")
    resolv_conf: Path = Path("/etc/resolv.conf")


class LinuxLive:
    """--live on Linux, read straight from /proc and /etc: default route and
    gateway, per-interface counters, resolvers. Needs no helper tools, so it
    works in slim containers. DHCP lease and port names have no portable source.
    """

    _ALL_ZERO = "00000000"  # destination and mask of the default route
    _IFACE, _DESTINATION, _GATEWAY, _METRIC, _MASK = 0, 1, 2, 6, 7  # route columns
    _DEV_HEADER_LINES = 2
    _DEV_RECEIVE_COLUMNS = 8  # then 8 transmit columns
    _DEV_COLUMNS = 2 * _DEV_RECEIVE_COLUMNS

    def __init__(
        self, files: LinuxLiveFiles = LinuxLiveFiles(), notes: TextIO | None = None
    ) -> None:
        self._files = files
        self._notes = notes  # None: sys.stderr at write time

    def enrich(self, by_name: dict[str, Interface]) -> None:
        self._apply_default_route(by_name)
        self._apply_traffic(by_name)
        self._apply_dns(by_name)

    def _read(self, path: Path) -> str:
        try:
            return path.read_text()
        except OSError as e:
            note = f"ifpretty: --live: cannot read {path} ({e.strerror})\n"
            (self._notes or sys.stderr).write(note)
            return ""

    def _metric(self, route: list[str]) -> int:
        return int(route[self._METRIC])

    def _is_default(self, route: list[str]) -> bool:
        return (
            len(route) > self._MASK
            and route[self._DESTINATION] == self._ALL_ZERO
            and route[self._MASK] == self._ALL_ZERO
        )

    def _apply_default_route(self, by_name: dict[str, Interface]) -> None:
        table = self._read(self._files.route_table).splitlines()[1:]  # skip header
        defaults = [row.split() for row in table if self._is_default(row.split())]
        if not defaults:
            return
        best = min(defaults, key=self._metric)
        iface = by_name.get(best[self._IFACE])
        if iface is None:
            return
        iface.is_default = True
        if best[self._GATEWAY] != self._ALL_ZERO:  # a device route has no gateway
            little_endian = bytes.fromhex(best[self._GATEWAY])
            iface.gateway = str(ipaddress.IPv4Address(little_endian[::-1]))

    def _apply_traffic(self, by_name: dict[str, Interface]) -> None:
        lines = self._read(self._files.net_dev).splitlines()
        for line in lines[self._DEV_HEADER_LINES :]:
            name, _, counters = line.partition(":")
            iface = by_name.get(name.strip())
            values = [int(value) for value in counters.split() if value.isdigit()]
            if iface is not None and len(values) >= self._DEV_COLUMNS:
                self._store_counters(iface, values)

    def _store_counters(self, iface: Interface, values: list[int]) -> None:
        """/proc/net/dev order: bytes packets errs drop fifo frame compressed
        multicast, then bytes packets errs drop fifo colls carrier compressed."""
        rx_bytes, rx_pkts, rx_errs, *_ = values[: self._DEV_RECEIVE_COLUMNS]
        tx_bytes, tx_pkts, tx_errs, _, _, colls, *_ = values[
            self._DEV_RECEIVE_COLUMNS :
        ]
        iface.rx_bytes, iface.rx_pkts, iface.rx_errs = rx_bytes, rx_pkts, rx_errs
        iface.tx_bytes, iface.tx_pkts, iface.tx_errs = tx_bytes, tx_pkts, tx_errs
        iface.collisions = colls

    def _apply_dns(self, by_name: dict[str, Interface]) -> None:
        """resolv.conf is system-wide, so it belongs to the default-route interface."""
        owner = next((iface for iface in by_name.values() if iface.is_default), None)
        if owner is None:
            return
        for words in (
            line.split() for line in self._read(self._files.resolv_conf).splitlines()
        ):
            if words[:1] == ["nameserver"] and len(words) > 1:
                owner.dns.append(words[1])
                continue
            if words[:1] in (["search"], ["domain"]):
                owner.search_domains.extend(words[1:])


def enrich_live(interfaces: list[Interface]) -> None:
    """Augment interfaces with route, traffic, names, DNS and DHCP lease."""
    by_name = {i.name: i for i in interfaces}
    if sys.platform.startswith("linux"):
        LinuxLive().enrich(by_name)
        return
    if sys.platform != "darwin":
        sys.stderr.write("ifpretty: --live supports macOS and Linux; skipping\n")
        return
    _apply_default_route(by_name)
    _apply_traffic(by_name)
    _apply_hw_ports(by_name)
    _apply_dns(by_name)
    _apply_dhcp(by_name)


def _apply_gateway_ping(interfaces: list[Interface]) -> None:
    for iface in interfaces:
        if not (iface.is_default and iface.gateway):
            continue
        out = _run(["ping", "-c", "2", "-t", "2", iface.gateway], timeout=5.0)
        m = re.search(r"=\s*[\d.]+/([\d.]+)/", out) if out else None
        if m:
            iface.gw_latency_ms = float(m.group(1))
        else:
            iface.gw_loss = True


def enrich_check(interfaces: list[Interface]) -> None:
    """Active health probe (--check): ping the default gateway."""
    if sys.platform != "darwin":
        print("ifpretty: --check is macOS-only; skipping", file=sys.stderr)
        return
    by_name = {i.name: i for i in interfaces}
    if not any(i.is_default for i in interfaces):
        _apply_default_route(by_name)  # need the gateway if --live wasn't used
    _apply_gateway_ping(interfaces)


_HISTORY_WINDOW = 3600  # seconds of history kept / graphed

_HISTORY_PATH = Path(
    os.environ.get("IFPRETTY_HISTORY")
    or Path.home() / ".cache" / "ifpretty" / "samples.csv"
)


def _load_samples() -> list[tuple[int, str, int, int]]:
    """Each row: (epoch, ifname, rx_bytes, tx_bytes)."""
    rows: list[tuple[int, str, int, int]] = []
    try:
        text = _HISTORY_PATH.read_text()
    except OSError:
        return rows
    for line in text.splitlines():
        parts = line.split(",")
        if len(parts) != 4:
            continue
        try:
            rows.append((int(parts[0]), parts[1], int(parts[2]), int(parts[3])))
        except ValueError:
            continue
    return rows


def record_sample() -> int:
    """Append current per-interface byte counters to the history file (for --record)."""
    if sys.platform != "darwin":
        print("ifpretty: --record is macOS-only", file=sys.stderr)
        return 1
    counters = _read_link_counters()
    if not counters:
        print("ifpretty: --record: could not read counters", file=sys.stderr)
        return 1
    now = int(time.time())
    cutoff = now - 2 * _HISTORY_WINDOW
    rows = [r for r in _load_samples() if r[0] >= cutoff]
    rows += [(now, name, v[2], v[5]) for name, v in counters.items()]
    _HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    _HISTORY_PATH.write_text("".join(f"{t},{n},{rx},{tx}\n" for t, n, rx, tx in rows))
    return 0


def _rates(points: list[tuple[int, int, int]]) -> tuple[list[float], list[float]]:
    """Consecutive (ts, rx, tx) samples -> (rx_bytes/s, tx_bytes/s), resets clamped."""
    rx_rates, tx_rates = [], []
    for (t0, rx0, tx0), (t1, rx1, tx1) in zip(points, points[1:]):
        dt = t1 - t0
        if dt <= 0:
            continue
        rx_rates.append(max(0, rx1 - rx0) / dt)
        tx_rates.append(max(0, tx1 - tx0) / dt)
    return rx_rates, tx_rates


def enrich_history(interfaces: list[Interface]) -> None:
    """Attach the last hour of throughput rates from the --record datastore."""
    samples = _load_samples()
    if not samples:
        return
    now = max(ts for ts, _, _, _ in samples)
    by_iface: dict[str, list[tuple[int, int, int]]] = {}
    for ts, name, rx, tx in samples:
        if now - ts <= _HISTORY_WINDOW:
            by_iface.setdefault(name, []).append((ts, rx, tx))
    for iface in interfaces:
        pts = sorted(by_iface.get(iface.name, []))[-61:]  # ~1h at 1/min
        iface.rx_hist, iface.tx_hist = _rates(pts)


_WAN_TTL = 3600  # cache the WAN lookup for an hour

_WAN_URL = "https://ipapi.co/json/"

_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"

# standards-oui.ieee.org answers HTTP 418 to the default "Python-urllib/x.y" agent.
_USER_AGENT = "ifpretty (+https://github.com/iklobato/ifpretty)"


def fetch_wan(timeout: float = 3.0) -> dict[str, str] | None:
    """Public IP + ASN/ISP/geo via ipapi.co (cached ~1h). None on any failure.

    Opt-in (--wan): sends a request that reveals your public IP to ipapi.co.
    """
    cache = _CACHE_DIR / "wan.json"
    try:
        blob = json.loads(cache.read_text())
        if int(time.time()) - int(blob.get("_ts", 0)) < _WAN_TTL:
            return blob["data"]
    except (OSError, ValueError, KeyError):
        pass
    try:
        with urllib.request.urlopen(_WAN_URL, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (OSError, ValueError) as e:
        print(f"ifpretty: --wan lookup failed ({e})", file=sys.stderr)
        return None
    if payload.get("error"):
        print(
            f"ifpretty: --wan lookup failed ({payload.get('reason', 'error')})",
            file=sys.stderr,
        )
        return None
    data = {
        "ip": str(payload.get("ip", "")),
        "asn": str(payload.get("asn", "")),
        "org": str(payload.get("org", "")),
        "city": str(payload.get("city", "")),
        "cc": str(payload.get("country_code", "")),
    }
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({"_ts": int(time.time()), "data": data}))
    except OSError:
        pass
    return data


def update_oui(timeout: float = 60.0) -> int:
    """Download the IEEE OUI registry into the user cache (refreshes vendor lookup)."""
    try:
        request = urllib.request.Request(_OUI_URL, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except OSError as e:
        print(f"ifpretty: --update-oui failed ({e})", file=sys.stderr)
        return 1
    rows: dict[str, str] = {}
    for rec in csv.DictReader(io.StringIO(raw)):
        prefix = (rec.get("Assignment") or "").strip().upper()
        org = (rec.get("Organization Name") or "").strip()
        if len(prefix) == 6 and org:
            rows[prefix] = org
    if not rows:
        print("ifpretty: --update-oui parsed 0 entries", file=sys.stderr)
        return 1
    dest = _CACHE_DIR / "oui.tsv.gz"
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with gzip.open(dest, "wt", encoding="utf-8") as f:
            for prefix in sorted(rows):
                f.write(f"{prefix}\t{rows[prefix]}\n")
    except OSError as e:
        print(f"ifpretty: --update-oui could not write {dest} ({e})", file=sys.stderr)
        return 1
    global _OUI
    _OUI = None  # invalidate cache so the next lookup reloads
    print(f"ifpretty: OUI database updated — {len(rows)} entries → {dest}")
    return 0


_SNAPSHOT_PATH = _CACHE_DIR / "snapshot.json"


def snapshot_state(interfaces: list[Interface]) -> dict[str, dict]:
    """Stable per-interface state for diffing — excludes volatile counters/rates."""
    state: dict[str, dict] = {}
    for i in interfaces:
        state[i.name] = {
            "up": i.is_up,
            "status": i.status,
            "mtu": i.mtu,
            "ether": i.ether,
            "flags": i.flags,
            "media": i.media,
            "gateway": i.gateway,
            "inet": [
                f"{x.addr}/{x.netmask.split('/')[-1]}" if "/" in x.netmask else x.addr
                for x in i.inet
            ],
            "inet6": [
                f"{x.addr}/{x.prefixlen}" if x.prefixlen else x.addr for x in i.inet6
            ],
        }
    return state


def save_snapshot(state: dict[str, dict]) -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _SNAPSHOT_PATH.write_text(json.dumps({"_ts": int(time.time()), "data": state}))
    except OSError:
        pass


def load_snapshot() -> tuple[dict[str, dict], int] | None:
    try:
        blob = json.loads(_SNAPSHOT_PATH.read_text())
        return blob["data"], int(blob.get("_ts", 0))
    except (OSError, ValueError, KeyError):
        return None


_DIFF_SCALARS = [
    ("status", "status"),
    ("mtu", "mtu"),
    ("ether", "mac"),
    ("media", "media"),
    ("gateway", "gateway"),
]


def diff_snapshots(old: dict[str, dict], new: dict[str, dict]) -> list[str]:
    """Human-readable (rich-markup) change lines between two snapshots."""
    lines: list[str] = []
    old_names, new_names = set(old), set(new)
    for name in sorted(new_names - old_names):
        lines.append(f"[green]+ {name}[/] appeared")
    for name in sorted(old_names - new_names):
        lines.append(f"[red]- {name}[/] removed")
    for name in sorted(old_names & new_names):
        o, n = old[name], new[name]
        changes: list[str] = []
        if o.get("up") != n.get("up"):
            changes.append(
                f"state: {'up' if o.get('up') else 'down'} → "
                f"{'up' if n.get('up') else 'down'}"
            )
        for key, label in _DIFF_SCALARS:
            if o.get(key) != n.get(key):
                changes.append(f"{label}: {o.get(key) or '—'} → {n.get(key) or '—'}")
        for key in ("inet", "inet6"):
            added = sorted(set(n.get(key, [])) - set(o.get(key, [])))
            removed = sorted(set(o.get(key, [])) - set(n.get(key, [])))
            if added or removed:
                marks = [f"[green]+{a}[/]" for a in added]
                marks += [f"[red]-{r}[/]" for r in removed]
                changes.append(f"{key}: " + "  ".join(marks))
        if changes:
            lines.append(f"[yellow]~ {name}[/]")
            lines.extend(f"    {c}" for c in changes)
    return lines
