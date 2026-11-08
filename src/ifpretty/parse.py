"""Parse raw `ifconfig` text into the interface model."""

from __future__ import annotations

import ipaddress
import re

from .model import Inet, Inet6, Interface


def hexmask_to_cidr(mask: str) -> str:
    """Convert an ifconfig netmask (0xffffff00) to '255.255.255.0/24'."""
    try:
        value = int(mask, 16)
    except ValueError:
        return mask
    octets = [(value >> shift) & 0xFF for shift in (24, 16, 8, 0)]
    bits = bin(value).count("1")
    return f"{'.'.join(map(str, octets))}/{bits}"


class Netmask:
    """An ifconfig netmask: macOS hex ('0xffffff00') or Linux dotted ('255.255.255.0')."""

    _HEX_PREFIX = "0x"

    def __init__(self, raw: str) -> None:
        self._raw = raw

    def to_cidr(self) -> str:
        """'255.255.255.0/24'; a non-contiguous or malformed mask passes through."""
        if self._raw.startswith(self._HEX_PREFIX):
            return hexmask_to_cidr(self._raw)
        try:
            bits = ipaddress.IPv4Network(f"0.0.0.0/{self._raw}").prefixlen
        except ValueError:
            return self._raw
        return f"{self._raw}/{bits}"


class CounterLine:
    """A Linux net-tools counter line, e.g. "RX packets 6007  bytes 13082891 (12.4 MiB)"
    or "TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0"."""

    _PACKETS = re.compile(
        r"^(?P<way>RX|TX) packets (?P<packets>\d+)\s+bytes (?P<octets>\d+)"
    )
    _ERRORS = re.compile(
        r"^(?P<way>RX|TX) errors (?P<errors>\d+)(?:.*\bcollisions (?P<collisions>\d+))?"
    )

    def __init__(self, line: str) -> None:
        self._line = line

    def apply_to(self, iface: Interface) -> bool:
        """Store the counters on iface; False when this is not a counter line."""
        packets = self._PACKETS.match(self._line)
        if packets:
            self._store_packets(iface, packets)
            return True
        errors = self._ERRORS.match(self._line)
        if errors:
            self._store_errors(iface, errors)
            return True
        return False

    def _store_packets(self, iface: Interface, match: re.Match[str]) -> None:
        count, octets = int(match["packets"]), int(match["octets"])
        if match["way"] == "RX":
            iface.rx_pkts, iface.rx_bytes = count, octets
            return
        iface.tx_pkts, iface.tx_bytes = count, octets

    def _store_errors(self, iface: Interface, match: re.Match[str]) -> None:
        if match["way"] == "RX":
            iface.rx_errs = int(match["errors"])
            return
        iface.tx_errs = int(match["errors"])
        iface.collisions = int(match["collisions"] or 0)


_VALUE_WORDS = {
    "stp",
    "rstp",
    "disabled",
    "enabled",
    "up",
    "down",
    "active",
    "inactive",
    "none",
    "auto",
}


def _is_value(tok: str) -> bool:
    if "=" in tok or tok.endswith(":"):
        return False
    if any(ch.isdigit() for ch in tok):
        return True
    if ":" in tok:  # mac / ipv6 fragment
        return True
    return tok.lower() in _VALUE_WORDS


def kv_pairs(s: str) -> list[tuple[str, str]]:
    """Split a multi-field line into (key, value) pairs.

    Handles `key value` runs (multi-word keys allowed), `label:` headers, and
    `name=hex<FLAG,FLAG>` blobs. Returns ('', value) for a bare value and
    (label, '') for a header so the renderer can style each kind.
    """
    pairs: list[tuple[str, str]] = []
    key_parts: list[str] = []

    def flush_label() -> None:
        if key_parts:
            pairs.append((" ".join(key_parts), ""))
            key_parts.clear()

    for tok in s.split():
        if "=" in tok:  # name=hex<FLAGS>  or  name=value
            flush_label()
            name, _, val = tok.partition("=")
            fm = re.search(r"<([^>]*)>", val)
            if fm:
                val = "  ".join(f for f in fm.group(1).split(",") if f)
            pairs.append((name, val))
        elif tok.endswith(":"):  # completes a label phrase ("Address cache:")
            key_parts.append(tok[:-1])
        elif _is_value(tok):
            pairs.append((" ".join(key_parts), tok))
            key_parts.clear()
        else:
            key_parts.append(tok)
    flush_label()
    return pairs


def _parse_inet(parts: list[str]) -> Inet:
    addr = parts[1] if len(parts) > 1 else ""
    netmask = broadcast = ""
    i = 2
    while i < len(parts) - 1:
        if parts[i] == "netmask":
            netmask = Netmask(parts[i + 1]).to_cidr()
        elif parts[i] == "broadcast":
            broadcast = parts[i + 1]
        i += 2
    return Inet(addr, netmask, broadcast)


def _parse_inet6(parts: list[str]) -> Inet6:
    addr = parts[1] if len(parts) > 1 else ""
    prefixlen = ""
    attrs: list[str] = []
    i = 2
    while i < len(parts):
        if parts[i] in ("prefixlen", "scopeid") and i + 1 < len(parts):
            if parts[i] == "prefixlen":
                prefixlen = parts[i + 1]
            i += 2
        else:
            attrs.append(parts[i])
            i += 1
    return Inet6(addr, prefixlen, tuple(attrs))


def _flags_in(rest: str) -> list[str]:
    m = re.search(r"flags=\w+<([^>]*)>", rest)
    return [f for f in m.group(1).split(",") if f] if m else []


def parse(text: str) -> list[Interface]:
    """Parse ifconfig text into a list of Interface records."""
    interfaces: list[Interface] = []
    cur: Interface | None = None

    for raw in text.splitlines():
        if not raw.strip():
            continue

        if not raw[0].isspace():  # interface header at column 0
            m = re.match(r"^(\S+?):\s+(.*)$", raw)
            name, rest = m.groups() if m else (raw.rstrip(":"), "")
            mtu = re.search(r"mtu (\d+)", rest)
            cur = Interface(
                name=name, flags=_flags_in(rest), mtu=mtu.group(1) if mtu else ""
            )
            interfaces.append(cur)
            continue

        if cur is None:  # detail before any header — shouldn't happen
            continue

        s = raw.strip()
        if CounterLine(s).apply_to(cur):  # Linux RX/TX lines
            continue
        if s.startswith("inet "):
            cur.inet.append(_parse_inet(s.split()))
        elif s.startswith("inet6 "):
            cur.inet6.append(_parse_inet6(s.split()))
        elif s.startswith("ether "):  # Linux appends "  txqueuelen 0  (Ethernet)"
            mac, _, link_info = s.split(None, 1)[1].partition(" ")
            cur.ether = mac
            if link_info.strip():
                cur.other.append(link_info.strip())
        elif s.startswith("status:"):
            cur.status = s.split(":", 1)[1].strip()
        elif s.startswith("media:"):
            cur.media = s.split(":", 1)[1].strip()
        elif m := re.match(r"^options=\w+<([^>]*)>$", s):
            cur.options = [f for f in m.group(1).split(",") if f]
        elif m := re.match(r"^nd6 options=\w+<([^>]*)>$", s):
            cur.nd6 = [f for f in m.group(1).split(",") if f]
        else:
            cur.other.append(s)

    return interfaces
