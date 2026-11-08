"""Domain model: parsed network interfaces."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# A decoded JSON object (snapshot state, ip-api records, vis.js nodes/edges).
JsonObject = dict[str, Any]


@dataclass(frozen=True)
class Inet:
    addr: str
    netmask: str = ""  # already CIDR form, e.g. "255.255.255.0/24"
    broadcast: str = ""


@dataclass(frozen=True)
class Inet6:
    addr: str
    prefixlen: str = ""
    attrs: tuple[str, ...] = ()


@dataclass
class Interface:
    name: str
    mtu: str = ""
    flags: list[str] = field(default_factory=list)
    options: list[str] = field(default_factory=list)
    ether: str = ""
    inet: list[Inet] = field(default_factory=list)
    inet6: list[Inet6] = field(default_factory=list)
    nd6: list[str] = field(default_factory=list)
    media: str = ""
    status: str = ""
    other: list[str] = field(default_factory=list)  # unmodeled lines, verbatim

    # Tier-2 live enrichment (populated only with --live; -1 / "" mean "unknown")
    hw_port: str = ""  # friendly name from networksetup, e.g. "Wi-Fi"
    gateway: str = ""  # set on the default-route interface
    is_default: bool = False
    rx_bytes: int = -1
    tx_bytes: int = -1
    rx_pkts: int = -1
    tx_pkts: int = -1
    rx_errs: int = 0
    tx_errs: int = 0
    collisions: int = 0
    dns: list[str] = field(default_factory=list)
    search_domains: list[str] = field(default_factory=list)
    dhcp_server: str = ""
    dhcp_lease: int = -1  # seconds
    gw_latency_ms: float = -1.0  # set by --check
    gw_loss: bool = False
    shares_mac_with: list[str] = field(default_factory=list)  # Tier-1 derivation
    rx_hist: list[float] = field(default_factory=list)  # bytes/s, from --record history
    tx_hist: list[float] = field(default_factory=list)

    @property
    def is_up(self) -> bool:
        return "UP" in self.flags

    @property
    def role(self) -> str:
        return interface_role(self.name)


_ROLES = {
    "lo": "loopback",
    "gif": "tunnel",
    "stf": "6to4 tunnel",
    "awdl": "Apple Wireless Direct",
    "llw": "low-latency WLAN",
    "utun": "VPN/tunnel",
    "bridge": "bridge",
    "ap": "access point",
    "en": "Ethernet/Wi-Fi",
    "anpi": "Apple private",
    # Linux names (classic and systemd predictable: enp3s0, wlp2s0, ...)
    "eth": "Ethernet",
    "enp": "Ethernet",
    "ens": "Ethernet",
    "eno": "Ethernet",
    "enx": "Ethernet",
    "wlan": "Wi-Fi",
    "wlp": "Wi-Fi",
    "br": "bridge",
    "docker": "Docker bridge",
    "veth": "virtual Ethernet",
    "tun": "VPN/tunnel",
    "wg": "WireGuard",
    "tunl": "tunnel",
    "gre": "tunnel",
    "sit": "IPv6-in-IPv4 tunnel",
}


def interface_role(name: str) -> str:
    m = re.match(r"^([a-z]+)", name)
    return _ROLES.get(m.group(1), "") if m else ""
