"""Turn model values into styled (rich-markup) display strings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .model import Inet, Inet6, Interface
from .parse import kv_pairs
from .enrich import ip_scope, ipv4_net_info, is_eui64, link_mbps, mac_kind, mac_vendor


def mtu_note(mtu: str) -> str:
    if not mtu.isdigit():
        return ""
    n = int(mtu)
    if n >= 9000:
        return "   [dim]· jumbo frames[/]"
    if n < 1280:
        return "   [yellow]· below IPv6 minimum[/]"
    return ""


def humanize_bytes(n: int) -> str:
    if n < 0:
        return ""
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if size < 1024 or unit == "PB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"  # unreachable; keeps the type checker happy


def humanize_count(n: int) -> str:
    if n < 0:
        return ""
    size = float(n)
    for unit in ("", "k", "M", "G"):
        if size < 1000 or unit == "G":
            return f"{size:.0f}{unit}" if unit == "" else f"{size:.1f}{unit}"
        size /= 1000
    return f"{size:.1f}G"


def humanize_secs(s: int) -> str:
    if s < 0:
        return ""
    for limit, unit in ((86400, "d"), (3600, "h"), (60, "m")):
        if s >= limit:
            return f"{s // limit}{unit}"
    return f"{s}s"


def humanize_rate(bytes_per_s: float) -> str:
    bits = bytes_per_s * 8
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if bits < 1000 or unit == "Gbps":
            return f"{bits:.0f} {unit}" if unit == "bps" else f"{bits:.1f} {unit}"
        bits /= 1000
    return f"{bits:.1f} Gbps"


_SPARK = "▁▂▃▄▅▆▇█"


def sparkline(values: list[float]) -> str:
    """Unicode block sparkline scaled 0..peak (single-width chars, alignment-safe)."""
    if not values:
        return ""
    peak = max(values) or 1.0
    return "".join(_SPARK[min(7, int(v / peak * 7.999))] for v in values)


def bar(frac: float, width: int = 10) -> str:
    """Horizontal gauge from full/light blocks (single-width, alignment-safe)."""
    n = round(max(0.0, min(1.0, frac)) * width)
    return "█" * n + "░" * (width - n)


def media_note(media: str) -> str:
    """Derive 'speed full-duplex' from a media string; warn on half-duplex."""
    if not media:
        return ""
    parts = []
    m = re.search(r"(\d+)(G?)[Bb]ase", media)
    if m:
        n = int(m.group(1))
        if m.group(2) == "G":
            parts.append(f"{n} Gbps")
        elif n >= 1000 and n % 1000 == 0:
            parts.append(f"{n // 1000} Gbps")
        else:
            parts.append(f"{n} Mbps")
    if "full-duplex" in media:
        parts.append("full-duplex")
    out = f"   [dim]· {' '.join(parts)}[/]" if parts else ""
    if "half-duplex" in media:
        out += "   [yellow]⚠ half-duplex[/]"
    return out


def traffic_value(iface: Interface) -> str:
    if iface.rx_bytes < 0:
        return ""
    rp = f" ({humanize_count(iface.rx_pkts)} pkts)" if iface.rx_pkts >= 0 else ""
    tp = f" ({humanize_count(iface.tx_pkts)} pkts)" if iface.tx_pkts >= 0 else ""
    return (
        f"↓ {humanize_bytes(iface.rx_bytes)}{rp}"
        f"   ↑ {humanize_bytes(iface.tx_bytes)}{tp}"
    )


def errors_value(iface: Interface) -> str:
    """Non-empty only when traffic was collected (--live) and something is nonzero."""
    if iface.rx_bytes < 0 or (iface.rx_errs == iface.tx_errs == iface.collisions == 0):
        return ""
    return f"in {iface.rx_errs}  out {iface.tx_errs}  coll {iface.collisions}"


DASH = "[grey50]—[/]"

LINK_INFO_MARK = "txqueuelen"  # Linux net-tools link line: "loop  txqueuelen 1000 ..."


def status_badge(iface: Interface) -> str:
    if iface.status == "active":
        return "[green]● active[/]"
    if iface.status == "inactive":
        return "[red]● inactive[/]"
    return "[green]● up[/]" if iface.is_up else "[grey50]● down[/]"


def _color_kv_line(line: str, sep: str = "  ") -> str:
    """Color a verbatim multi-field line (bridge config) into key/value chunks."""
    chunks = []
    for k, v in kv_pairs(line):
        if k and v:
            chunks.append(f"[cyan]{k}[/] {v}")
        elif k:
            chunks.append(f"[bold]{k}[/]")
        else:
            chunks.append(v)
    return sep.join(chunks) or f"[dim]{line}[/]"


def inet_detail(x: Inet) -> str:
    val = f"[bold green]{x.addr}[/]"
    if x.netmask:
        val += f"   netmask {x.netmask}"
    if x.broadcast:
        val += f"   broadcast {x.broadcast}"
    ann = [a for a in (ip_scope(x.addr), ipv4_net_info(x)) if a]
    if ann:
        val += "   [dim]· " + " · ".join(ann) + "[/]"
    return val


_V6_SLOTS = ("state", "config", "source")

_V6_ATTR_SLOT = {
    "deprecated": "state",
    "detached": "state",
    "tentative": "state",
    "duplicated": "state",
    "optimistic": "state",
    "autoconf": "config",
    "secured": "source",
    "temporary": "source",
    "dynamic": "source",
}


@dataclass
class V6Layout:
    """Column widths for aligning a single interface's IPv6 rows."""

    addr_w: int = 0
    slot_w: dict[str, int] = field(default_factory=lambda: {s: 0 for s in _V6_SLOTS})
    extra_w: int = 0


def _v6_slotted(attrs: tuple[str, ...]) -> tuple[dict[str, str], list[str]]:
    slots: dict[str, list[str]] = {s: [] for s in _V6_SLOTS}
    extra: list[str] = []
    for a in attrs:
        slot = _V6_ATTR_SLOT.get(a)
        (slots[slot] if slot else extra).append(a)
    return {s: " ".join(v) for s, v in slots.items()}, extra


def plan_inet6(items: list[Inet6]) -> V6Layout:
    layout = V6Layout()
    for x in items:
        addr = f"{x.addr}/{x.prefixlen}" if x.prefixlen else x.addr
        layout.addr_w = max(layout.addr_w, len(addr))
        slots, extra = _v6_slotted(x.attrs)
        for s in _V6_SLOTS:
            layout.slot_w[s] = max(layout.slot_w[s], len(slots[s]))
        layout.extra_w = max(layout.extra_w, len(" ".join(extra)))
    return layout


def _pad(markup: str, visible: int, width: int) -> str:
    """Right-pad `markup` to `width` columns, counting only `visible` chars."""
    return markup + " " * max(0, width - visible)


def fmt_inet6_aligned(x: Inet6, layout: V6Layout) -> str:
    addr = f"{x.addr}/{x.prefixlen}" if x.prefixlen else x.addr
    parts = [_pad(f"[bold magenta]{addr}[/]", len(addr), layout.addr_w)]
    slots, extra = _v6_slotted(x.attrs)
    for s in _V6_SLOTS:
        if layout.slot_w[s]:
            v = slots[s]
            parts.append(_pad(f"[yellow]{v}[/]" if v else "", len(v), layout.slot_w[s]))
    if layout.extra_w:
        ex = " ".join(extra)
        parts.append(_pad(f"[yellow]{ex}[/]" if ex else "", len(ex), layout.extra_w))
    line = "   ".join(parts)
    tail = [t for t in (ip_scope(x.addr), "EUI-64" if is_eui64(x.addr) else "") if t]
    if tail:
        line += "   [dim]· " + " · ".join(tail) + "[/]"
    return line


def ether_value(iface: Interface) -> str:
    """MAC + (kind · vendor) + shared-with note."""
    if not iface.ether:
        return ""
    out = f"[yellow]{iface.ether}[/]"
    tags = [t for t in (mac_kind(iface.ether), mac_vendor(iface.ether)) if t]
    if tags:
        out += "   [dim](" + " · ".join(tags) + ")[/]"
    if iface.shares_mac_with:
        out += "   [dim]· shared with " + " ".join(iface.shares_mac_with) + "[/]"
    return out


def gateway_value(iface: Interface) -> str:
    if not iface.gateway:
        return ""
    out = iface.gateway
    if iface.gw_latency_ms >= 0:
        out += f"   [dim]· {iface.gw_latency_ms:.1f} ms[/]"
    elif iface.gw_loss:
        out += "   [red]· unreachable[/]"
    return out


def dhcp_value(iface: Interface) -> str:
    if not iface.dhcp_server:
        return ""
    lease = humanize_secs(iface.dhcp_lease)
    return iface.dhcp_server + (f"   [dim]· lease {lease}[/]" if lease else "")


def bandwidth_rows(iface: Interface) -> list[tuple[str, str]]:
    """1h throughput sparklines + link-utilization gauge (only with --record data)."""
    rows: list[tuple[str, str]] = []
    if iface.rx_hist:
        rows.append(
            (
                "1h in",
                sparkline(iface.rx_hist)
                + f"   [dim]peak {humanize_rate(max(iface.rx_hist))}[/]",
            )
        )
    if iface.tx_hist:
        rows.append(
            (
                "1h out",
                sparkline(iface.tx_hist)
                + f"   [dim]peak {humanize_rate(max(iface.tx_hist))}[/]",
            )
        )
    spd = link_mbps(iface.media)
    if iface.rx_hist and iface.tx_hist and spd:
        frac = max(iface.rx_hist[-1], iface.tx_hist[-1]) * 8 / (spd * 1e6)
        rows.append(
            ("link use", f"{bar(frac)}   [dim]{frac * 100:.0f}% of {spd} Mbps[/]")
        )
    return rows


def _routable6(iface: Interface) -> list[Inet6]:
    return [x for x in iface.inet6 if ip_scope(x.addr) != "link-local"]


def is_minor(iface: Interface) -> bool:
    """An interface with nothing routable to show (down / address-less)."""
    return not iface.is_up or not (iface.inet or _routable6(iface))


def _live_and_graph_rows(iface: Interface) -> list[tuple[str, str]]:
    """Rows that only appear with --live / --record (shared by both densities)."""
    rows = [
        ("dns", " ".join(iface.dns)),
        ("search", " ".join(iface.search_domains)),
        ("dhcp", dhcp_value(iface)),
        ("gateway", gateway_value(iface)),
        ("traffic", traffic_value(iface)),
    ]
    errs = errors_value(iface)
    rows.append(("errors", f"[red]{errs}[/]" if errs else ""))
    rows += bandwidth_rows(iface)
    return [(lbl, val) for lbl, val in rows if val]


def _fields_verbose(iface: Interface) -> list[tuple[str, str]]:
    """Full detail — every field (the `-v` view)."""
    rows: list[tuple[str, str]] = []

    def add(label: str, value: str) -> None:
        if value:
            rows.append((label, value))

    add("mtu", iface.mtu + mtu_note(iface.mtu) if iface.mtu else "")
    add("flags", "  ".join(iface.flags))
    add("options", "  ".join(iface.options))
    add("ether", ether_value(iface))
    for v4 in iface.inet:
        add("inet", inet_detail(v4))
    v6plan = plan_inet6(iface.inet6)
    for v6 in iface.inet6:
        add("inet6", fmt_inet6_aligned(v6, v6plan))
    add("nd6 options", "  ".join(iface.nd6))
    add("media", iface.media + media_note(iface.media) if iface.media else "")
    rows += _live_and_graph_rows(iface)
    # Leftover lines: Linux "txqueuelen N (type)" link info, else a macOS bridge
    # config block (labelled once) or anything else ifconfig printed.
    group_label = "bridge" if iface.role == "bridge" else "other"
    for line in iface.other:
        if LINK_INFO_MARK in line:
            add("link", _color_kv_line(line, sep="    "))
            continue
        add(group_label, _color_kv_line(line, sep="    "))
        group_label = ""
    return rows


def _fields_essential(iface: Interface) -> list[tuple[str, str]]:
    """Primary tier — identity, routable addresses, gateway, throughput.

    The address/identity rows are returned with their `· annotation` aligned into
    a column (value padded to the widest plain value in the group).
    """
    # (label, main_markup, main_visible_len, annotation_markup)
    items: list[tuple[str, str, int, str]] = []

    if mtu_note(iface.mtu):  # only when notable (jumbo / sub-1280)
        items.append(("mtu", iface.mtu, len(iface.mtu), mtu_note(iface.mtu).strip()))
    if iface.ether:
        vendor = mac_vendor(iface.ether)
        items.append(
            (
                "ether",
                f"[yellow]{iface.ether}[/]",
                len(iface.ether),
                f"[dim]{vendor}[/]" if vendor else "",
            )
        )
    for v4 in iface.inet:
        bits = v4.netmask.split("/")[-1] if "/" in v4.netmask else ""
        addr = f"{v4.addr}/{bits}" if bits else v4.addr
        scope = ip_scope(v4.addr)
        items.append(
            (
                "inet",
                f"[bold green]{addr}[/]",
                len(addr),
                f"[dim]· {scope}[/]" if scope else "",
            )
        )
    for v6 in _routable6(iface):
        addr = f"{v6.addr}/{v6.prefixlen}" if v6.prefixlen else v6.addr
        scope = ip_scope(v6.addr)
        items.append(
            (
                "inet6",
                f"[bold magenta]{addr}[/]",
                len(addr),
                f"[dim]· {scope}[/]" if scope else "",
            )
        )

    width = max((mv for _, _, mv, ann in items if ann), default=0)
    rows: list[tuple[str, str]] = []
    for label, main, mv, ann in items:
        rows.append((label, f"{main}{' ' * (width - mv)}  {ann}" if ann else main))

    if "half-duplex" in (iface.media or ""):  # only when it's a problem
        rows.append(("media", iface.media + media_note(iface.media)))
    rows += _live_and_graph_rows(iface)
    return rows


def interface_fields(iface: Interface, verbose: bool = True) -> list[tuple[str, str]]:
    """Canonical (label, styled-value) rows; trimmed unless `verbose`."""
    return _fields_verbose(iface) if verbose else _fields_essential(iface)


def minor_line(iface: Interface) -> str:
    """One-line dim summary for a collapsed (down / address-less) interface."""
    dot = "[green]●[/]" if iface.is_up else "[grey50]○[/]"
    state = iface.status or ("up" if iface.is_up else "down")
    role = f"  [dim]{iface.role}[/]" if iface.role else ""
    return f"{dot} [blue]{iface.name}[/]{role}   [grey50]{state}[/]"


def inet_compact(x: Inet) -> str:
    bits = x.netmask.split("/")[-1] if "/" in x.netmask else ""
    s = f"{x.addr}/{bits}" if bits else x.addr
    if x.broadcast:
        s += f" [dim]bcast {x.broadcast}[/]"
    return s


def inet6_compact(x: Inet6) -> str:
    s = f"{x.addr}/{x.prefixlen}" if x.prefixlen else x.addr
    if x.attrs:
        s += " [yellow]" + " ".join(x.attrs) + "[/]"
    return s


def details_cell(iface: Interface, verbose: bool = True) -> str:
    """Catch-all column for the table view; trimmed unless `verbose`."""
    lines = []
    if verbose:
        if iface.flags:
            lines.append("[dim cyan]flags[/] [green]" + " ".join(iface.flags) + "[/]")
        if iface.options:
            lines.append("[dim cyan]opts [/] " + " ".join(iface.options))
        if iface.nd6:
            lines.append("[dim cyan]nd6  [/] " + " ".join(iface.nd6))
        if iface.media:
            lines.append("[dim cyan]media[/] " + iface.media + media_note(iface.media))
    elif "half-duplex" in (iface.media or ""):
        lines.append("[dim cyan]media[/] " + iface.media + media_note(iface.media))
    if iface.dns:
        lines.append("[dim cyan]dns  [/] " + " ".join(iface.dns))
    if iface.search_domains:
        lines.append("[dim cyan]srch [/] " + " ".join(iface.search_domains))
    if dhcp_value(iface):
        lines.append("[dim cyan]dhcp [/] " + dhcp_value(iface))
    if gateway_value(iface):
        lines.append("[dim cyan]gw   [/] " + gateway_value(iface))
    if traffic_value(iface):
        lines.append("[dim cyan]traf [/] " + traffic_value(iface))
    if errors_value(iface):
        lines.append("[dim cyan]err  [/] [red]" + errors_value(iface) + "[/]")
    for label, value in bandwidth_rows(iface):
        lines.append(f"[dim cyan]{label:<5}[/] {value}")
    if verbose:
        lines += [_color_kv_line(line) for line in iface.other]
    return "\n".join(lines) or DASH


def caption_suffix(iface: Interface) -> str:
    """Role / friendly-name / default-route badge appended to an interface header."""
    parts = []
    label = iface.hw_port or iface.role
    if label:
        parts.append(f"[cyan]{label}[/]")
    if iface.is_default:
        parts.append("[green]default ↑[/]")
    return ("  ·  " + "  ·  ".join(parts)) if parts else ""
