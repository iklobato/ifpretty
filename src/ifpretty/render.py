"""Render strategies: boxed / records / table, plus overview & diff."""

from __future__ import annotations

import shutil
import sys
import time
from typing import Callable

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .enrich import diff_snapshots
from .formatting import (
    DASH,
    caption_suffix,
    details_cell,
    humanize_bytes,
    humanize_secs,
    inet6_compact,
    inet_compact,
    interface_fields,
    is_minor,
    minor_line,
    status_badge,
)
from .model import Interface, JsonObject


def render_diff(
    prev: tuple[dict[str, JsonObject], int] | None, new: dict[str, JsonObject]
) -> None:
    console = _console(120)
    if prev is None:
        console.print(
            "[dim]No previous snapshot — saved this run as the baseline.[/]\n"
        )
        return
    old_state, old_ts = prev
    ago = humanize_secs(int(time.time()) - old_ts)
    lines = diff_snapshots(old_state, new)
    if not lines:
        console.print(f"[dim]No changes since last run ({ago} ago).[/]\n")
        return
    console.print(f"[bold]Changes since last run ({ago} ago):[/]")
    for line in lines:
        console.print(f"  {line}")
    console.print()


def _console(non_tty_width: int) -> Console:
    return Console(width=None if sys.stdout.isatty() else non_tty_width)


def render_boxed(interfaces: list[Interface], verbose: bool = False) -> None:
    """Boxed table per interface; every box shares one width so borders align."""
    console = _console(200)
    shown = {
        id(i): interface_fields(i, verbose)
        for i in interfaces
        if verbose or not is_minor(i)
    }
    label_w = max(
        (len(lbl) for rows in shown.values() for lbl, _ in rows),
        default=len("nd6 options"),
    )
    value_w = max(
        (Text.from_markup(val).cell_len for rows in shown.values() for _, val in rows),
        default=1,
    )

    for iface in interfaces:
        if id(iface) not in shown:
            console.print(minor_line(iface))
            continue
        table = Table(
            box=box.ROUNDED,
            show_header=False,
            title=f"[bold blue]{iface.name}[/]  {status_badge(iface)}"
            f"{caption_suffix(iface)}",
            title_justify="left",
        )
        table.add_column(
            "Field", style="cyan", justify="right", width=label_w, no_wrap=True
        )
        table.add_column("Value", width=value_w, no_wrap=True)
        for label, value in shown[id(iface)]:
            table.add_row(label, value)
        console.print(table)


def render_records(interfaces: list[Interface], verbose: bool = False) -> None:
    """Compact label/value blocks — width bounded by the longest line."""
    console = _console(100)
    shown = {
        id(i): interface_fields(i, verbose)
        for i in interfaces
        if verbose or not is_minor(i)
    }
    label_w = max((len(lbl) for rows in shown.values() for lbl, _ in rows), default=1)

    first = True
    for iface in interfaces:
        if id(iface) not in shown:
            console.print(minor_line(iface))
            first = False
            continue
        if not first:
            console.print()
        first = False
        mtu = f"  ·  [dim]mtu {iface.mtu}[/]" if iface.mtu else ""
        console.print(
            f"[bold blue]{iface.name}[/]  {status_badge(iface)}"
            f"{caption_suffix(iface)}{mtu}"
        )
        for label, value in shown[id(iface)]:
            if label == "mtu":  # already shown in the header
                continue
            console.print(f"  [cyan]{label:<{label_w}}[/] {value}")


def render_table(interfaces: list[Interface], verbose: bool = False) -> None:
    """All interfaces and all fields in one wide table; cap width at 240."""
    cap = 240
    term = shutil.get_terminal_size((cap, 24)).columns if sys.stdout.isatty() else cap
    console = Console(width=min(term, cap))

    table = Table(
        box=box.ROUNDED, header_style="bold cyan", title="ifconfig", show_lines=True
    )
    table.add_column("Interface", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("MTU", justify="right", style="dim", no_wrap=True)
    table.add_column("MAC", style="yellow", no_wrap=True)
    table.add_column("IPv4", style="green", no_wrap=True)
    table.add_column("IPv6", style="magenta", no_wrap=True)
    table.add_column("Details")

    for iface in interfaces:
        name_cell = f"[bold blue]{iface.name}[/]"
        sub = iface.hw_port or iface.role
        if sub:
            name_cell += f"\n[dim]{sub}[/]"
        if iface.is_default:
            name_cell += "\n[green]default ↑[/]"
        table.add_row(
            name_cell,
            status_badge(iface),
            iface.mtu or DASH,
            iface.ether or DASH,
            "\n".join(inet_compact(x) for x in iface.inet) or DASH,
            "\n".join(inet6_compact(x) for x in iface.inet6) or DASH,
            details_cell(iface, verbose),
        )
    console.print(table)


def render_overview(
    interfaces: list[Interface], wan: dict[str, str] | None = None
) -> None:
    """One-line summary above the layout."""
    console = _console(120)
    up = sum(1 for i in interfaces if i.is_up)
    parts = [f"[bold]{len(interfaces)}[/] interfaces", f"[green]{up} up[/]"]
    default = next((i for i in interfaces if i.is_default), None)
    if default:
        gw = f" ({default.gateway})" if default.gateway else ""
        parts.append(f"default via [bold blue]{default.name}[/]{gw}")
    live = [i for i in interfaces if i.rx_bytes >= 0]
    if live:
        rx = sum(i.rx_bytes for i in live)
        tx = sum(i.tx_bytes for i in live)
        parts.append(f"↓ {humanize_bytes(rx)}  ↑ {humanize_bytes(tx)}")
    if wan and wan.get("ip"):
        parts.append(f"WAN [bold]{wan['ip']}[/]")
        net = " ".join(x for x in (wan.get("asn"), wan.get("org")) if x)
        if net:
            parts.append(net)
        geo = " ".join(x for x in (wan.get("city"), wan.get("cc")) if x)
        if geo:
            parts.append(geo)
    console.print("  ·  ".join(parts))
    console.print()


Renderer = Callable[[list[Interface], bool], None]

RENDERERS: dict[str, Renderer] = {
    "boxed": render_boxed,
    "records": render_records,
    "table": render_table,
}

_GLOSSARY = {
    # flags
    "UP": "interface is up",
    "DOWN": "interface is down",
    "BROADCAST": "supports broadcast",
    "MULTICAST": "supports multicast",
    "LOOPBACK": "loopback interface",
    "POINTOPOINT": "point-to-point link",
    "RUNNING": "resources allocated",
    "SIMPLEX": "can't hear its own transmissions",
    "SMART": "managed by the system",
    "PROMISC": "promiscuous (sees all traffic)",
    "NOARP": "ARP disabled",
    # options (hardware offloads etc.)
    "RXCSUM": "hardware RX checksum offload",
    "TXCSUM": "hardware TX checksum offload",
    "TSO4": "TCP segmentation offload (IPv4)",
    "TSO6": "TCP segmentation offload (IPv6)",
    "LRO": "large receive offload",
    "VLAN_MTU": "VLAN-sized MTU support",
    "CHANNEL_IO": "multi-queue channel I/O",
    "PARTIAL_CSUM": "partial checksum offload",
    "ZEROINVERT_CSUM": "zero-invert checksum offload",
    "TXSTATUS": "TX completion status",
    "SW_TIMESTAMP": "software packet timestamping",
    # nd6
    "PERFORMNUD": "neighbor unreachability detection",
    "DAD": "duplicate address detection",
    "IFDISABLED": "IPv6 disabled on this interface",
}


def render_legend(interfaces: list[Interface]) -> None:
    console = Console(width=None if sys.stdout.isatty() else 100)
    sections = [
        ("flags", sorted({t for i in interfaces for t in i.flags})),
        ("options", sorted({t for i in interfaces for t in i.options})),
        ("nd6", sorted({t for i in interfaces for t in i.nd6})),
    ]
    console.print("\n[bold]Legend[/]")
    for title, tokens in sections:
        if not tokens:
            continue
        console.print(f"[dim cyan]{title}[/]")
        for tok in tokens:
            desc = _GLOSSARY.get(tok, "[dim](no description)[/]")
            console.print(f"  [green]{tok:<16}[/] {desc}")
