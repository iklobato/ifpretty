"""Command-line entry point: acquire input, enrich, render."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys

from .enrich import (
    derive_shared_macs,
    enrich_check,
    enrich_history,
    enrich_live,
    fetch_wan,
    load_snapshot,
    record_sample,
    save_snapshot,
    snapshot_state,
    update_oui,
)
from .parse import parse
from .render import RENDERERS, render_diff, render_legend, render_overview


def _capture_ifconfig(interfaces: list[str]) -> str:
    try:
        r = subprocess.run(
            ["ifconfig", *interfaces],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,  # ifconfig exits nonzero for an unknown name; stdout is enough
        )
    except (OSError, subprocess.SubprocessError) as e:
        print(f"ifpretty: could not run ifconfig ({e})", file=sys.stderr)
        return ""
    return r.stdout


def acquire_input(interfaces: list[str]) -> str:
    """ifconfig text: read stdin when piped or redirected from a file, else run
    `ifconfig` ourselves. A TTY, /dev/null (cron, CI, `docker run` without -t),
    a socket or a closed stdin carries no piped text."""
    try:
        mode = os.fstat(sys.stdin.fileno()).st_mode
    except (OSError, ValueError, AttributeError):
        mode = 0
    if stat.S_ISFIFO(mode) or stat.S_ISREG(mode):
        return sys.stdin.read()
    return _capture_ifconfig(interfaces)


def _cli() -> int:
    p = argparse.ArgumentParser(
        prog="ifpretty",
        description="Prettify `ifconfig` output. Run bare (ifpretty) or pipe "
        "`ifconfig` in.",
        epilog="bandwidth graph: schedule `* * * * * %s --record` (cron/launchd) to "
        "sample counters; the 1h sparkline then appears automatically."
        % (shutil.which("ifpretty") or "ifpretty"),
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument(
        "-r",
        "--records",
        dest="layout",
        action="store_const",
        const="records",
        help="compact label/value record layout",
    )
    g.add_argument(
        "-t",
        "--table",
        dest="layout",
        action="store_const",
        const="table",
        help="single wide table, all fields as columns",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show every field (flags, options, nd6, media, link-local, "
        "bridge config) and expand collapsed interfaces",
    )
    p.add_argument(
        "-l",
        "--live",
        action="store_true",
        help="enrich with live system data (macOS: route, traffic, "
        "friendly names, DNS, DHCP lease)",
    )
    p.add_argument(
        "-c",
        "--check",
        action="store_true",
        help="ping the default gateway and report latency (macOS)",
    )
    p.add_argument(
        "--record",
        action="store_true",
        help="sample byte counters into the history file and exit "
        "(run periodically via cron to feed the 1h graph)",
    )
    p.add_argument(
        "-w",
        "--wan",
        action="store_true",
        help="look up your public IP + ASN/ISP/geo (sends your IP to ipapi.co; "
        "cached ~1h)",
    )
    p.add_argument(
        "--update-oui",
        action="store_true",
        help="download the latest IEEE OUI registry into the cache and exit",
    )
    p.add_argument(
        "-d",
        "--diff",
        action="store_true",
        help="show what changed since the previous run (every run is recorded)",
    )
    p.add_argument(
        "-x",
        "--explain",
        action="store_true",
        help="append a legend explaining the flags/options seen",
    )
    p.add_argument(
        "--map",
        nargs="?",
        const="1.1.1.1",
        default=None,
        metavar="TARGET",
        help="open an interactive browser map: interfaces, LAN devices, gateway "
        "and the traceroute path to TARGET (default 1.1.1.1)",
    )
    p.add_argument(
        "interfaces",
        nargs="*",
        help="interface(s) to show; with nothing piped in, ifpretty runs "
        "`ifconfig` for you (optionally limited to these names)",
    )
    p.set_defaults(layout="boxed")
    args = p.parse_args()

    if args.record:  # no stdin needed; samples counters and exits
        return record_sample()
    if args.update_oui:  # download IEEE registry and exit
        return update_oui()

    data = acquire_input(args.interfaces)
    if not data.strip():
        print("ifpretty: no interface data (is `ifconfig` on PATH?)", file=sys.stderr)
        return 1

    interfaces = parse(data)
    if args.map is not None:  # browser topology map, then exit
        from .topology import open_map

        return open_map(interfaces, args.map)
    if args.live:
        enrich_live(interfaces)
    if args.check:
        enrich_check(interfaces)
    derive_shared_macs(interfaces)  # Tier 1: always-on, deterministic
    enrich_history(interfaces)  # 1h bandwidth from the --record datastore
    wan = fetch_wan() if args.wan else None  # Tier 3: external, opt-in

    state = snapshot_state(interfaces)  # record "what was found" every run
    if args.diff:
        render_diff(load_snapshot(), state)
    save_snapshot(state)

    if len(interfaces) > 1 or wan:
        render_overview(interfaces, wan)
    RENDERERS[args.layout](interfaces, args.verbose)
    if args.explain:
        render_legend(interfaces)
    return 0


def main() -> int:
    """Console-script entry point: run and translate signals to exit codes."""
    try:
        return _cli()
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130
