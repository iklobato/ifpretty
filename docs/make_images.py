"""Regenerate the README screenshots in docs/img from fake data.

Every terminal image is a real ifpretty run. A fake `ifconfig` prints an
anonymized fixture, fake macOS tools (route, netstat, scutil, ...) answer
--live and --check, and a seeded cache answers --wan. So no address of the
machine that runs this script reaches an image. macOS only: --live and
--check take their macOS code path.

    uv run python docs/make_images.py             # SVGs + the --map PNG
    uv run python docs/make_images.py --svg-only  # what CI regenerates
"""

from __future__ import annotations

import argparse
import io
import json
import os
import shlex
import socket
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from rich.cells import cell_len
from rich.console import Console
from rich.text import Text

from ifpretty.model import JsonObject
from ifpretty.parse import parse
from ifpretty.topology import (
    build_graph,
    parse_neighbors,
    parse_traceroute,
    render_html,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
MAC_FIXTURE = FIXTURES / "sample.txt"
LINUX_FIXTURE = FIXTURES / "sample_linux.txt"
IMAGE_DIR = ROOT / "docs" / "img"
MAP_IMAGE = IMAGE_DIR / "map.png"
CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
MAP_WINDOW = "1600,900"
MAP_SETTLE_MS = "8000"  # vis-network loads from a CDN, then its physics settles
SVG_MARGIN = 2  # cells right of the longest line
DIFF_AGE_SECONDS = 180  # the --diff image says "3m ago"

GATEWAY = "192.168.1.1"
FAKE_HOSTNAME = "laptop.local"
MAP_TARGET = "1.1.1.1"

FAKE_TOOLS = (
    (
        "ifconfig",
        """#!/bin/sh
# Prints $FAKE_IFCONFIG, limited to the interfaces named as arguments.
if [ $# -eq 0 ]; then cat "$FAKE_IFCONFIG"; exit 0; fi
awk -v want=" $* " '/^[^ \\t]/ { n = $1; sub(/:$/, "", n); keep = index(want, " " n " ") > 0 } keep' "$FAKE_IFCONFIG"
""",
    ),
    (
        "route",
        """#!/bin/sh
printf '   route to: default\\ndestination: default\\n    gateway: 192.168.1.1\\n  interface: en0\\n'
""",
    ),
    (
        "netstat",
        """#!/bin/sh
cat <<'EOF'
Name  Mtu   Network     Address              Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
en0   1500  <Link#11>   14:7d:da:00:00:01  8812345     0 9876543210  4123456     0  654321098     0
en1   9000  <Link#12>   82:00:00:00:00:01   112233     3   98765432    99887     0   12345678     2
EOF
""",
    ),
    (
        "networksetup",
        """#!/bin/sh
printf 'Hardware Port: Wi-Fi\\nDevice: en0\\n\\nHardware Port: Thunderbolt Ethernet\\nDevice: en1\\n'
""",
    ),
    (
        "scutil",
        """#!/bin/sh
cat <<'EOF'
DNS configuration

resolver #1
  search domain[0] : home.example
  nameserver[0] : 192.168.1.1
  nameserver[1] : 1.1.1.1
  if_index : 11 (en0)
EOF
""",
    ),
    (
        "ipconfig",
        """#!/bin/sh
[ "$2" = en0 ] || exit 0
case "$3" in
  server_identifier) echo 192.168.1.1 ;;
  lease_time) echo 86400 ;;
esac
""",
    ),
    (
        "ping",
        """#!/bin/sh
printf 'round-trip min/avg/max/stddev = 1.102/1.391/1.680/0.289 ms\\n'
""",
    ),
)

FAKE_WAN = (
    ("ip", "203.0.113.7"),
    ("asn", "AS64500"),
    ("org", "Example ISP"),
    ("city", "Lisbon"),
    ("cc", "PT"),
)

# Per-5-minute throughput of en1 over the last hour, in Mbit/s (rx, tx).
HISTORY_PROFILE = (
    (20, 2),
    (35, 4),
    (60, 6),
    (120, 10),
    (250, 25),
    (380, 30),
    (220, 18),
    (90, 9),
    (50, 5),
    (150, 12),
    (260, 22),
    (400, 35),
)
HISTORY_IFACE = "en1"
HISTORY_START = 1_800_000_000  # any epoch: the graph is relative to the last sample
SAMPLE_EVERY = 60
SAMPLES_PER_STEP = 5
BYTES_PER_MBIT = 125_000

FAKE_TRACEROUTE = """\
 1  192.168.1.1  1.402 ms
 2  100.64.0.1  6.881 ms
 3  198.51.100.9  8.120 ms
 4  *
 5  203.0.113.45  11.930 ms
 6  1.1.1.1  12.410 ms
"""

FAKE_ARP = """\
? (192.168.1.23) at 3c:22:fb:00:00:02 on en0 ifscope [ethernet]
? (192.168.1.40) at 3c:d9:2b:00:00:03 on en0 ifscope [ethernet]
? (192.168.1.57) at 78:bd:bc:00:00:04 on en0 ifscope [ethernet]
"""

FAKE_IPINFO = (
    (
        "1.1.1.1",
        (
            ("host", "one.one.one.one"),
            ("org", "Cloudflare, Inc."),
            ("isp", "Cloudflare, Inc."),
            ("asn", "AS13335 Cloudflare, Inc."),
            ("country", "Australia"),
            ("cc", "AU"),
            ("city", "Sydney"),
        ),
    ),
    (
        "198.51.100.9",
        (
            ("host", "core1.example.net"),
            ("org", "Example ISP"),
            ("isp", "Example ISP"),
            ("asn", "AS64500 Example ISP"),
            ("country", "Portugal"),
            ("cc", "PT"),
            ("city", "Lisbon"),
        ),
    ),
    (
        "203.0.113.45",
        (
            ("host", "edge.transit.example"),
            ("org", "Example Transit"),
            ("isp", "Example Transit"),
            ("asn", "AS64501 Example Transit"),
            ("country", "Spain"),
            ("cc", "ES"),
            ("city", "Madrid"),
        ),
    ),
    ("192.168.1.23", (("host", "macbook.local"),)),
    ("192.168.1.40", (("host", "printer.local"),)),
    ("192.168.1.57", (("host", "living-room-tv.local"),)),
)
EXECUTABLE = 0o755


class ShotFailedError(RuntimeError):
    """An ifpretty run for one image exited nonzero."""


@dataclass(frozen=True)
class Shot:
    """One README image: an ifpretty command line and the fake world it sees."""

    name: str
    argv: tuple[str, ...] = ()
    fixture: Path = MAC_FIXTURE
    env: dict[str, str] = field(default_factory=dict)
    before: Path | None = None  # a run that records the --diff baseline first

    def title(self) -> str:
        return shlex.join(("ifpretty", *self.argv))


class Workspace:
    """Temp dir holding the fake tools, the seeded cache and the extra fixtures."""

    def __init__(self, root: Path) -> None:
        self.root = root

    @property
    def tools(self) -> Path:
        return self.root / "bin"

    @property
    def cache(self) -> Path:
        return self.root / "cache"

    @property
    def history(self) -> Path:
        return self.root / "samples.csv"

    @property
    def diff_fixture(self) -> Path:
        return self.root / "sample_changed.txt"

    def build(self) -> Workspace:
        self.tools.mkdir()
        self.cache.mkdir()
        for name, body in FAKE_TOOLS:
            tool = self.tools / name
            tool.write_text(body)
            tool.chmod(EXECUTABLE)
        self._seed_wan()
        self.history.write_text(HistoryWriter().csv())
        self.diff_fixture.write_text(self._changed_fixture())
        return self

    def snapshot_path(self) -> Path:
        return self.cache / "snapshot.json"

    def _seed_wan(self) -> None:
        blob = {"_ts": int(time.time()), "data": dict(FAKE_WAN)}
        (self.cache / "wan.json").write_text(json.dumps(blob))

    def _changed_fixture(self) -> str:
        """sample.txt after a DHCP renew and with en9 unplugged."""
        text = MAC_FIXTURE.read_text().replace("192.168.1.201", "192.168.1.50")
        kept, _, _ = text.partition("en9:")
        return kept


class HistoryWriter:
    """Byte counters that --record would have written once a minute for 1h."""

    def csv(self) -> str:
        rows = []
        rx = tx = 0
        ts = HISTORY_START
        for rx_mbit, tx_mbit in HISTORY_PROFILE:
            for _ in range(SAMPLES_PER_STEP):
                ts += SAMPLE_EVERY
                rx += rx_mbit * BYTES_PER_MBIT * SAMPLE_EVERY
                tx += tx_mbit * BYTES_PER_MBIT * SAMPLE_EVERY
                rows.append(f"{ts},{HISTORY_IFACE},{rx},{tx}\n")
        return "".join(rows)


class Runner:
    """Runs ifpretty for a Shot inside the Workspace and returns its ANSI output."""

    def __init__(self, workspace: Workspace) -> None:
        self._ws = workspace

    def capture(self, shot: Shot) -> str:
        out = self._ws.root / f"{shot.name}.ansi"
        if shot.before is not None:
            self._run(shot, shot.before, out)
            self._age_snapshot()
        self._run(shot, shot.fixture, out)
        return out.read_text()

    def _env(self, shot: Shot, fixture: Path) -> dict[str, str]:
        env = {
            "PATH": f"{self._ws.tools}:{os.environ['PATH']}",
            "FAKE_IFCONFIG": str(fixture),
            "IFPRETTY_CACHE": str(self._ws.cache),
            # never the real ~/.cache/ifpretty/samples.csv
            "IFPRETTY_HISTORY": str(self._ws.root / "no-history.csv"),
            "FORCE_COLOR": "1",  # rich ignores CLICOLOR_FORCE
        }
        env.update(shot.env)
        return env

    def _run(self, shot: Shot, fixture: Path, out: Path) -> None:
        env = self._env(shot, fixture)
        assignments = [f"{name}={value}" for name, value in env.items()]
        command = ["env", "-u", "NO_COLOR", *assignments]
        command += [sys.executable, "-m", "ifpretty", *shot.argv]
        err = self._ws.root / f"{shot.name}.err"
        line = f"{shlex.join(command)} < /dev/null > {shlex.quote(str(out))}"
        status = os.system(f"{line} 2> {shlex.quote(str(err))}")
        if os.waitstatus_to_exitcode(status) != 0:
            raise ShotFailedError(f"{shot.title()} failed:\n{err.read_text()}")

    def _age_snapshot(self) -> None:
        path = self._ws.snapshot_path()
        blob = json.loads(path.read_text())
        blob["_ts"] = int(time.time()) - DIFF_AGE_SECONDS
        path.write_text(json.dumps(blob))


class SvgRenderer:
    """ANSI terminal text to a terminal-window SVG, sized to the longest line."""

    def render(self, ansi: str, title: str) -> str:
        text = Text.from_ansi(ansi.rstrip("\n"))
        width = max(cell_len(line) for line in text.plain.splitlines()) + SVG_MARGIN
        console = Console(
            record=True,
            width=width,
            file=io.StringIO(),
            force_terminal=True,
            color_system="truecolor",
        )
        console.print(text, no_wrap=True, overflow="ignore")
        return console.export_svg(title=title)


class MapRenderer:
    """The --map page built from a made-up network, screenshotted by headless Chrome."""

    def __init__(self, workspace: Workspace) -> None:
        self._ws = workspace

    def render(self, png: Path) -> None:
        page = self._ws.root / "map.html"
        page.write_text(self._html())
        command = [
            str(CHROME),
            "--headless=new",
            f"--user-data-dir={self._ws.root / 'chrome'}",
            "--no-first-run",
            "--hide-scrollbars",
            f"--window-size={MAP_WINDOW}",
            f"--virtual-time-budget={MAP_SETTLE_MS}",
            f"--screenshot={png}",
            page.as_uri(),
        ]
        status = os.system(f"{shlex.join(command)} > /dev/null 2>&1")
        if os.waitstatus_to_exitcode(status) != 0 or not png.exists():
            raise ShotFailedError(f"map screenshot failed (status {status})")

    def _html(self) -> str:
        interfaces = parse(MAC_FIXTURE.read_text())
        hops = parse_traceroute(FAKE_TRACEROUTE)
        neighbors = parse_neighbors(FAKE_ARP)
        ipinfo = {ip: dict(fields) for ip, fields in FAKE_IPINFO}
        nodes, edges, zones = build_graph(
            interfaces, GATEWAY, "en0", hops, neighbors, MAP_TARGET, ipinfo
        )
        self._hide_hostname(nodes)
        html = render_html(nodes, edges, zones, self._subtitle(nodes, zones))
        if socket.gethostname() in html:
            raise ShotFailedError("the map still carries this machine's hostname")
        return html

    def _hide_hostname(self, nodes: list[JsonObject]) -> None:
        """build_graph names the computer node after socket.gethostname()."""
        real = socket.gethostname()
        for node in nodes:
            node["label"] = str(node["label"]).replace(real, FAKE_HOSTNAME)
            node["title"] = str(node["title"]).replace(real, FAKE_HOSTNAME)

    def _subtitle(self, nodes: list[JsonObject], zones: dict[str, list[str]]) -> str:
        wan = dict(FAKE_WAN)
        devices = len(zones["local"]) - 1  # the gateway is not a device
        hop_count = sum(1 for node in nodes if node["group"] == "hop")
        wan_note = f"WAN {wan['ip']} ({wan['asn']} · {wan['org']})"
        return f"{devices} devices · {hop_count} hops to {MAP_TARGET}  ·  {wan_note}"


class Gallery:
    """Composition root: every README image, written to docs/img."""

    def __init__(self, workspace: Workspace) -> None:
        self._ws = workspace

    def write_svgs(self) -> None:
        runner, svg = Runner(self._ws), SvgRenderer()
        IMAGE_DIR.mkdir(parents=True, exist_ok=True)
        for shot in self._shots():
            image = IMAGE_DIR / f"{shot.name}.svg"
            image.write_text(svg.render(runner.capture(shot), shot.title()))
            sys.stderr.write(f"wrote {image.relative_to(ROOT)}\n")

    def write_map(self) -> None:
        MapRenderer(self._ws).render(MAP_IMAGE)
        sys.stderr.write(f"wrote {MAP_IMAGE.relative_to(ROOT)}\n")

    def _shots(self) -> list[Shot]:
        changed = self._ws.diff_fixture
        history = {"IFPRETTY_HISTORY": str(self._ws.history)}
        return [
            Shot("default"),
            Shot("verbose", ("-v",)),
            Shot("records", ("-r",)),
            Shot("table", ("-t",)),
            Shot("linux", fixture=LINUX_FIXTURE),
            Shot("interfaces", ("en0", "en1")),
            Shot("live", ("-l",)),
            Shot("check", ("-c",)),
            Shot("wan", ("-w",)),
            Shot("diff", ("-d",), fixture=changed, before=MAC_FIXTURE),
            Shot("explain", ("-x", "en0")),
            Shot("graph", ("-v", HISTORY_IFACE), env=history),
            Shot("live-diff", ("-l", "-d"), fixture=changed, before=MAC_FIXTURE),
        ]


class Main:
    """Command line: parse the flags, build the workspace, write the images."""

    def generate(self, argv: list[str]) -> int:
        if sys.platform != "darwin":
            sys.stderr.write("make_images: macOS only (--live/--check paths)\n")
            return 1
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--svg-only", action="store_true", help="skip the PNG")
        args = parser.parse_args(argv)
        with tempfile.TemporaryDirectory(prefix="ifpretty-img-") as scratch_dir:
            gallery = Gallery(Workspace(Path(scratch_dir)).build())
            gallery.write_svgs()
            if not args.svg_only:
                gallery.write_map()
        return 0


if __name__ == "__main__":
    raise SystemExit(Main().generate(sys.argv[1:]))
