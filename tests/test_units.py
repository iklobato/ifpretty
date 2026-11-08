"""Unit tests for ifpretty's pure logic — parsing, derivation, formatting,
graph math, diffing, and the system-command parsers (with mocked I/O).

These target real bugs (off-by-one column shifts, scope/EUI-64 classification,
humanizer boundaries, alignment, counter-reset clamping) rather than snapshots.
Run: python3 tests/test_units.py
"""

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

SRC = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(SRC))

from ifpretty import cli, enrich, formatting, model, parse, render, topology  # noqa
from ifpretty.model import Inet, Inet6, Interface  # noqa: E402
from rich.text import Text  # noqa: E402


def plain(markup: str) -> str:
    """Visible text of a rich-markup string (what the user actually sees)."""
    return Text.from_markup(markup).plain


def iface(name="en0", **kw) -> Interface:
    return Interface(name=name, **kw)


# ── parsing ───────────────────────────────────────────────────────────────────
class HexmaskTest(unittest.TestCase):
    def test_common(self):
        self.assertEqual(parse.hexmask_to_cidr("0xffffff00"), "255.255.255.0/24")
        self.assertEqual(parse.hexmask_to_cidr("0xff000000"), "255.0.0.0/8")
        self.assertEqual(parse.hexmask_to_cidr("0xffffffff"), "255.255.255.255/32")
        self.assertEqual(parse.hexmask_to_cidr("0x0"), "0.0.0.0/0")

    def test_invalid_passthrough(self):
        self.assertEqual(parse.hexmask_to_cidr("garbage"), "garbage")


class ParseTest(unittest.TestCase):
    SAMPLE = (
        "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n"
        "\tinet 127.0.0.1 netmask 0xff000000\n"
        "\tinet6 ::1 prefixlen 128\n"
        "\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1\n"
        "stf0: flags=0<> mtu 1280\n"
        "en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n"
        "\tether 14:7d:da:00:00:01\n"
        "\tinet 192.168.1.10 netmask 0xffffff00 broadcast 192.168.1.255\n"
        "\tinet6 2001:470::1 prefixlen 64 autoconf secured\n"
        "\tmedia: autoselect (1000baseT <full-duplex>)\n"
        "\tstatus: active\n"
        "bridge0: flags=8863<UP,BROADCAST> mtu 1500\n"
        "\tConfiguration:\n"
        "\t\tid 0:0:0:0:0:0 priority 0\n"
    )

    def setUp(self):
        self.ifaces = {i.name: i for i in parse.parse(self.SAMPLE)}

    def test_all_interfaces_found(self):
        self.assertEqual(set(self.ifaces), {"lo0", "stf0", "en0", "bridge0"})

    def test_flags_and_mtu(self):
        self.assertEqual(self.ifaces["lo0"].mtu, "16384")
        self.assertIn("UP", self.ifaces["lo0"].flags)
        self.assertEqual(self.ifaces["stf0"].flags, [])  # flags=0<>

    def test_inet_parsed(self):
        v4 = self.ifaces["en0"].inet[0]
        self.assertEqual(v4.addr, "192.168.1.10")
        self.assertEqual(v4.netmask, "255.255.255.0/24")
        self.assertEqual(v4.broadcast, "192.168.1.255")

    def test_inet6_attrs_and_prefixlen(self):
        lo6 = self.ifaces["lo0"].inet6
        self.assertEqual(lo6[0].addr, "::1")
        self.assertEqual(lo6[0].prefixlen, "128")
        en6 = self.ifaces["en0"].inet6[0]
        self.assertEqual(en6.prefixlen, "64")
        self.assertEqual(en6.attrs, ("autoconf", "secured"))  # scopeid excluded

    def test_ether_status_media(self):
        en0 = self.ifaces["en0"]
        self.assertEqual(en0.ether, "14:7d:da:00:00:01")
        self.assertEqual(en0.status, "active")
        self.assertIn("1000baseT", en0.media)

    def test_unmodeled_lines_go_to_other(self):
        self.assertTrue(
            any("id 0:0:0:0:0:0" in o for o in self.ifaces["bridge0"].other)
        )

    def test_blank_and_garbage_safe(self):
        self.assertEqual(parse.parse(""), [])
        self.assertEqual(parse.parse("\n\n"), [])


class KvPairsTest(unittest.TestCase):
    def test_word_number_pairs(self):
        self.assertEqual(
            parse.kv_pairs("id 0:0:0:0:0:0 priority 0 hellotime 0"),
            [("id", "0:0:0:0:0:0"), ("priority", "0"), ("hellotime", "0")],
        )

    def test_multiword_key(self):
        self.assertIn(("path cost", "0"), parse.kv_pairs("path cost 0"))
        self.assertIn(
            ("root id", "0:0:0:0:0:0"), parse.kv_pairs("root id 0:0:0:0:0:0 port 0")
        )

    def test_alpha_value_word(self):
        self.assertIn(("proto", "stp"), parse.kv_pairs("proto stp maxaddr 100"))

    def test_flag_blob_and_label(self):
        pairs = parse.kv_pairs("member: en1 flags=3<LEARNING,DISCOVER>")
        self.assertIn(("member", "en1"), pairs)
        self.assertIn(("flags", "LEARNING  DISCOVER"), pairs)

    def test_header_phrase(self):
        self.assertEqual(parse.kv_pairs("Address cache:"), [("Address cache", "")])


# ── Tier-1 derivations ─────────────────────────────────────────────────────────
class DerivationTest(unittest.TestCase):
    def test_interface_role(self):
        self.assertEqual(model.interface_role("lo0"), "loopback")
        self.assertEqual(model.interface_role("en0"), "Ethernet/Wi-Fi")
        self.assertEqual(model.interface_role("utun3"), "VPN/tunnel")
        self.assertEqual(model.interface_role("bridge0"), "bridge")
        self.assertEqual(model.interface_role("zzz9"), "")

    def test_mac_kind(self):
        self.assertEqual(enrich.mac_kind("14:7d:da:00:00:01"), "universal")
        self.assertEqual(enrich.mac_kind("82:00:00:00:00:01"), "locally administered")
        self.assertEqual(enrich.mac_kind("01:00:5e:00:00:01"), "multicast")
        self.assertEqual(enrich.mac_kind(""), "")

    def test_ip_scope_v4(self):
        self.assertEqual(enrich.ip_scope("127.0.0.1"), "loopback")
        self.assertEqual(enrich.ip_scope("169.254.1.1"), "link-local")
        self.assertEqual(enrich.ip_scope("192.168.1.1"), "private")
        self.assertEqual(enrich.ip_scope("8.8.8.8"), "global")
        self.assertEqual(enrich.ip_scope("not-an-ip"), "")

    def test_ip_scope_v6(self):
        self.assertEqual(enrich.ip_scope("::1"), "loopback")
        self.assertEqual(enrich.ip_scope("fe80::1%en0"), "link-local")
        self.assertEqual(enrich.ip_scope("fd00::1"), "ULA")
        self.assertEqual(enrich.ip_scope("2001:470::1"), "global")

    def test_ipv4_net_info(self):
        self.assertEqual(
            enrich.ipv4_net_info(Inet("192.168.1.10", "255.255.255.0/24")),
            "net 192.168.1.0/24 · 254 hosts",
        )
        self.assertEqual(enrich.ipv4_net_info(Inet("10.0.0.1", "")), "")

    def test_is_eui64(self):
        self.assertTrue(enrich.is_eui64("fe80::021b:63ff:fe84:45e6"))  # ff:fe present
        self.assertFalse(enrich.is_eui64("fe80::829:2be5:a6d5:99b5"))  # privacy/secured
        self.assertFalse(enrich.is_eui64("::1"))
        self.assertFalse(enrich.is_eui64("192.168.1.1"))  # not v6

    def test_mtu_note(self):
        self.assertIn("jumbo", plain(formatting.mtu_note("9000")))
        self.assertIn("below", plain(formatting.mtu_note("1000")))
        self.assertEqual(formatting.mtu_note("1500"), "")
        self.assertEqual(formatting.mtu_note("1280"), "")  # IPv6 min is normal

    def test_derive_shared_macs(self):
        a = iface("en1", ether="aa:bb:cc:dd:ee:ff")
        b = iface("bridge0", ether="aa:bb:cc:dd:ee:ff")
        c = iface("en2", ether="11:22:33:44:55:66")
        enrich.derive_shared_macs([a, b, c])
        self.assertEqual(a.shares_mac_with, ["bridge0"])
        self.assertEqual(b.shares_mac_with, ["en1"])
        self.assertEqual(c.shares_mac_with, [])

    def test_mac_vendor_uses_oui(self):
        self.addCleanup(setattr, enrich, "_OUI", None)
        enrich._OUI = {"A0B1C2": "Acme Corp"}
        self.assertEqual(
            enrich.mac_vendor("a0:b1:c2:00:11:22"), "Acme Corp"
        )  # universal
        self.assertEqual(
            enrich.mac_vendor("a2:b1:c2:00:11:22"), ""
        )  # locally administered
        self.assertEqual(enrich.mac_vendor("a0:b1:c3:00:11:22"), "")  # unknown prefix


# ── humanizers + graph math ────────────────────────────────────────────────────
class HumanizeTest(unittest.TestCase):
    def test_bytes(self):
        self.assertEqual(formatting.humanize_bytes(0), "0 B")
        self.assertEqual(formatting.humanize_bytes(1023), "1023 B")
        self.assertEqual(formatting.humanize_bytes(1024), "1.0 KB")
        self.assertEqual(formatting.humanize_bytes(1536), "1.5 KB")
        self.assertEqual(formatting.humanize_bytes(1048576), "1.0 MB")
        self.assertEqual(formatting.humanize_bytes(1024**4), "1.0 TB")
        self.assertEqual(
            formatting.humanize_bytes(1024**5), "1.0 PB"
        )  # was wrongly "1024.0 TB"
        self.assertEqual(formatting.humanize_bytes(-1), "")

    def test_count(self):
        self.assertEqual(formatting.humanize_count(999), "999")
        self.assertEqual(formatting.humanize_count(1000), "1.0k")
        self.assertEqual(formatting.humanize_count(1_500_000), "1.5M")
        self.assertEqual(formatting.humanize_count(-1), "")

    def test_secs(self):
        self.assertEqual(formatting.humanize_secs(30), "30s")
        self.assertEqual(formatting.humanize_secs(90), "1m")
        self.assertEqual(formatting.humanize_secs(3600), "1h")
        self.assertEqual(formatting.humanize_secs(90000), "1d")
        self.assertEqual(formatting.humanize_secs(-1), "")

    def test_rate(self):
        self.assertEqual(formatting.humanize_rate(0), "0 bps")
        self.assertEqual(
            formatting.humanize_rate(125000), "1.0 Mbps"
        )  # bytes/s → bits/s


class GraphMathTest(unittest.TestCase):
    def test_sparkline(self):
        self.assertEqual(formatting.sparkline([]), "")
        self.assertEqual(
            formatting.sparkline([0, 0, 0]), "▁▁▁"
        )  # all-zero scales safely
        spark = formatting.sparkline([0, 50, 100])
        self.assertEqual(len(spark), 3)
        self.assertEqual(spark[0], "▁")
        self.assertEqual(spark[-1], "█")

    def test_bar(self):
        self.assertEqual(formatting.bar(0.0, 10), "░" * 10)
        self.assertEqual(formatting.bar(1.0, 10), "█" * 10)
        self.assertEqual(formatting.bar(0.5, 10), "█████░░░░░")
        self.assertEqual(formatting.bar(2.0, 10), "█" * 10)  # clamped

    def test_link_mbps(self):
        self.assertEqual(enrich.link_mbps("autoselect (1000baseT <full-duplex>)"), 1000)
        self.assertEqual(enrich.link_mbps("10GbaseT"), 10000)
        self.assertEqual(enrich.link_mbps("100baseTX"), 100)
        self.assertEqual(enrich.link_mbps("autoselect"), 0)

    def test_rates_clamps_reset(self):
        # (ts, rx, tx): normal rise, then a counter reset (reboot) → clamp to 0.
        pts = [(0, 0, 0), (10, 1000, 500), (20, 0, 0)]
        rx, tx = enrich._rates(pts)
        self.assertEqual(rx, [100.0, 0.0])  # 1000/10, then reset→0
        self.assertEqual(tx, [50.0, 0.0])

    def test_rates_skips_nonpositive_dt(self):
        rx, tx = enrich._rates([(5, 0, 0), (5, 100, 100)])  # dt == 0
        self.assertEqual((rx, tx), ([], []))

    def test_media_note(self):
        self.assertEqual(
            plain(formatting.media_note("autoselect (1000baseT <full-duplex>)")),
            "   · 1 Gbps full-duplex",
        )
        self.assertIn(
            "half-duplex", plain(formatting.media_note("100baseTX <half-duplex>"))
        )
        self.assertEqual(formatting.media_note("autoselect"), "")
        self.assertEqual(formatting.media_note(""), "")


# ── formatters ─────────────────────────────────────────────────────────────────
class FormatterTest(unittest.TestCase):
    def test_inet_detail(self):
        out = plain(
            formatting.inet_detail(
                Inet("192.168.1.10", "255.255.255.0/24", "192.168.1.255")
            )
        )
        self.assertIn("192.168.1.10", out)
        self.assertIn("netmask 255.255.255.0/24", out)
        self.assertIn("broadcast 192.168.1.255", out)
        self.assertIn("private", out)
        self.assertIn("254 hosts", out)

    def test_inet6_aligned_scope_and_eui64(self):
        layout = formatting.plan_inet6([Inet6("fe80::021b:63ff:fe84:45e6", "64", ())])
        out = plain(
            formatting.fmt_inet6_aligned(
                Inet6("fe80::021b:63ff:fe84:45e6", "64", ()), layout
            )
        )
        self.assertIn("link-local", out)
        self.assertIn("EUI-64", out)

    def test_ether_value(self):
        self.addCleanup(setattr, enrich, "_OUI", None)
        enrich._OUI = {"147DDA": "Apple, Inc."}
        i = iface(ether="14:7d:da:00:00:01", shares_mac_with=["en1"])
        out = plain(formatting.ether_value(i))
        self.assertIn("14:7d:da:00:00:01", out)
        self.assertIn("universal", out)
        self.assertIn("Apple, Inc.", out)
        self.assertIn("shared with en1", out)

    def test_gateway_value(self):
        self.assertIn(
            "1.5 ms",
            plain(
                formatting.gateway_value(
                    iface(gateway="192.168.1.1", gw_latency_ms=1.5)
                )
            ),
        )
        self.assertIn(
            "unreachable",
            plain(formatting.gateway_value(iface(gateway="192.168.1.1", gw_loss=True))),
        )
        self.assertEqual(formatting.gateway_value(iface()), "")

    def test_traffic_and_errors(self):
        i = iface(
            rx_bytes=2048,
            tx_bytes=1024,
            rx_pkts=10,
            tx_pkts=5,
            rx_errs=3,
            tx_errs=0,
            collisions=1,
        )
        self.assertIn("2.0 KB", plain(formatting.traffic_value(i)))
        self.assertIn("(10 pkts)", plain(formatting.traffic_value(i)))
        self.assertEqual(plain(formatting.errors_value(i)), "in 3  out 0  coll 1")
        self.assertEqual(formatting.errors_value(iface()), "")  # no --live data

    def test_dhcp_value(self):
        self.assertEqual(
            plain(
                formatting.dhcp_value(iface(dhcp_server="192.168.1.1", dhcp_lease=3600))
            ),
            "192.168.1.1   · lease 1h",
        )
        self.assertEqual(formatting.dhcp_value(iface()), "")

    def test_bandwidth_rows(self):
        i = iface(
            rx_hist=[0.0, 125000.0],
            tx_hist=[0.0, 0.0],
            media="autoselect (1000baseT <full-duplex>)",
        )
        labels = {lbl for lbl, _ in formatting.bandwidth_rows(i)}
        self.assertEqual(labels, {"1h in", "1h out", "link use"})

    def test_is_minor(self):
        self.assertTrue(formatting.is_minor(iface(flags=[])))  # down, no addr
        self.assertTrue(
            formatting.is_minor(iface(flags=["UP"], inet6=[Inet6("fe80::1", "64")]))
        )  # link-local only
        self.assertFalse(
            formatting.is_minor(
                iface(flags=["UP"], inet=[Inet("192.168.1.2", "255.255.255.0/24")])
            )
        )

    def test_essential_annotation_column_aligned(self):
        i = iface(
            mtu="1500",
            ether="14:7d:da:00:00:01",
            inet=[Inet("192.168.1.10", "255.255.255.0/24")],
            inet6=[Inet6("2001:470::1", "64", ("autoconf",))],
        )
        rows = formatting.interface_fields(i, verbose=False)
        cols = {plain(v).index("·") for _, v in rows if "·" in plain(v)}
        self.assertEqual(len(cols), 1, f"· not column-aligned: {cols}")

    def test_essential_hides_link_local_verbose_shows_all(self):
        i = iface(
            flags=["UP", "BROADCAST"],
            options=["TSO4"],
            inet6=[Inet6("fe80::1", "64"), Inet6("2001:470::1", "64", ("autoconf",))],
        )
        ess = "\n".join(
            f"{lbl}:{plain(v)}"
            for lbl, v in formatting.interface_fields(i, verbose=False)
        )
        self.assertNotIn("fe80::1", ess)  # link-local hidden in essentials
        self.assertIn("2001:470::1", ess)  # global shown
        self.assertNotIn("flags:", ess)  # flags are detail-only

        verb = "\n".join(
            f"{lbl}:{plain(v)}"
            for lbl, v in formatting.interface_fields(i, verbose=True)
        )
        self.assertIn("fe80::1", verb)  # link-local shown in verbose
        self.assertIn("TSO4", verb)  # options shown

    def test_inet6_slot_columns_align_across_rows(self):
        rows = [
            Inet6("fe80::1", "64", ("secured",)),
            Inet6("2001:470::1", "64", ("autoconf", "secured")),
            Inet6("fddf::1", "64", ("deprecated", "autoconf", "temporary")),
        ]
        layout = formatting.plan_inet6(rows)
        rendered = [plain(formatting.fmt_inet6_aligned(x, layout)) for x in rows]
        # the "·" scope marker must land in the same column for every row
        cols = {line.index("·") for line in rendered}
        self.assertEqual(len(cols), 1, f"slot columns misaligned: {rendered}")
        # all attributes are preserved
        joined = "\n".join(rendered)
        for attr in ("secured", "autoconf", "temporary", "deprecated"):
            self.assertIn(attr, joined)

    def test_v6_slotted_categorizes_and_keeps_extras(self):
        slots, extra = formatting._v6_slotted(
            ("deprecated", "autoconf", "temporary", "clat46")
        )
        self.assertEqual(slots["state"], "deprecated")
        self.assertEqual(slots["config"], "autoconf")
        self.assertEqual(slots["source"], "temporary")
        self.assertEqual(extra, ["clat46"])  # unknown attr preserved, not dropped


# ── snapshot / diff ─────────────────────────────────────────────────────────────
class SnapshotDiffTest(unittest.TestCase):
    def test_snapshot_state_shape(self):
        i = iface(
            flags=["UP"],
            mtu="1500",
            ether="aa:bb",
            inet=[Inet("192.168.1.2", "255.255.255.0/24")],
            inet6=[Inet6("fe80::1", "64")],
        )
        st = enrich.snapshot_state([i])["en0"]
        self.assertTrue(st["up"])
        self.assertEqual(st["inet"], ["192.168.1.2/24"])
        self.assertEqual(st["inet6"], ["fe80::1/64"])

    def test_diff_added_removed_changed(self):
        base = {
            "up": True,
            "status": "",
            "mtu": "1500",
            "ether": "aa:bb",
            "flags": [],
            "media": "",
            "gateway": "",
            "inet": [],
            "inet6": [],
        }
        old = {"en0": {**base, "inet": ["192.168.1.10/24"]}, "en1": dict(base)}
        new = {
            "en0": {**base, "inet": ["192.168.1.20/24"], "up": False},
            "en2": dict(base),
        }
        out = "\n".join(plain(line) for line in enrich.diff_snapshots(old, new))
        self.assertIn("+ en2", out)
        self.assertIn("- en1", out)
        self.assertIn("~ en0", out)
        self.assertIn("up → down", out)
        self.assertIn("+192.168.1.20/24", out)
        self.assertIn("-192.168.1.10/24", out)

    def test_diff_identical_is_empty(self):
        snap = {
            "en0": {
                "up": True,
                "status": "",
                "mtu": "1500",
                "ether": "",
                "flags": [],
                "media": "",
                "gateway": "",
                "inet": [],
                "inet6": [],
            }
        }
        self.assertEqual(enrich.diff_snapshots(snap, snap), [])


# ── system-command parsers (mocked I/O) ─────────────────────────────────────────
class SystemParserTest(unittest.TestCase):
    def test_read_link_counters_with_and_without_mac(self):
        netstat = (
            "Name  Mtu   Network       Address            Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n"
            "lo0   16384 <Link#1>                          100   0     5000   100   0     5000   0\n"
            "en0   1500  <Link#6>      14:7d:da:00:00:01   200   1     9000   150   2     8000   3\n"
            "en0   1500  192.168.1/24  192.168.1.10        50    0     0      40    0     0      0\n"
        )
        with mock.patch.object(enrich, "_run", return_value=netstat):
            counters = enrich._read_link_counters()
        self.assertEqual(counters["lo0"], (100, 0, 5000, 100, 0, 5000, 0))
        self.assertEqual(
            counters["en0"], (200, 1, 9000, 150, 2, 8000, 3)
        )  # MAC col dropped

    def test_apply_default_route(self):
        out = "   route to: default\n  gateway: 192.168.1.1\n  interface: en6\n"
        by = {"en6": iface("en6")}
        with mock.patch.object(enrich, "_run", return_value=out):
            enrich._apply_default_route(by)
        self.assertTrue(by["en6"].is_default)
        self.assertEqual(by["en6"].gateway, "192.168.1.1")

    def test_apply_dns_scoped(self):
        out = (
            "resolver #1\n  nameserver[0] : 1.1.1.1\n  if_index : 6 (en0)\n\n"
            "resolver #2\n  search domain[0] : lan\n  nameserver[0] : 192.168.1.1\n"
            "  if_index : 6 (en0)\n"
        )
        by = {"en0": iface("en0")}
        with mock.patch.object(enrich, "_run", return_value=out):
            enrich._apply_dns(by)
        self.assertEqual(by["en0"].dns, ["1.1.1.1", "192.168.1.1"])
        self.assertEqual(by["en0"].search_domains, ["lan"])

    def test_apply_dhcp(self):
        by = {"en0": iface("en0", inet=[Inet("192.168.1.10", "255.255.255.0/24")])}
        with mock.patch.object(enrich, "_run", side_effect=["192.168.1.1\n", "3600\n"]):
            enrich._apply_dhcp(by)
        self.assertEqual(by["en0"].dhcp_server, "192.168.1.1")
        self.assertEqual(by["en0"].dhcp_lease, 3600)


# ── topology / browser map ──────────────────────────────────────────────────────
class TopologyTest(unittest.TestCase):
    def test_parse_traceroute(self):
        text = (
            "traceroute to 1.1.1.1 (1.1.1.1), 20 hops max\n"
            " 1  192.168.1.1  2.345 ms\n"
            " 2  * * *\n"
            " 3  100.64.0.1  10.2 ms\n"
        )
        hops = topology.parse_traceroute(text)
        self.assertEqual(
            [(h.ttl, h.ip) for h in hops],
            [(1, "192.168.1.1"), (2, ""), (3, "100.64.0.1")],
        )
        self.assertEqual(hops[0].rtt, "2.345")

    def test_parse_neighbors_skips_incomplete(self):
        text = (
            "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
            "? (192.168.1.5) at 11:22:33:44:55:66 on en0 ifscope [ethernet]\n"
            "? (192.168.1.9) at (incomplete) on en0 [ethernet]\n"
        )
        nbs = topology.parse_neighbors(text)
        self.assertEqual(
            [(n.ip, n.iface) for n in nbs],
            [("192.168.1.1", "en0"), ("192.168.1.5", "en0")],
        )

    def test_build_graph_links_path_and_devices(self):
        ifaces = [
            iface("en0", flags=["UP"], inet=[Inet("192.168.1.10", "255.255.255.0/24")])
        ]
        hops = [
            topology.Hop(1, "192.168.1.1", "2.0"),  # == gateway, deduped
            topology.Hop(2, "", ""),  # timeout, skipped
            topology.Hop(3, "100.64.0.1", "9.0"),
        ]
        nbs = [topology.Neighbor("192.168.1.5", "11:22:33:44:55:66", "en0")]
        nodes, edges, zones = topology.build_graph(
            ifaces, "192.168.1.1", "en0", hops, nbs, "1.1.1.1"
        )
        ids = {n["id"] for n in nodes}
        self.assertEqual(
            {"self", "if:en0", "gw", "hop:3", "net", "dev:192.168.1.5"} - ids, set()
        )
        self.assertNotIn("hop:1", ids)  # gateway hop not duplicated
        self.assertNotIn("hop:2", ids)  # timeout hop skipped
        pairs = {(e["from"], e["to"]) for e in edges}
        self.assertIn(("self", "if:en0"), pairs)
        self.assertIn(("if:en0", "gw"), pairs)
        self.assertIn(("gw", "hop:3"), pairs)
        self.assertIn(("hop:3", "net"), pairs)
        self.assertIn(("if:en0", "dev:192.168.1.5"), pairs)
        # three zones, each placing the right nodes
        self.assertEqual(set(zones), {"computer", "local", "internet"})
        self.assertIn("self", zones["computer"])
        self.assertIn("gw", zones["local"])
        self.assertIn("dev:192.168.1.5", zones["local"])
        self.assertIn("net", zones["internet"])

    def test_parse_ipapi_batch(self):
        items = [
            {
                "status": "success",
                "query": "1.1.1.1",
                "org": "Cloudflare",
                "isp": "Cloudflare",
                "as": "AS13335 Cloudflare",
                "country": "Australia",
                "countryCode": "AU",
                "city": "Sydney",
                "reverse": "one.one.one.one",
            },
            {"status": "fail", "query": "10.0.0.1"},  # private → dropped
        ]
        info = topology.parse_ipapi_batch(items)
        self.assertEqual(set(info), {"1.1.1.1"})
        self.assertEqual(info["1.1.1.1"]["org"], "Cloudflare")
        self.assertEqual(info["1.1.1.1"]["host"], "one.one.one.one")
        self.assertEqual(info["1.1.1.1"]["cc"], "AU")

    def test_lookup_ips_batches_public_and_rdns_private(self):
        from unittest import mock

        batch = json.dumps(
            [
                {
                    "status": "success",
                    "query": "1.1.1.1",
                    "org": "Cloudflare",
                    "as": "AS13335",
                    "country": "Australia",
                    "countryCode": "AU",
                    "reverse": "one.one.one.one",
                },
            ]
        ).encode()
        resp = mock.MagicMock()
        resp.read.return_value = batch
        resp.__enter__.return_value = resp
        with (
            mock.patch.object(topology.urllib.request, "urlopen", return_value=resp),
            mock.patch.object(
                topology.socket, "gethostbyaddr", return_value=("printer.local", [], [])
            ),
        ):
            info = topology.lookup_ips(["1.1.1.1", "192.168.1.5"])
        self.assertEqual(info["1.1.1.1"]["org"], "Cloudflare")  # public via API
        self.assertEqual(
            info["192.168.1.5"]["host"], "printer.local"
        )  # private via rDNS

    def test_build_graph_enriches_ips_from_ipinfo(self):
        ipinfo = {
            "100.64.0.1": {
                "org": "Acme ISP",
                "asn": "AS65000",
                "country": "US",
                "cc": "US",
                "host": "core.acme.net",
            },
            "1.1.1.1": {
                "org": "Cloudflare",
                "asn": "AS13335",
                "country": "AU",
                "cc": "AU",
            },
        }
        nodes, _, _ = topology.build_graph(
            [
                iface(
                    "en0", flags=["UP"], inet=[Inet("192.168.1.10", "255.255.255.0/24")]
                )
            ],
            "192.168.1.1",
            "en0",
            [topology.Hop(2, "100.64.0.1", "9.0")],
            [],
            "1.1.1.1",
            ipinfo,
        )
        hop = next(n for n in nodes if n["id"] == "hop:2")
        self.assertIn("Acme ISP", hop["label"])  # company on the node
        self.assertIn("core.acme.net", hop["title"])  # host in the tooltip
        net = next(n for n in nodes if n["id"] == "net")
        self.assertIn("Cloudflare", net["label"])

    def test_render_html_is_self_contained(self):
        nodes, edges, zones = topology.build_graph(
            [
                iface(
                    "en0", flags=["UP"], inet=[Inet("192.168.1.10", "255.255.255.0/24")]
                )
            ],
            "192.168.1.1",
            "en0",
            [],
            [],
            "1.1.1.1",
        )
        html = topology.render_html(nodes, edges, zones, "test")
        self.assertIn("vis.Network", html)
        self.assertIn("vis-network", html)  # CDN script
        self.assertIn("192.168.1.1", html)  # gateway in node data
        self.assertIn("Your computer", html)  # zone bands
        self.assertIn("beforeDrawing", html)  # zone-drawing hook
        self.assertTrue(html.lstrip().startswith("<!DOCTYPE html>"))
        self.assertTrue(html.lstrip().startswith("<!DOCTYPE html>"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
