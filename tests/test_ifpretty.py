"""Snapshot tests for ifpretty.

Output is deterministic given input (NO_COLOR + piped stdin → fixed widths),
so each layout is pinned to a golden file. Run: python3 -m unittest -v
(from /Users/iklo/scripts). Regenerate goldens intentionally with REGEN=1.
"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).parent
SRC = HERE.parent / "src"
FIXTURES = HERE / "fixtures"
SAMPLE = FIXTURES / "sample.txt"

MODES = {
    "boxed": [],
    "records": ["--records"],
    "table": ["--table"],
    "boxed_v": ["-v"],
    "records_v": ["--records", "-v"],
    "table_v": ["--table", "-v"],
}


def run(flags, stdin_text, history="/nonexistent/ifpretty-history.csv"):
    # Isolate the bandwidth datastore so layout snapshots never pick up real
    # recorded history (which would be non-deterministic). Run the package
    # in-place via `python -m ifpretty` (PYTHONPATH=src), no install needed.
    env = {
        **os.environ,
        "NO_COLOR": "1",
        "IFPRETTY_HISTORY": history,
        "IFPRETTY_CACHE": "/nonexistent/ifpretty-cache",  # force bundled OUI, no WAN cache
        "PYTHONPATH": str(SRC),
    }
    return subprocess.run(
        [sys.executable, "-m", "ifpretty", *flags],
        input=stdin_text,
        capture_output=True,
        text=True,
        env=env,
    )


class SnapshotTest(unittest.TestCase):
    def test_layouts_match_golden(self):
        sample = SAMPLE.read_text()
        for name, flags in MODES.items():
            with self.subTest(mode=name):
                result = run(flags, sample)
                self.assertEqual(result.returncode, 0, result.stderr)
                golden = FIXTURES / f"golden_{name}.txt"
                if os.environ.get("REGEN"):
                    golden.write_text(result.stdout)
                self.assertEqual(
                    result.stdout,
                    golden.read_text(),
                    f"{name} layout drifted from {golden.name}",
                )

    def test_empty_input_fails_loudly(self):
        result = run([], "\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn("no interface data", result.stderr)

    def test_acquire_input_runs_ifconfig_when_not_piped(self):
        from unittest import mock

        sys.path.insert(0, str(SRC))
        from ifpretty import cli

        fake = mock.Mock(stdout="en0: flags=1<UP> mtu 1500\n")
        with (
            mock.patch.object(cli.subprocess, "run", return_value=fake) as run_mock,
            mock.patch.object(cli.sys.stdin, "isatty", return_value=True),
        ):
            out = cli.acquire_input(["en0"])
        self.assertEqual(out, fake.stdout)
        self.assertEqual(run_mock.call_args[0][0], ["ifconfig", "en0"])

    def test_acquire_input_reads_stdin_when_piped(self):
        from unittest import mock

        sys.path.insert(0, str(SRC))
        from ifpretty import cli

        with (
            mock.patch.object(cli.sys.stdin, "isatty", return_value=False),
            mock.patch.object(cli.sys.stdin, "read", return_value="piped data"),
        ):
            self.assertEqual(cli.acquire_input([]), "piped data")

    def test_explain_appends_legend(self):
        result = run(["--explain"], SAMPLE.read_text())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Legend", result.stdout)
        self.assertIn("interface is up", result.stdout)  # UP flag
        self.assertIn("TCP segmentation offload", result.stdout)  # TSO4 option

    @unittest.skipUnless(sys.platform == "darwin", "--live is macOS-only")
    def test_live_runs_clean(self):
        # Counters/route are non-deterministic, so just assert it doesn't crash.
        result = run(["--live", "--records"], SAMPLE.read_text())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bandwidth_sparkline_from_history(self):
        # Controlled history: en0 transfers 7.5 MB in 60s = 1.0 Mbps down.
        import tempfile

        now = int(__import__("time").time())
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as fh:
            fh.write(f"{now - 60},en0,0,0\n{now},en0,7500000,0\n")
            hist = fh.name
        try:
            result = run(["--records"], SAMPLE.read_text(), history=hist)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("1h in", result.stdout)
            self.assertIn("1.0 Mbps", result.stdout)  # 7.5 MB / 60 s, in bits
        finally:
            os.unlink(hist)

    def test_fetch_wan_parses_and_caches(self):
        import tempfile
        from unittest import mock

        sys.path.insert(0, str(SRC))
        from ifpretty import enrich

        payload = json.dumps(
            {
                "ip": "203.0.113.5",
                "asn": "AS13335",
                "org": "Cloudflare, Inc.",
                "city": "São Paulo",
                "country_code": "BR",
            }
        ).encode()
        fake = mock.MagicMock()
        fake.read.return_value = payload
        fake.__enter__.return_value = fake
        with tempfile.TemporaryDirectory() as cache:
            with (
                mock.patch.object(enrich, "_CACHE_DIR", Path(cache)),
                mock.patch.object(enrich.urllib.request, "urlopen", return_value=fake),
            ):
                data = enrich.fetch_wan()
                self.assertEqual(data["ip"], "203.0.113.5")
                self.assertEqual(data["asn"], "AS13335")
                self.assertTrue((Path(cache) / "wan.json").exists())  # cached
                # second call serves from cache (urlopen would now raise)
                with mock.patch.object(
                    enrich.urllib.request, "urlopen", side_effect=OSError("no net")
                ):
                    self.assertEqual(enrich.fetch_wan()["ip"], "203.0.113.5")

    def test_update_oui_writes_cache(self):
        import tempfile
        from unittest import mock

        sys.path.insert(0, str(SRC))
        from ifpretty import enrich

        # A0B1C2: first octet 0xA0 is universal + unicast, so vendor lookup applies.
        csv_text = (
            "Registry,Assignment,Organization Name,Organization Address\r\n"
            'MA-L,A0B1C2,"Acme Corp","somewhere"\r\n'
        ).encode()
        fake = mock.MagicMock()
        fake.read.return_value = csv_text
        fake.__enter__.return_value = fake
        with tempfile.TemporaryDirectory() as cache:
            with (
                mock.patch.object(enrich, "_CACHE_DIR", Path(cache)),
                mock.patch.object(enrich.urllib.request, "urlopen", return_value=fake),
            ):
                self.assertEqual(enrich.update_oui(), 0)
                self.assertTrue((Path(cache) / "oui.tsv.gz").exists())
                self.assertEqual(enrich.mac_vendor("a0:b1:c2:00:11:22"), "Acme Corp")

    def test_diff_snapshots(self):
        sys.path.insert(0, str(SRC))
        from ifpretty import enrich

        base = {
            "up": True,
            "status": "active",
            "mtu": "1500",
            "ether": "aa:bb",
            "flags": [],
            "media": "",
            "gateway": "",
            "inet": [],
            "inet6": [],
        }
        old = {
            "en0": {**base, "inet": ["192.168.1.10/24"]},
            "en1": {**base},
        }
        new = {
            "en0": {**base, "inet": ["192.168.1.20/24"], "up": False},
            "en2": {**base},
        }
        out = "\n".join(enrich.diff_snapshots(old, new))
        self.assertIn("+ en2", out)  # appeared
        self.assertIn("- en1", out)  # removed
        self.assertIn("~ en0", out)  # changed
        self.assertIn("+192.168.1.20/24", out)  # address added
        self.assertIn("-192.168.1.10/24", out)  # address removed
        self.assertIn("up → down", out)  # state change
        # identical snapshots → no change lines
        self.assertEqual(enrich.diff_snapshots(old, old), [])

    def test_diff_flag_runs_clean(self):
        # No baseline (cache isolated) → "baseline" notice, then normal output.
        result = run(["--diff", "--records"], SAMPLE.read_text())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("baseline", result.stdout)


if __name__ == "__main__":
    unittest.main()
