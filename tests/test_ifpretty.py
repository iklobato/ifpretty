"""Snapshot tests for ifpretty.

Output is deterministic given input (NO_COLOR + piped stdin → fixed widths),
so each layout is pinned to a golden file. Run: python3 -m unittest -v
(from /Users/iklo/scripts). Regenerate goldens intentionally with REGEN=1.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).parent
SRC = HERE.parent / "src"
FIXTURES = HERE / "fixtures"
SAMPLE = FIXTURES / "sample.txt"
# rich honors FORCE_COLOR over NO_COLOR's "no styles", so a shell exporting it
# would turn the plain-text goldens into ANSI. Strip it from child envs.
COLOR_FORCING_VAR = "FORCE_COLOR"
OUI_CSV = b"Registry,Assignment,Organization Name\r\nMA-L,A0B1C2,Acme\r\n"

MODES = {
    "boxed": [],
    "records": ["--records"],
    "table": ["--table"],
    "boxed_v": ["-v"],
    "records_v": ["--records", "-v"],
    "table_v": ["--table", "-v"],
}


def run(flags, stdin_text, history=None):
    # Fresh temp history + cache per call, so no --diff baseline leaks between
    # tests ("/nonexistent" is creatable by root on Linux). PYTHONPATH=src.
    with tempfile.TemporaryDirectory() as scratch:
        env = os.environ.copy()
        env.pop(COLOR_FORCING_VAR, None)
        env.update(
            NO_COLOR="1",
            IFPRETTY_HISTORY=history or str(Path(scratch) / "history.csv"),
            IFPRETTY_CACHE=str(Path(scratch) / "cache"),  # bundled OUI, no WAN cache
            PYTHONPATH=str(SRC),
        )
        return subprocess.run(
            [sys.executable, "-m", "ifpretty", *flags],
            input=stdin_text,
            capture_output=True,
            text=True,
            env=env,
            check=False,
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
        with (
            tempfile.TemporaryDirectory() as cache,
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
            b"Registry,Assignment,Organization Name,Organization Address\r\n"
            b'MA-L,A0B1C2,"Acme Corp","somewhere"\r\n'
        )
        fake = mock.MagicMock()
        fake.read.return_value = csv_text
        fake.__enter__.return_value = fake
        with (
            tempfile.TemporaryDirectory() as cache,
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


LINUX_SAMPLE = FIXTURES / "sample_linux.txt"


class LinuxSnapshotTest(unittest.TestCase):
    """Linux net-tools layouts, pinned like the macOS ones (REGEN=1 rewrites)."""

    def _check_golden(self, mode: str, output: str) -> None:
        golden = FIXTURES / f"golden_linux_{mode}.txt"
        if os.environ.get("REGEN"):
            golden.write_text(output)
        self.assertEqual(output, golden.read_text(), f"linux {mode} drifted")

    def test_linux_layouts_match_golden(self) -> None:
        sample = LINUX_SAMPLE.read_text()
        for mode, flags in MODES.items():
            with self.subTest(mode=mode):
                completed = run(flags, sample)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self._check_golden(mode, completed.stdout)


IFCONFIG_TEXT = "en0: flags=1<UP> mtu 1500\n"
PIPED_TEXT = "piped data"
EXECUTABLE_MODE = 0o755


class AcquireInputTest(unittest.TestCase):
    """stdin is read only when something was piped or redirected in."""

    def _acquire_with_stdin_mode(self, st_mode: int) -> tuple[str, list[str] | None]:
        """Run acquire_input with stdin of this file type; return (text, ifconfig argv)."""
        from unittest import mock

        sys.path.insert(0, str(SRC))
        from ifpretty import cli

        ifconfig_result = mock.Mock(stdout=IFCONFIG_TEXT)
        fake_stdin = mock.Mock(fileno=lambda: 0, read=lambda: PIPED_TEXT)
        with (
            mock.patch.object(
                cli.subprocess, "run", return_value=ifconfig_result
            ) as ran,
            mock.patch.object(cli.sys, "stdin", fake_stdin),
            mock.patch.object(cli.os, "fstat", return_value=mock.Mock(st_mode=st_mode)),
        ):
            text = cli.acquire_input(["en0"])
        return text, ran.call_args[0][0] if ran.called else None

    def test_tty_runs_ifconfig(self) -> None:
        self.assertEqual(
            self._acquire_with_stdin_mode(stat.S_IFCHR),
            (IFCONFIG_TEXT, ["ifconfig", "en0"]),
        )

    def test_socket_runs_ifconfig(self) -> None:
        self.assertEqual(
            self._acquire_with_stdin_mode(stat.S_IFSOCK),
            (IFCONFIG_TEXT, ["ifconfig", "en0"]),
        )

    def test_pipe_is_read(self) -> None:
        self.assertEqual(
            self._acquire_with_stdin_mode(stat.S_IFIFO), (PIPED_TEXT, None)
        )

    def test_redirected_file_is_read(self) -> None:
        self.assertEqual(
            self._acquire_with_stdin_mode(stat.S_IFREG), (PIPED_TEXT, None)
        )

    def test_closed_stdin_runs_ifconfig(self) -> None:
        from unittest import mock

        sys.path.insert(0, str(SRC))
        from ifpretty import cli

        closed_stdin = mock.Mock(fileno=mock.Mock(side_effect=ValueError("closed")))
        with (
            mock.patch.object(
                cli.subprocess, "run", return_value=mock.Mock(stdout=IFCONFIG_TEXT)
            ),
            mock.patch.object(cli.sys, "stdin", closed_stdin),
        ):
            self.assertEqual(cli.acquire_input([]), IFCONFIG_TEXT)

    def _stub_ifconfig_env(self, bindir: str) -> dict[str, str]:
        """Env with a fake `ifconfig` first on PATH that prints the macOS sample."""
        stub = Path(bindir) / "ifconfig"
        stub.write_text(f"#!/bin/sh\ncat '{SAMPLE}'\n")
        stub.chmod(EXECUTABLE_MODE)
        env = os.environ.copy()
        env.pop(COLOR_FORCING_VAR, None)
        env.update(
            NO_COLOR="1",
            IFPRETTY_CACHE=str(Path(bindir) / "cache"),
            PYTHONPATH=str(SRC),
            PATH=bindir + os.pathsep + os.environ.get("PATH", ""),
        )
        return env

    def test_devnull_stdin_runs_ifconfig_end_to_end(self) -> None:
        # cron, CI and `docker run` without -t give /dev/null, not piped input.
        with tempfile.TemporaryDirectory() as bindir:
            completed = subprocess.run(
                [sys.executable, "-m", "ifpretty", "--records"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                env=self._stub_ifconfig_env(bindir),
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("8 interfaces", completed.stdout)


class OuiDownloadTest(unittest.TestCase):
    """standards-oui.ieee.org answers HTTP 418 to the default Python-urllib agent."""

    def test_update_oui_sends_own_user_agent(self) -> None:
        from unittest import mock

        sys.path.insert(0, str(SRC))
        from ifpretty import enrich

        response = mock.MagicMock()
        response.read.return_value = OUI_CSV
        response.__enter__.return_value = response
        with (
            tempfile.TemporaryDirectory() as cache,
            mock.patch.object(enrich, "_CACHE_DIR", Path(cache)),
            mock.patch.object(
                enrich.urllib.request, "urlopen", return_value=response
            ) as opened,
        ):
            self.assertEqual(enrich.update_oui(), 0)
        request = opened.call_args[0][0]
        self.assertEqual(request.full_url, "https://standards-oui.ieee.org/oui/oui.csv")
        self.assertTrue(request.get_header("User-agent", "").startswith("ifpretty "))


class OuiTlsFallbackTest(unittest.TestCase):
    """macOS Python reads /etc/ssl/cert.pem, which can miss a root the Keychain
    trusts (IEEE's GlobalSign Root R46); curl uses the Keychain, so retry there."""

    def _update_with(
        self, url_error: Exception, curl_output: str | None
    ) -> tuple[int, list[str] | None]:
        """Run update_oui with urlopen raising url_error; return (exit code, curl argv)."""
        from unittest import mock

        sys.path.insert(0, str(SRC))
        from ifpretty import enrich

        with (
            tempfile.TemporaryDirectory() as cache,
            mock.patch.object(enrich, "_CACHE_DIR", Path(cache)),
            mock.patch.object(enrich.urllib.request, "urlopen", side_effect=url_error),
            mock.patch.object(enrich, "_run", return_value=curl_output) as ran,
            mock.patch("sys.stderr"),
        ):
            code = enrich.update_oui()
        return code, ran.call_args[0][0] if ran.called else None

    def test_cert_error_falls_back_to_curl(self) -> None:
        import ssl
        import urllib.error

        cert_error = urllib.error.URLError(ssl.SSLCertVerificationError("self-signed"))
        code, argv = self._update_with(cert_error, OUI_CSV.decode())
        self.assertEqual(code, 0)
        self.assertEqual(argv[0], "curl")
        self.assertIn("https://standards-oui.ieee.org/oui/oui.csv", argv)
        self.assertTrue(argv[argv.index("-A") + 1].startswith("ifpretty "))

    def test_cert_error_and_curl_failing_exits_1(self) -> None:
        import ssl
        import urllib.error

        cert_error = urllib.error.URLError(ssl.SSLCertVerificationError("self-signed"))
        self.assertEqual(self._update_with(cert_error, None)[0], 1)

    def test_other_network_error_does_not_try_curl(self) -> None:
        import urllib.error

        code, argv = self._update_with(
            urllib.error.URLError("timed out"), OUI_CSV.decode()
        )
        self.assertEqual((code, argv), (1, None))


if __name__ == "__main__":
    unittest.main()
