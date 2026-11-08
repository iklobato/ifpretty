# ifpretty: project knowledge

Read this before you change, test or release ifpretty. It records what the
code does today, what was learned the hard way, what is still open and how
to ship. The README is for users; this file is for whoever works on the code
next (a person or an agent).

Scope: the work done in the session of 2026-11-08 (releases 0.13.0 to
0.14.2). Older history is only in `git log`.

## 1. Where things are

| Thing | Where |
|---|---|
| Source repo | https://github.com/iklobato/ifpretty (public, branch `main`) |
| Package | https://pypi.org/project/ifpretty/ |
| Latest release | **0.14.2** (2026-11-08 22:18 UTC), `main` at `02352c9` |
| CI | `.github/workflows/ci.yml`, runs on every push and PR |
| README pictures | `docs/img/*.svg` + `docs/img/map.png`, built by `docs/make_images.py` |
| Test fixtures | `tests/fixtures/sample.txt` (macOS), `sample_linux.txt` (net-tools), `golden_*.txt` |
| PyPI token | `PYPI_TOKEN` in the local `.env` (gitignored, never commit or print it) |

Releases still on PyPI: 0.1.0 to 0.5.0, 0.13.0, 0.13.1, 0.14.0, 0.14.1,
0.14.2. Releases 0.6.0 to 0.12.0 were **deleted on purpose** (see section 6).
Their version numbers can never be uploaded again.

## 2. What ifpretty does (current implementation)

Pipeline: acquire input, parse, enrich, render. One job per module:

| Module | Job |
|---|---|
| `cli.py` | flags, input, filter by name, wiring |
| `parse.py` | raw `ifconfig` text (macOS or Linux net-tools) to `Interface` objects |
| `model.py` | dataclasses `Inet` / `Inet6` / `Interface`, `JsonObject = dict[str, Any]`, interface roles |
| `enrich.py` | OUI vendor, scopes, `--live`, `--check`, history, `--wan`, `--update-oui`, snapshot/diff |
| `formatting.py` | model values to rich markup, field rows per view |
| `render.py` | boxed / records / table views, overview, legend, diff |
| `topology.py` | `--map`: traceroute + ARP + IP lookups to a vis-network HTML page |

Behavior added or changed in this session, with the place to look:

- **Input** (`cli.acquire_input`): reads stdin only when it is a pipe or a
  regular file (`os.fstat` + `S_ISFIFO`/`S_ISREG`). A TTY, `/dev/null`, a
  socket or a closed stdin means "run ifconfig ourselves". Before 0.13.1 a
  bare `ifpretty` with no TTY (cron, CI, `docker run` without `-t`) read an
  empty stdin and printed nothing.
- **Interface filter** (`cli.InterfaceSelection`, 0.14.2): `ifpretty en0 en1`
  runs `ifconfig -a` once and keeps the named interfaces after parsing. The
  real `ifconfig` takes one name at most (`ifconfig en0 lo0` fails with
  `lo0: bad value` on macOS and Linux), so passing the names through broke
  any filter with two names. The filter also applies to piped input. An
  unknown name prints `ifpretty: no interface named X`; if nothing matches,
  exit code 1. A bare `ifpretty` still runs plain `ifconfig` (no `-a`).
- **Linux parsing** (`parse.py`, 0.14.0): net-tools 2.x format. `Netmask`
  handles hex (macOS) and dotted (Linux) masks. `CounterLine` reads the
  `RX/TX packets` and `RX/TX errors ... collisions` lines, so Linux shows
  traffic and errors without `--live`. The `ether` line keeps only the MAC;
  the tail (`txqueuelen 1000 (Ethernet)`) goes to `other` and is labeled
  `link` in the verbose view (`formatting.LINK_INFO_MARK`).
- **Linux roles** (`model._ROLES`): eth/enp/ens/eno/enx Ethernet, wlan/wlp
  Wi-Fi, br bridge, docker, veth, tun, wg, tunl/gre, sit.
- **`--live` on Linux** (`enrich.LinuxLive`, 0.14.0): reads
  `/proc/net/route` (default route; the gateway is little-endian hex),
  `/proc/net/dev` (bytes, packets, errors, collisions) and
  `/etc/resolv.conf` (DNS, attached to the default-route interface). No
  extra tools needed. Paths are injectable through `LinuxLiveFiles` for
  tests. Port names and the DHCP lease stay macOS-only.
- **`--update-oui`** (`enrich.update_oui`): sends its own User-Agent
  (`_USER_AGENT`), because standards-oui.ieee.org answers **HTTP 418** to
  `Python-urllib`. On `ssl.SSLCertVerificationError` it retries with
  `curl -fsSL -A <agent>`. Older macOS `/etc/ssl/cert.pem` (Aug 2024) lacks
  the GlobalSign Root R46 the site uses; curl reads the Keychain, which has
  it.
- **No emoji codes** (`render.SHOW_EMOJI_CODES = False`, 0.14.2): every rich
  `Console` is created with `emoji=False`. rich turns `:cd:` into 💿 and
  `:ab:` into 🆎, so a MAC like `a6:cd:4a:ab:37:89` printed as
  `a6💿4a🆎37:89` (about 3% of MACs, plus IPv6 groups). Any new `Console`
  must pass `emoji=SHOW_EMOJI_CODES`.
- **Types**: the package passes `mypy --strict` (CI enforces it).

Platform matrix as measured on 2026-11-08 (macOS host, and Linux in Docker
`python:3.9-slim` / `python:3.13-slim` with `--cap-add NET_ADMIN`, package
installed from PyPI):

| Feature | macOS | Linux |
|---|---|---|
| default, `-v`, `-r`, `-t`, `-x`, pipe, `< /dev/null` | works | works |
| `ifpretty a b` filter | works (0.14.2) | works (0.14.2) |
| `-l` | route, traffic, DNS, DHCP, port names | route, gateway, traffic, DNS |
| `-d` | works, with the noise listed in section 5 | same |
| `-w` | works (real ipapi.co call, cached 1h) | works |
| `--update-oui` | works (curl fallback on old cert store) | works (40455 entries) |
| `-c`, `--record` | works | prints "macOS-only", by design |
| `--map` | works | no gateway found, so 0 hops (section 5) |

## 3. How to work on it

Run everything from the repo root. `uv.lock` pins the dev environment
(rich 15.0.0).

```sh
env -u FORCE_COLOR uv run --frozen --with pytest pytest tests -q   # 102 tests
uv run --frozen --with ruff ruff check src tests docs
uv run --frozen --with ruff ruff format --check src tests docs
uv run --frozen --with mypy mypy --strict src docs/make_images.py
REGEN=1 python3 tests/test_ifpretty.py   # rewrite golden files on purpose
```

- Unset `FORCE_COLOR` before running tests in a shell that exports it: rich
  honors it over `NO_COLOR`, and the plain-text goldens break. The tests
  already strip it from child processes (`COLOR_FORCING_VAR`).
- Each test run gets its own temp cache and history dir. Never point tests at
  `~/.cache/ifpretty`.

**README pictures** (macOS only, because `--live`/`--check` take their macOS
code path):

```sh
uv run python docs/make_images.py             # 13 SVGs + map.png (needs Google Chrome)
uv run python docs/make_images.py --svg-only  # what CI checks
```

How it works and why:
- Every picture is a real CLI run on fake data: a fake `ifconfig` (prints a
  fixture, refuses more than one name, like the real one), fake `route`,
  `netstat`, `networksetup`, `scutil`, `ipconfig` and `ping`, a seeded
  `wan.json` (203.0.113.7, AS64500) and a made-up `samples.csv`.
  `IFPRETTY_HISTORY` always points at a temp file so the real
  `~/.cache/ifpretty/samples.csv` never leaks in.
- It sets `FORCE_COLOR=1`, `COLORTERM=truecolor` and `TERM=xterm-256color`.
  rich picks the palette from `COLORTERM`/`TERM`; without pinning them the CI
  runner (no `COLORTERM`) wrote different SVGs than a local terminal.
- The `--map` picture is built in-process from a made-up network
  (`build_graph` + `render_html`) and screenshotted by headless Google
  Chrome. Headless Brave hung and never wrote a file. `build_graph` names
  the computer node after `socket.gethostname()`, so the generator swaps the
  real hostname for `laptop.local` and refuses to write if it is still there.
- SVGs are deterministic: two runs give identical files. `map.png` is not
  (fonts, CDN), so CI does not check it.
- README links use absolute `https://raw.githubusercontent.com/iklobato/ifpretty/main/docs/img/...`
  URLs, so the same README renders on GitHub and on PyPI (PyPI proxies them
  through camo and shows SVGs fine; checked on the 0.14.1 page).

**CI jobs**: `test` (ubuntu 3.9, ubuntu 3.13, macos 3.13, `pip install .
pytest`), `lint` (mypy --strict on src and the generator, ruff check and
format on src/tests/docs), `readme-images` (macOS, `uv run --frozen`
regenerates the SVGs and fails if `docs/img` changed, printing the diff).

**Git and GitHub**: the repo uses the personal account `iklobato` over SSH
(`git@github.com:`). For `gh` and for pushes that need the API token, put the
token on the one command, never export it:

```sh
GH_TOKEN="$(gh auth token --user iklobato)" git push origin <branch>
```

Work on a branch, wait for green CI, then fast-forward `main` and delete the
branch (local and remote). That is how every change in this session landed.

## 4. Release procedure (what worked for 0.13.0 to 0.14.2)

1. Branch `release/X.Y.Z` (or ship it on the fix branch).
2. Bump `version` in `pyproject.toml` **and** `__version__` in
   `src/ifpretty/__init__.py`, then `uv lock` (never edit `uv.lock` by hand).
3. Tests, lint, mypy; push the branch; wait for green CI.
4. `uv build`, then `uv run --frozen --with twine twine check dist/ifpretty-X.Y.Z*`.
5. Unpack the sdist and wheel and grep them for anything real: the author's
   real MAC, real global IPv6 prefix and Mac hostname. Read those values from
   the machine (`ifconfig en0`, `hostname -s`) at check time; **never write
   them into the repo**, this file included. `docs/` and the images are not
   in the package.
6. Publish:
   ```sh
   set -a; . ./.env; set +a
   UV_PUBLISH_TOKEN="$PYPI_TOKEN" uv publish dist/ifpretty-X.Y.Z-py3-none-any.whl dist/ifpretty-X.Y.Z.tar.gz
   ```
7. Wait for the simple index before testing an install. The JSON API updates
   first; `pip` failed with "no matching version" for about a minute after
   upload. Wait on
   `https://pypi.org/simple/ifpretty/` with
   `Accept: application/vnd.pypi.simple.v1+json` until the new wheel shows.
8. Install from PyPI in a fresh container or `uvx --refresh --from ifpretty==X.Y.Z`
   and run it.
9. Fast-forward `main`, push, delete the branch.

PyPI shows the README of the latest upload, so a README-only change needs a
release to appear there (that is why 0.14.1 exists).

## 5. Open items (known, not fixed, in priority order)

1. **`-d` baseline noise.** Every run saves the snapshot, including filtered
   runs (`ifpretty eth0`) and runs without `-l`. The next `-d` then reports
   the other interfaces as `removed`/`appeared`, or a gateway change from
   empty to `x` only because the previous run had no `-l`. Fix idea: do not save the snapshot
   on filtered runs, and leave live-only fields (gateway) out of the
   comparison unless both runs had them. About 20 minutes.
2. **`--map` on Linux.** `open_map` finds the gateway with
   `route -n get default` (macOS syntax), so on Linux there is no gateway,
   no traceroute and 0 hops. Fix idea: reuse `LinuxLive`'s
   `/proc/net/route` reading. The ip-api.com batch lookup also timed out in
   the Docker test; not investigated. The README does not say `--map` is
   macOS-only. About 20 minutes.
3. **`CLICOLOR_FORCE` does nothing.** The README says
   `CLICOLOR_FORCE=1` forces color; rich 15 ignores it, only `FORCE_COLOR`
   works (measured: 0 colored lines vs 1). Fix the code (map it to
   `FORCE_COLOR`) or the README line. About 10 minutes.
4. **README "Development" section is stale**: it says `70 tests` (now 102)
   and `mypy src` (CI runs `--strict`).
5. **`-c` and `--record` are macOS-only** by design; Linux would need
   `ip route`/`ping` flags and `/proc/net/dev` sampling. Not requested.
6. **Private IP in fixtures**: `tests/fixtures/sample.txt` and 9 README
   pictures still carry `192.168.1.201`, the real LAN address of the
   author's Mac. It is a private RFC 1918 address and identifies nobody; the
   real MAC and global IPv6 prefix were replaced. Swap it only if wanted
   (goldens and pictures must be regenerated).

## 6. Privacy history (why releases are missing)

- PyPI releases 0.6.0 to 0.12.0 shipped the author's real MAC and real
  global IPv6 prefix in `tests/test_units.py` (0.12.0
  also in README/PKG-INFO). They were deleted from PyPI on 2026-11-08
  through the PyPI web UI (logged-in browser, every delete approved by the
  author). Verified afterwards: `/pypi/ifpretty/<v>/json` returns 404 for
  each. Copies already pulled by mirrors or caches cannot be recalled.
- Fixtures and tests now use `14:7d:da:00:00:01`, `82:00:00:00:00:01`,
  `2001:470:1:2:...`, `fd00:0:0:8:...` and documentation ranges.
- The local `dist/` folder (gitignored) still holds the old
  `ifpretty-0.12.0*` files with the leak. Delete them if the folder is ever
  shared.
- `--wan` sends the public IP to ipapi.co; `--map` sends hop IPs to
  ip-api.com. Both are opt-in. Test logs of `-w` contain the real public IP,
  so keep them out of the repo.

## 7. Things to watch

- **rich upgrades.** `uv.lock` pins rich 15.0.0. A new rich can change the
  SVG template or colors, and the `readme-images` job will fail. That is
  expected: regenerate the SVGs, look at them, commit. It can also bring new
  emoji or markup surprises (see `SHOW_EMOJI_CODES`).
- **CI `readme-images` job.** It depends on `macos-latest` and on
  `COLORTERM`/`TERM` being pinned in the generator. If it fails on a commit
  that did not touch output, compare the printed diff for palette changes
  first.
- **External endpoints**: `standards-oui.ieee.org` (User-Agent rules, TLS
  chain), `ipapi.co` (`--wan`, rate limits), `ip-api.com` (`--map`, plain
  HTTP batch API). Any of them can change or block.
- **GitHub raw image URLs** point at `main` and the `docs/img/` path.
  Renaming the branch or moving the folder breaks every picture on PyPI
  until a new release.
- **net-tools `ifconfig`** shows only the primary IPv4 address of an
  interface. A secondary address added with `ip addr add` is invisible to
  ifpretty (found when a `-d` test showed "no changes").

## 8. Testing on Linux (how it was done)

Docker Desktop on the Mac, `python:3.9-slim` and `python:3.13-slim`,
`--cap-add NET_ADMIN` so the script can add `dummy`, `bridge` and `veth`
interfaces with `ip link`. Install `net-tools iproute2 traceroute
iputils-ping`, install ifpretty from PyPI, run every flag. Two lessons:

- Mount a **directory**, not a single file: Docker Desktop mangled a
  single-file bind mount name.
- Run the unit tests as a non-root user too: as root, "/nonexistent" is
  creatable, which once let a `--diff` baseline leak between tests (fixed
  by a temp cache per test run in 0.13.1).

## 9. What was done in this session (2026-11-08)

| Version / commit | Change |
|---|---|
| 0.13.0 | First release from this repo; `--live` guard off macOS; real MAC/IPv6 in fixtures replaced |
| 0.13.1 | stdin detection (no-TTY runs), OUI User-Agent (HTTP 418), temp cache per test |
| (no release) | Deleted PyPI releases 0.6.0 to 0.12.0 (privacy) |
| 0.14.0 | Linux net-tools parsing, Linux `--live` from /proc, curl fallback for `--update-oui`, `mypy --strict`, CI (tests on Linux/macOS, lint), `project.urls` |
| 0.14.1 | README with a picture of every flag, `docs/make_images.py`, `readme-images` CI job |
| 0.14.2 | Multi-name interface filter (`ifconfig -a` + filter after parse), emoji codes off so MACs print as they are |

The full Linux test of 0.14.1 (every flag, Python 3.9 and 3.13) found the two
bugs fixed in 0.14.2 and the open items 1 to 3 in section 5.
