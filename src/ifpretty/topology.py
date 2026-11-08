"""Build an interactive browser map of the network, in three zones:
your computer (interfaces) · local network (gateway + LAN devices) · the
internet (traceroute path). Every IP is enriched with reverse-DNS host and
whois-style org / ASN / country. Rendered with vis-network (CDN), opened in
the browser.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import sys
import tempfile
import urllib.request
import webbrowser
from dataclasses import dataclass

from .enrich import (
    _apply_default_route,
    _run,
    fetch_wan,
    ip_scope,
    mac_kind,
    mac_vendor,
)
from .model import Interface

_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_RTT = re.compile(r"(\d+\.\d+) ms")
_IPAPI_BATCH = (
    "http://ip-api.com/batch?fields="
    "status,query,country,countryCode,city,isp,org,as,reverse"
)


@dataclass
class Hop:
    ttl: int
    ip: str  # "" for a non-responding (timeout) hop
    rtt: str = ""


@dataclass
class Neighbor:
    ip: str
    mac: str
    iface: str


def parse_traceroute(text: str) -> list[Hop]:
    """Parse `traceroute -n` output into hops (pure; testable)."""
    hops: list[Hop] = []
    for line in text.splitlines():
        m = re.match(r"\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        ttl, rest = int(m.group(1)), m.group(2)
        ip = _IPV4.search(rest)
        rtt = _RTT.search(rest)
        hops.append(Hop(ttl, ip.group(1) if ip else "", rtt.group(1) if rtt else ""))
    return hops


def parse_neighbors(text: str) -> list[Neighbor]:
    """Parse `arp -an` output into LAN neighbours (pure; testable)."""
    out: list[Neighbor] = []
    for line in text.splitlines():
        m = re.search(r"\(([\d.]+)\) at ([0-9a-fA-F:]+) on (\w+)", line)
        if m and "incomplete" not in line:
            out.append(Neighbor(m.group(1), m.group(2).lower(), m.group(3)))
    return out


def _traceroute(target: str, max_hops: int = 20) -> list[Hop]:
    out = _run(
        ["traceroute", "-n", "-w", "1", "-q", "1", "-m", str(max_hops), target],
        timeout=float(max_hops) + 5,
    )
    return parse_traceroute(out) if out else []


def _neighbors() -> list[Neighbor]:
    out = _run(["arp", "-an"], timeout=5.0)
    return parse_neighbors(out) if out else []


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def parse_ipapi_batch(items: list[dict]) -> dict[str, dict]:
    """ip-api.com /batch response → {ip: {host, org, isp, asn, country, cc, city}}."""
    info: dict[str, dict] = {}
    for it in items:
        if it.get("status") == "success" and it.get("query"):
            info[it["query"]] = {
                "host": it.get("reverse", ""),
                "org": it.get("org") or it.get("isp", ""),
                "isp": it.get("isp", ""),
                "asn": it.get("as", ""),
                "country": it.get("country", ""),
                "cc": it.get("countryCode", ""),
                "city": it.get("city", ""),
            }
    return info


def lookup_ips(ips: list[str], timeout: float = 5.0) -> dict[str, dict]:
    """Enrich IPs: whois-style org/ASN/country (public, via ip-api batch) +
    reverse-DNS host. Best-effort; degrades silently offline."""
    info: dict[str, dict] = {}
    public = sorted({ip for ip in ips if _is_public(ip)})
    private = sorted({ip for ip in ips if ip and not _is_public(ip)})

    if public:
        try:
            body = json.dumps([{"query": ip} for ip in public]).encode()
            req = urllib.request.Request(
                _IPAPI_BATCH, data=body, headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                info.update(parse_ipapi_batch(json.loads(r.read().decode("utf-8"))))
        except (OSError, ValueError) as e:
            print(f"ifpretty: --map IP lookup failed ({e})", file=sys.stderr)

    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(1.0)
    try:
        for ip in private:  # LAN devices rarely have PTR, but try
            try:
                info.setdefault(ip, {})["host"] = socket.gethostbyaddr(ip)[0]
            except OSError:
                pass
    finally:
        socket.setdefaulttimeout(old)
    return info


def _meaningful(iface: Interface) -> bool:
    """Interfaces worth drawing: up and carrying a routable address."""
    if not iface.is_up:
        return False
    routable6 = any(
        ":" in x.addr and not x.addr.startswith("fe80") for x in iface.inet6
    )
    return bool(iface.inet or routable6)


def _short(text: str, n: int = 22) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def _company(info: dict[str, str]) -> str:
    """Best 'who owns this IP' string from a lookup record."""
    return info.get("org") or info.get("isp") or info.get("asn") or ""


def _ip_detail(
    ip: str,
    info: dict,
    *,
    mac: str = "",
    vendor: str = "",
    via: str = "",
    rtt: str = "",
) -> str:
    """Multi-line tooltip with everything useful known about an IP."""
    lines = [ip]
    if info.get("host"):
        lines.append(f"host {info['host']}")
    if mac:
        lines.append(f"MAC {mac}" + (f"  ({vendor})" if vendor else ""))
    elif vendor:
        lines.append(f"vendor {vendor}")
    if info.get("org"):
        lines.append(f"org {info['org']}")
    if info.get("isp") and info.get("isp") != info.get("org"):
        lines.append(f"ISP {info['isp']}")
    if info.get("asn"):
        lines.append(info["asn"])
    loc = " · ".join(x for x in (info.get("city"), info.get("country")) if x)
    if loc:
        lines.append(loc)
    if via:
        lines.append(f"via {via}")
    if rtt:
        lines.append(f"{rtt} ms")
    return "\n".join(lines)


def build_graph(
    interfaces: list[Interface],
    gateway_ip: str,
    gateway_iface: str,
    hops: list[Hop],
    neighbors: list[Neighbor],
    target: str,
    ipinfo: dict[str, dict] | None = None,
) -> tuple[list[dict], list[dict], dict[str, list[str]]]:
    """Build vis-network (nodes, edges, zones) from the topology (pure)."""
    ipinfo = ipinfo or {}
    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[str] = set()
    zones: dict[str, list[str]] = {"computer": [], "local": [], "internet": []}

    def node(nid, label, group, level, zone, title):
        if nid not in seen:
            seen.add(nid)
            nodes.append(
                {
                    "id": nid,
                    "label": label,
                    "group": group,
                    "level": level,
                    "title": title,
                }
            )
            zones[zone].append(nid)

    host = socket.gethostname()
    node("self", f"💻 {host}", "self", 0, "computer", f"This machine — {host}")

    shown = [i for i in interfaces if _meaningful(i)]
    for iface in shown:
        node(
            f"if:{iface.name}",
            _iface_label(iface),
            "iface",
            1,
            "computer",
            _iface_title(iface),
        )
        edges.append({"from": "self", "to": f"if:{iface.name}"})

    shown_names = {i.name for i in shown}
    for nb in neighbors:
        anchor = f"if:{nb.iface}" if nb.iface in shown_names else "self"
        vendor = mac_vendor(nb.mac)
        info = ipinfo.get(nb.ip, {})
        tag = info.get("host") or vendor
        label = f"{nb.ip}\n{_short(tag)}" if tag else nb.ip
        node(
            f"dev:{nb.ip}",
            label,
            "device",
            2,
            "local",
            _ip_detail(nb.ip, info, mac=nb.mac, vendor=vendor, via=nb.iface),
        )
        edges.append({"from": anchor, "to": f"dev:{nb.ip}"})

    if gateway_ip:
        node(
            "gw",
            f"🚪 Gateway\n{gateway_ip}",
            "gateway",
            2,
            "local",
            _ip_detail(gateway_ip, ipinfo.get(gateway_ip, {}), via=gateway_iface),
        )
        anchor = f"if:{gateway_iface}" if gateway_iface in shown_names else "self"
        edges.append({"from": anchor, "to": "gw", "arrows": "to"})
        prev, level = "gw", 3
        for hop in hops:
            if not hop.ip or hop.ip == gateway_ip:
                continue
            info = ipinfo.get(hop.ip, {})
            nid = f"hop:{hop.ttl}"
            lbl = [f"#{hop.ttl}  {hop.ip}"]
            if _company(info):
                lbl.append(_short(_company(info)))
            if info.get("cc"):
                lbl.append(info["cc"] + (f"  {hop.rtt} ms" if hop.rtt else ""))
            elif hop.rtt:
                lbl.append(f"{hop.rtt} ms")
            node(
                nid,
                "\n".join(lbl),
                "hop",
                level,
                "internet",
                _ip_detail(hop.ip, info, rtt=hop.rtt),
            )
            edges.append({"from": prev, "to": nid, "arrows": "to"})
            prev, level = nid, level + 1
        tinfo = ipinfo.get(target, {})
        tlbl = [f"🌐 {target}"]
        if _company(tinfo):
            tlbl.append(_short(_company(tinfo)))
        if tinfo.get("country"):
            tlbl.append(tinfo["country"])
        node(
            "net",
            "\n".join(tlbl),
            "internet",
            level,
            "internet",
            _ip_detail(target, tinfo),
        )
        edges.append({"from": prev, "to": "net", "arrows": "to"})

    return nodes, edges, zones


def _iface_label(iface: Interface) -> str:
    lines = [f"🖧 {iface.name}"]
    if iface.role:
        lines.append(iface.role)
    primary = next((x.addr for x in iface.inet), None) or next(
        (x.addr for x in iface.inet6 if not x.addr.startswith("fe80")), None
    )
    if primary:
        lines.append(primary)
    return "\n".join(lines)


def _iface_title(iface: Interface) -> str:
    parts = [f"{iface.name} · {iface.role or 'interface'}"]
    if iface.ether:
        tail = " · ".join(
            t for t in (mac_kind(iface.ether), mac_vendor(iface.ether)) if t
        )
        parts.append(f"MAC {iface.ether}" + (f"  ({tail})" if tail else ""))
    for v4 in iface.inet:
        sc = ip_scope(v4.addr)
        parts.append(f"inet {v4.addr}" + (f"  [{sc}]" if sc else ""))
    for v6 in iface.inet6:
        sc = ip_scope(v6.addr)
        parts.append(f"inet6 {v6.addr}" + (f"  [{sc}]" if sc else ""))
    if iface.media:
        parts.append(f"media {iface.media}")
    if iface.mtu:
        parts.append(f"mtu {iface.mtu}")
    return "\n".join(parts)


_GROUPS = {
    "self": {
        "color": {"background": "#1f6feb", "border": "#388bfd"},
        "shape": "box",
        "font": {"color": "#fff", "size": 16},
    },
    "iface": {
        "color": {"background": "#1b3a4b", "border": "#39c5cf"},
        "shape": "box",
        "font": {"color": "#a5f3fc"},
    },
    "gateway": {
        "color": {"background": "#13361f", "border": "#3fb950"},
        "shape": "box",
        "font": {"color": "#7ee787"},
    },
    "device": {
        "color": {"background": "#21262d", "border": "#8b949e"},
        "shape": "box",
        "font": {"color": "#c9d1d9", "size": 12},
    },
    "hop": {
        "color": {"background": "#3a2d12", "border": "#d29922"},
        "shape": "box",
        "font": {"color": "#e3b341", "size": 12},
    },
    "internet": {
        "color": {"background": "#2d2147", "border": "#bc8cff"},
        "shape": "box",
        "font": {"color": "#d2b8ff", "size": 15},
    },
}


def render_html(nodes, edges, zones, subtitle: str) -> str:
    return _TEMPLATE % {
        "nodes": json.dumps(nodes),
        "edges": json.dumps(edges),
        "zones": json.dumps(zones),
        "groups": json.dumps(_GROUPS),
        "subtitle": subtitle,
    }


def open_map(interfaces: list[Interface], target: str) -> int:
    """Gather topology, enrich every IP, render the HTML map, open it."""
    print(
        f"ifpretty: mapping network & tracing route to {target} "
        "(this can take a few seconds)…",
        file=sys.stderr,
    )
    by_name = {i.name: i for i in interfaces}
    _apply_default_route(by_name)
    default = next((i for i in interfaces if i.is_default), None)
    gw_ip = default.gateway if default else ""
    gw_iface = default.name if default else ""

    hops = _traceroute(target) if gw_ip else []
    neighbors = _neighbors()

    all_ips = [target, gw_ip] + [h.ip for h in hops if h.ip] + [n.ip for n in neighbors]
    ipinfo = lookup_ips([ip for ip in all_ips if ip])

    nodes, edges, zones = build_graph(
        interfaces, gw_ip, gw_iface, hops, neighbors, target, ipinfo
    )

    wan = fetch_wan()
    wan_bits = ""
    if wan and wan.get("ip"):
        extra = " · ".join(x for x in (wan.get("asn"), wan.get("org")) if x)
        wan_bits = f"  ·  WAN {wan['ip']}" + (f" ({extra})" if extra else "")
    devices = len(zones["local"]) - (1 if gw_ip else 0)
    hop_n = sum(1 for n in nodes if n["group"] == "hop")
    subtitle = f"{devices} devices · {hop_n} hops to {target}{wan_bits}"

    html = render_html(nodes, edges, zones, subtitle)
    with tempfile.NamedTemporaryFile(
        "w", suffix="-ifpretty-map.html", delete=False, encoding="utf-8"
    ) as fh:
        fh.write(html)
        path = fh.name
    print(f"ifpretty: network map → {path}", file=sys.stderr)
    webbrowser.open(f"file://{path}")
    return 0


_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>ifpretty · network map</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
  html,body{margin:0;height:100%%;background:#0d1117;color:#c9d1d9;
            font-family:-apple-system,system-ui,Segoe UI,sans-serif}
  #net{width:100vw;height:100vh}
  #hdr{position:fixed;top:12px;left:16px;z-index:5;pointer-events:none}
  #hdr h1{margin:0;font-size:16px;font-weight:700}
  #hdr p{margin:3px 0 0;font-size:12px;color:#8b949e}
  #legend{position:fixed;bottom:14px;left:16px;z-index:5;font-size:12px;
          background:#161b22cc;border:1px solid #30363d;border-radius:8px;padding:8px 12px}
  #legend .row{display:flex;align-items:center;gap:7px;margin:3px 0}
  #legend .sw{width:12px;height:12px;border-radius:3px;display:inline-block}
</style></head><body>
<div id="hdr"><h1>ifpretty · network map</h1><p>%(subtitle)s</p></div>
<div id="legend"></div>
<div id="net"></div>
<script>
  const nodes = new vis.DataSet(%(nodes)s);
  const edges = new vis.DataSet(%(edges)s);
  const ZONES = %(zones)s;
  const groups = %(groups)s;
  const network = new vis.Network(document.getElementById("net"),
    {nodes, edges}, {
      groups: groups,
      nodes: {borderWidth:2, shape:"box", margin:8,
              shadow:{enabled:true,size:8,color:"#00000066"},
              font:{multi:false,face:"-apple-system,system-ui"}},
      edges: {color:{color:"#3d444d",highlight:"#58a6ff"}, smooth:{type:"cubicBezier",
              forceDirection:"horizontal",roundness:0.45}, width:1.6,
              arrows:{to:{scaleFactor:0.6}}},
      layout: {hierarchical:{enabled:true,direction:"LR",sortMethod:"directed",
               levelSeparation:240,nodeSpacing:95,treeSpacing:130}},
      physics: false,
      interaction: {hover:true, tooltipDelay:100, navigationButtons:true, keyboard:true},
    });

  const ZINFO = [["computer","💻 Your computer","#1f6feb"],
                 ["local","🏠 Local network","#3fb950"],
                 ["internet","🌐 Internet","#bc8cff"]];
  network.on("beforeDrawing", function(ctx){
    const pos = network.getPositions();
    const all = Object.values(pos);
    if(!all.length) return;
    const ymin = Math.min(...all.map(p=>p.y)) - 130;
    const ymax = Math.max(...all.map(p=>p.y)) + 90;
    ctx.save();
    ZINFO.forEach(function(z){
      const ps = (ZONES[z[0]]||[]).map(i=>pos[i]).filter(Boolean);
      if(!ps.length) return;
      const xmin = Math.min(...ps.map(p=>p.x)) - 100;
      const xmax = Math.max(...ps.map(p=>p.x)) + 100;
      ctx.fillStyle = z[2] + "22";
      ctx.fillRect(xmin, ymin, xmax - xmin, ymax - ymin);
      ctx.fillStyle = z[2] + "cc";
      ctx.font = "600 19px -apple-system,system-ui,sans-serif";
      ctx.textAlign = "center";
      ctx.fillText(z[1], (xmin + xmax)/2, ymin + 24);
    });
    ctx.restore();
  });

  const names = {self:"this machine",iface:"interface",gateway:"gateway",
                 device:"LAN device",hop:"route hop",internet:"internet"};
  document.getElementById("legend").innerHTML = Object.keys(names).map(k =>
    `<div class="row"><span class="sw" style="background:${groups[k].color.border}"></span>${names[k]}</div>`
  ).join("");
</script></body></html>
"""
