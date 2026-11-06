"""EVE-NG and GNS3 REST API clients (read-only: they list labs and read nodes, links and startup configs).

The laboratory definition is the authoritative cabling record, so links read here are graded Confirmed.
Only the Python standard library is used (urllib with a cookie jar for the EVE-NG session).
Laboratory servers normally use a self-signed certificate, so HTTPS certificates are accepted without verification;
these clients are only used for EVE-NG and GNS3 lab servers the engineer names.
"""
from __future__ import annotations

import base64
import http.cookiejar
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field


class LabError(Exception):
    pass


class LabAuthError(LabError):
    pass


def normalise_server(value: str) -> str:
    value = (value or "").strip().rstrip("/")
    if not value:
        raise LabError("Enter the lab server address.")
    if "://" not in value:
        value = "http://" + value
    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise LabError("Use an http:// or https:// lab server address.")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise LabError("Server addresses cannot contain credentials or query strings.")
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"


@dataclass
class LabNode:
    ref: str            # provider node id
    name: str
    kind: str           # router | switch | firewall | pc | server | internet
    template: str | None
    console: str | None  # telnet://host:port
    status: str          # running | stopped
    interfaces: list[str] = field(default_factory=list)
    bridge: bool = False  # an unmanaged lab segment (EVE-NG bridge network / GNS3 built-in switch)
    platform: str | None = None  # cisco-ios | frr | None (not collectable)
    x: float | None = None
    y: float | None = None


@dataclass
class LabLink:
    a: str
    a_port: str | None
    b: str
    b_port: str | None


@dataclass
class LabTopology:
    provider: str
    lab_id: str
    name: str
    nodes: list[LabNode]
    links: list[LabLink]
    configs: dict[str, str] = field(default_factory=dict)  # node ref -> startup configuration


class _Http:
    def __init__(self, base: str, verify_tls: bool = False, timeout: float = 10.0, basic: tuple[str, str] | None = None):
        self.base, self.timeout = base, timeout
        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),
                                                  urllib.request.HTTPSHandler(context=context))
        self.headers = {"Accept": "application/json", "User-Agent": "NetGuard"}
        if basic:
            self.headers["Authorization"] = "Basic " + base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()

    def call(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        headers = dict(self.headers, **({"Content-Type": "application/json"} if data is not None else {}))
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403, 412):
                raise LabAuthError("The lab server rejected the credentials.") from None
            if exc.code == 404:
                raise LabError("The lab server does not know this lab or API path (check the server address and version).") from None
            raise LabError(f"The lab server answered HTTP {exc.code}.") from None
        except ssl.SSLError as exc:
            raise LabError(f"The TLS connection to the lab server failed ({exc.reason or exc}).") from None
        except (urllib.error.URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise LabError(f"Cannot reach the lab server: {reason}") from None
        try:
            return json.loads(raw.decode() or "null")
        except ValueError:
            raise LabError("The lab server returned a response that is not JSON (is this the API address?).") from None

    def text(self, path: str) -> str | None:
        """A raw file from the server (GNS3 node files); None when it does not exist."""
        request = urllib.request.Request(self.base + path, method="GET", headers=dict(self.headers, Accept="*/*"))
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise LabAuthError("The lab server rejected the credentials.") from None
            return None
        except (urllib.error.URLError, OSError, ssl.SSLError):
            return None


def _platform(*parts) -> str | None:
    text = " ".join(str(p) for p in parts if p).lower()
    if "frr" in text:
        return "frr"
    if any(k in text for k in ("iol", "vios", "csr", "c8000", "cat8", "cat9k", "c7200", "c3725", "c3745", "dynamips",
                               "iou", "xe", "cisco")):
        return "cisco-ios"
    return None


def _num(value) -> float | None:
    try:
        return float(str(value).rstrip("%"))
    except (TypeError, ValueError):
        return None


def _port(name: str | None, platform: str | None) -> str | None:
    from backend.services.interface_naming import canonical_name

    return canonical_name(name, "cisco-ios") if name and platform == "cisco-ios" else name


def _kind(template: str | None, image: str | None = None, node_type: str | None = None) -> str:
    text = " ".join(x for x in (template, image, node_type) if x).lower()
    if any(k in text for k in ("vpcs", "win", "desktop", "pc", "webterm", "docker")):
        return "pc"
    if any(k in text for k in ("asa", "forti", "paloalto", "pfsense", "firewall", "srx")):
        return "firewall"
    if any(k in text for k in ("l2", "switch", "nxos", "cat", "aruba", "ethernet_switch")):
        return "switch"
    if any(k in text for k in ("linux", "ubuntu", "server", "alpine", "debian")):
        return "server"
    if any(k in text for k in ("cloud", "nat", "pnet")):
        return "internet"
    return "router"


# ------------------------------------------------------------------ EVE-NG
class EveNgClient:
    provider = "eve-ng"

    def __init__(self, server: str, username: str, password: str, verify_tls: bool = False):
        self.server = normalise_server(server)
        self.http = _Http(self.server, verify_tls)
        self.username, self.password = username, password
        self._logged_in = False

    def login(self) -> None:
        try:
            answer = self.http.call("POST", "/api/auth/login", {"username": self.username, "password": self.password,
                                                                 "html5": "-1"})
        except LabError as exc:
            if "HTTP 400" in str(exc) or isinstance(exc, LabAuthError):
                raise LabAuthError("The EVE-NG server rejected the credentials.") from None
            raise
        if not isinstance(answer, dict) or str(answer.get("code", 200)) not in ("200", "201"):
            raise LabAuthError("The EVE-NG server rejected the credentials.")
        self._logged_in = True

    def _get(self, path: str):
        if not self._logged_in:
            self.login()
        answer = self.http.call("GET", path)
        return answer.get("data") if isinstance(answer, dict) else None

    def labs(self, folder: str = "/", depth: int = 0) -> list[dict]:
        data = self._get("/api/folders" + urllib.parse.quote(folder if folder.endswith("/") else folder + "/")) or {}
        labs = [{"id": lab.get("path"), "name": lab.get("file", "").removesuffix(".unl"), "folder": folder}
                for lab in data.get("labs", []) if lab.get("path")]
        if depth < 4:
            for sub in data.get("folders", []):
                if sub.get("name") == ".." or not sub.get("path"):
                    continue
                labs.extend(self.labs(sub["path"], depth + 1))
        return labs

    def topology(self, lab_path: str, with_configs: bool = True) -> LabTopology:
        lab = "/api/labs" + urllib.parse.quote(lab_path if lab_path.startswith("/") else "/" + lab_path)
        info = self._get(lab) or {}
        nodes_raw = self._get(lab + "/nodes") or {}
        networks = self._get(lab + "/networks") or {}
        if isinstance(nodes_raw, list):
            nodes_raw = {str(n.get("id")): n for n in nodes_raw}
        nodes: dict[str, LabNode] = {}
        membership: dict[str, list[tuple[str, str]]] = {}
        for nid, n in nodes_raw.items():
            node = LabNode(ref=str(n.get("id", nid)), name=str(n.get("name") or f"node{nid}"),
                           kind=_kind(n.get("template"), n.get("image"), n.get("type")), template=n.get("template"),
                           console=n.get("url") if str(n.get("url", "")).startswith("telnet://") else None,
                           status="running" if str(n.get("status")) in ("2", "3") else "stopped",
                           platform=_platform(n.get("template"), n.get("image"), n.get("type")),
                           x=_num(n.get("left")), y=_num(n.get("top")))
            ifaces = self._get(f"{lab}/nodes/{node.ref}/interfaces") or {}
            ethernet = ifaces.get("ethernet", []) if isinstance(ifaces, dict) else []
            if isinstance(ethernet, dict):
                ethernet = list(ethernet.values())
            for port in ethernet:
                name = _port(port.get("name"), node.platform)
                if name:
                    node.interfaces.append(name)
                if port.get("network_id") not in (None, 0, "0"):
                    membership.setdefault(str(port["network_id"]), []).append((node.ref, name))
            nodes[node.ref] = node
        if isinstance(networks, list):
            networks = {str(n.get("id")): n for n in networks}
        links = eve_links(nodes, networks, membership)
        configs = {}
        if with_configs:
            for ref, node in nodes.items():
                if node.bridge:
                    continue
                try:
                    cfg = self._get(f"{lab}/configs/{ref}") or {}
                except LabError:
                    continue
                text = cfg.get("data") if isinstance(cfg, dict) else None
                if text and text.strip():
                    configs[ref] = text
        return LabTopology("eve-ng", lab_path, str(info.get("name") or lab_path.rsplit("/", 1)[-1].removesuffix(".unl")),
                           list(nodes.values()), links, configs)


def eve_links(nodes: dict[str, LabNode], networks: dict, membership: dict[str, list[tuple[str, str]]]) -> list[LabLink]:
    """EVE-NG networks to cables: a hidden two-member bridge is a cable; any other network is a segment node."""
    links: list[LabLink] = []
    for net_id, members in membership.items():
        net = networks.get(net_id, {})
        net_type = str(net.get("type", "bridge"))
        if len(members) == 2 and net_type == "bridge" and not net.get("visibility") in (1, "1", True):
            (a, ap), (b, bp) = members
            links.append(LabLink(a, ap, b, bp))
            continue
        # A visible bridge or cloud with any number of members is a shared segment of its own.
        ref = f"net{net_id}"
        nodes[ref] = LabNode(ref=ref, name=str(net.get("name") or f"Network {net_id}")[:60],
                             kind="internet" if net_type.startswith("pnet") or "cloud" in net_type else "switch",
                             template=net_type, console=None, status="running", bridge=True,
                             x=_num(net.get("left")), y=_num(net.get("top")))
        for index, (node_ref, port) in enumerate(members):
            links.append(LabLink(node_ref, port, ref, f"port{index + 1}"))
    return links


def gns3_port_name(node: dict, adapter: int, port: int, label: str | None) -> str:
    """A GNS3 port name from a link label, or from the node's naming scheme."""
    if label:
        return label
    node_type = node.get("node_type")
    fmt = node.get("port_name_format")
    if fmt:
        try:
            return fmt.format(port, adapter=adapter, port=port, segment0=adapter, port0=port)
        except (KeyError, IndexError, ValueError):
            pass
    if node_type in ("vpcs", "docker", "qemu", "virtualbox", "vmware"):
        return f"Ethernet{adapter}" if node_type != "vpcs" else "Ethernet0"
    if node_type in ("ethernet_switch", "ethernet_hub"):
        return f"Ethernet{port}"
    if node_type == "iou":
        return f"Ethernet{adapter}/{port}"
    return f"FastEthernet{adapter}/{port}"


def gns3_topology(project_id: str, name: str, nodes_raw: list[dict], links_raw: list[dict], server_host: str | None,
                  configs: dict[str, str]) -> LabTopology:
    """A GNS3 project (from the API or a .gns3 file) as a lab topology."""
    nodes = {}
    for n in nodes_raw:
        node_type = n.get("node_type")
        console = None
        if n.get("console") and (n.get("console_type") or "telnet") == "telnet" and server_host:
            host = n.get("console_host") or "127.0.0.1"
            if host in ("0.0.0.0", "::", "127.0.0.1", "localhost"):
                host = server_host
            console = f"telnet://{host}:{n['console']}"
        bridge = node_type in ("ethernet_switch", "ethernet_hub", "frame_relay_switch", "atm_switch")
        props = n.get("properties") or {}
        platform = None if bridge else _platform(node_type, props.get("platform"), props.get("image"), n.get("name"))
        if platform is None and n["node_id"] in configs and "frr version" in configs[n["node_id"]]:
            platform = "frr"
        nodes[n["node_id"]] = LabNode(
            ref=n["node_id"], name=n.get("name") or n["node_id"][:8],
            kind="internet" if node_type in ("cloud", "nat") else "switch" if bridge else
            _kind(props.get("platform") or n.get("name"), None, node_type),
            template=node_type, console=None if bridge else console,
            status="running" if n.get("status") == "started" else "stopped",
            interfaces=[_port(p.get("short_name") or p.get("name"), platform) for p in n.get("ports", []) if p.get("name")],
            bridge=bridge or node_type in ("cloud", "nat"), platform=platform, x=_num(n.get("x")), y=_num(n.get("y")))
    raw = {n["node_id"]: n for n in nodes_raw}
    links = []
    for link in links_raw:
        ends = link.get("nodes") or []
        if len(ends) != 2 or not all(e.get("node_id") in nodes for e in ends):
            continue

        def port(end):
            node = nodes[end["node_id"]]
            label = (end.get("label") or {}).get("text")
            label = _port(label, node.platform) if label else None
            match = next((p for p in node.interfaces if p and label and p.lower() == label.lower()), None)
            if match:
                return match
            if label:
                return label
            return _port(gns3_port_name(raw[end["node_id"]], end.get("adapter_number", 0), end.get("port_number", 0),
                                        None), node.platform)
        a, b = ends
        links.append(LabLink(a["node_id"], port(a), b["node_id"], port(b)))
    return LabTopology("gns3", project_id, name or project_id, list(nodes.values()), links,
                       {k: v for k, v in configs.items() if k in nodes and not nodes[k].bridge})


# ------------------------------------------------------------------ GNS3
class Gns3Client:
    provider = "gns3"

    def __init__(self, server: str, username: str = "", password: str = "", verify_tls: bool = False):
        self.server = normalise_server(server)
        self.http = _Http(self.server, verify_tls, basic=(username, password) if username else None)

    def login(self) -> None:
        version = self.http.call("GET", "/v2/version")
        if not isinstance(version, dict) or "version" not in version:
            raise LabError("This address does not answer as a GNS3 server (expected /v2/version).")

    def labs(self) -> list[dict]:
        projects = self.http.call("GET", "/v2/projects") or []
        return [{"id": p.get("project_id"), "name": p.get("name"), "folder": p.get("status")} for p in projects
                if p.get("project_id")]

    # Startup configuration files that GNS3 keeps in each node directory, by node type.
    CONFIG_FILES = {
        "dynamips": lambda n: [f"configs/i{(n.get('properties') or {}).get('dynamips_id', '')}_startup-config.cfg",
                               (n.get("properties") or {}).get("startup_config") or ""],
        "iou": lambda n: ["startup-config.cfg", "nvram_startup-config.cfg"],
        "vpcs": lambda n: ["startup.vpc"],
        "docker": lambda n: ["etc/frr/frr.conf", "etc/network/interfaces"],
        "qemu": lambda n: ["config.txt", "startup-config.cfg"],
    }

    def _startup_config(self, project_id: str, node: dict) -> str | None:
        candidates = [p for p in self.CONFIG_FILES.get(node.get("node_type"), lambda n: [])(node) if p and "i_" not in p]
        for path in dict.fromkeys(candidates):
            text = self.http.text(f"/v2/projects/{project_id}/nodes/{node['node_id']}/files/{urllib.parse.quote(path)}")
            if text and text.strip() and not text.lstrip().startswith("{"):
                return text
        return None

    def topology(self, project_id: str, with_configs: bool = True) -> LabTopology:
        projects = {p.get("project_id"): p for p in self.http.call("GET", "/v2/projects") or []}
        project = projects.get(project_id)
        if project is None:
            raise LabError("The GNS3 project was not found.")
        if project.get("status") != "opened":
            self.http.call("POST", f"/v2/projects/{project_id}/open", {})
        nodes_raw = self.http.call("GET", f"/v2/projects/{project_id}/nodes") or []
        configs: dict[str, str] = {}
        if with_configs:
            for n in nodes_raw:
                if n.get("node_type") not in ("ethernet_switch", "ethernet_hub", "cloud", "nat"):
                    text = self._startup_config(project_id, n)
                    if text:
                        configs[n["node_id"]] = text
        links_raw = self.http.call("GET", f"/v2/projects/{project_id}/links") or []
        return gns3_topology(project_id, project.get("name") or project_id, nodes_raw, links_raw,
                             urllib.parse.urlsplit(self.server).hostname, configs)


def client(provider: str, server: str, username: str, password: str, verify_tls: bool = False):
    if provider == "eve-ng":
        return EveNgClient(server, username, password, verify_tls)
    if provider == "gns3":
        return Gns3Client(server, username, password, verify_tls)
    raise LabError("Choose EVE-NG or GNS3.")
