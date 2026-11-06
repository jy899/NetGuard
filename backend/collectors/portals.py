"""Web management portal detection and vendor fingerprinting (credential-free, read-only).

For each open TCP port the detector tries TLS first (devices often serve HTTPS on non-standard ports) and then
plain HTTP, sends one GET for "/", follows up to three same-host redirects, and records the status, title,
Server header, certificate subject/issuer/SHA-256 fingerprint and a vendor/product match. Nothing is submitted:
no form, no credential. The result is the list the topology workspace offers under "Open Web GUI".

Signatures cover the platforms NetGuard targets (FortiGate, pfSense/OPNsense, Cisco, Aruba, Ubiquiti, Ruijie,
TP-Link, D-Link, FiberHome) and common others (MikroTik, Huawei, ZTE, Netgear, Sophos, SonicWall, Juniper,
Palo Alto, Synology, QNAP, Hikvision, Dahua, printers). A signature is a hint for the operator, shown with the
evidence that matched; it never changes a device's identity on its own.
"""
from __future__ import annotations

import hashlib
import re
import socket
import ssl
from urllib.parse import urljoin, urlparse

# (vendor, product, regex over title + server + body head + certificate names)
SIGNATURES: list[tuple[str, str, str]] = [
    ("Fortinet", "FortiGate", r"fortigate|fortinet|fortios|/remote/login|ftnt"),
    ("Netgate", "pfSense", r"pfsense"),
    ("Deciso", "OPNsense", r"opnsense"),
    ("Cisco", "Cisco IOS/IOS-XE web UI", r"cisco[- ]ios|level_15|webui/#/|cisco systems|ios-xe"),
    ("Cisco", "Cisco ASA / AnyConnect", r"\+cscoe\+|anyconnect|adaptive security"),
    ("Cisco", "Cisco Meraki", r"meraki"),
    ("Cisco", "Cisco Small Business", r"cisco small business|sg\d{3}|cbs\d{3}"),
    ("HPE Aruba", "Aruba", r"aruba|arubaos|aos-cx|procurve|instant on"),
    ("Ubiquiti", "UniFi", r"unifi"),
    ("Ubiquiti", "EdgeOS / EdgeSwitch", r"edgeos|edgeswitch|edgerouter|edgemax"),
    ("Ubiquiti", "airOS / UISP", r"airos|uisp|ubnt"),
    ("Ruijie", "Ruijie / Reyee", r"ruijie|reyee|rg-[a-z0-9]+|eweb"),
    ("TP-Link", "TP-Link / Omada", r"tp-?link|omada|tplinkwifi|archer|deco"),
    ("D-Link", "D-Link", r"d-?link|dir-\d+|des-\d+|dgs-\d+|dap-\d+"),
    ("FiberHome", "FiberHome ONT/router", r"fiberhome|fiber home|hg6\d{3}|an5506|sr1041"),
    ("MikroTik", "RouterOS webfig", r"routeros|mikrotik|webfig"),
    ("Huawei", "Huawei", r"huawei|hg8\d{3}|echolife|vrp"),
    ("ZTE", "ZTE", r"\bzte\b|zxhn|f6\d{2}"),
    ("Netgear", "Netgear", r"netgear"),
    ("Sophos", "Sophos", r"sophos|cyberoam"),
    ("SonicWall", "SonicWall", r"sonicwall|sonicos"),
    ("Juniper", "Juniper J-Web", r"juniper|j-web|junos"),
    ("Palo Alto Networks", "PAN-OS", r"pan-os|palo alto|globalprotect"),
    ("Synology", "DiskStation", r"synology|diskstation|dsm"),
    ("QNAP", "QTS", r"qnap|qts"),
    ("Hikvision", "IP camera / NVR", r"hikvision|doc/page/login"),
    ("Dahua", "IP camera / NVR", r"dahua"),
    ("HP", "Printer (EWS)", r"hp (laserjet|officejet|color)|embedded web server"),
    ("Microsoft", "IIS", r"microsoft-iis"),
    ("Proxmox", "Proxmox VE", r"proxmox"),
    ("VMware", "ESXi", r"vmware esxi|esxui"),
]
_COMPILED = [(v, p, re.compile(rx, re.I)) for v, p, rx in SIGNATURES]
TLS_FIRST = {443, 8443, 10443, 4443, 9443, 7443}


def fingerprint(text: str) -> tuple[str | None, str | None, str | None]:
    """(vendor, product, the matching text) for the first signature that matches."""
    for vendor, product, rx in _COMPILED:
        m = rx.search(text or "")
        if m:
            return vendor, product, m.group(0)
    return None, None, None


def _request(ip: str, port: int, tls: bool, path: str, timeout: float) -> dict | None:
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    cert = None
    sock = raw
    try:
        if tls:
            context = ssl.create_default_context()
            context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
            try:
                import warnings

                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    context.minimum_version = ssl.TLSVersion.TLSv1  # old device firmware still serves TLS 1.0
                context.set_ciphers("DEFAULT:@SECLEVEL=0")
            except (ValueError, ssl.SSLError):
                pass
            sock = context.wrap_socket(raw, server_hostname=ip)
            der = sock.getpeercert(binary_form=True)
            if der:
                cert = {"sha256": hashlib.sha256(der).hexdigest(), **(_cert_names(der) or {})}
        sock.settimeout(timeout)
        host = ip if port in (80, 443) else f"{ip}:{port}"
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetGuard portal detector\r\n"
                     "Accept: text/html,*/*\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while len(data) < 32768:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except (OSError, ssl.SSLError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass
    text = data.decode("latin-1", "replace")
    if not text.startswith("HTTP/"):
        return None
    head, _, body = text.partition("\r\n\r\n")
    status = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", head)
    headers = {}
    for line in head.split("\r\n")[1:]:
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
    title = re.search(r"<title[^>]*>([^<]{1,160})</title>", body, re.I)
    refresh = re.search(r"http-equiv=[\"']?refresh[\"']?[^>]*url=([^\"'>\s]+)", body, re.I)
    script = re.search(r"(?:window\.|document\.|top\.)?location(?:\.href)?\s*=\s*[\"']([^\"']+)[\"']", body)
    return {"status": int(status.group(1)) if status else None, "headers": headers, "body": body[:6000],
            "title": title.group(1).strip() if title else None, "cert": cert,
            "redirect": headers.get("location") or (refresh.group(1) if refresh else None) or
                        (script.group(1) if script else None)}


def _cert_names(der: bytes) -> dict | None:
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        cert = x509.load_der_x509_certificate(der)

        def name(n):
            parts = {a.oid: a.value for a in n}
            return parts.get(NameOID.COMMON_NAME) or parts.get(NameOID.ORGANIZATION_NAME)
        return {"subject": name(cert.subject), "issuer": name(cert.issuer),
                "self_signed": cert.subject == cert.issuer}
    except Exception:  # noqa: BLE001 - malformed device certificates are common
        return None


def probe(ip: str, port: int, timeout: float = 2.5) -> dict | None:
    """The web portal on ip:port, or None when the port does not speak HTTP(S)."""
    order = (True, False) if port in TLS_FIRST else (False, True)
    for tls in order:
        first = _request(ip, port, tls, "/", timeout)
        if first is None:
            continue
        scheme = "https" if tls else "http"
        url = f"{scheme}://{ip}" + ("" if (tls and port == 443) or (not tls and port == 80) else f":{port}") + "/"
        pages, current, path = [first], first, "/"
        # A plain-HTTP port that redirects to HTTPS (or a login path) is followed on the same host only.
        for _ in range(3):
            location = current.get("redirect")
            if not location or current["status"] not in (301, 302, 303, 307, 308, 200):
                break
            target = urlparse(urljoin(url, location))
            if target.hostname != ip:
                break
            t_tls, t_port = target.scheme == "https", target.port or (443 if target.scheme == "https" else 80)
            nxt = _request(ip, t_port, t_tls, target.path or "/", timeout)
            if nxt is None:
                break
            url = f"{target.scheme}://{ip}" + ("" if t_port in (80, 443) else f":{t_port}") + (target.path or "/")
            pages.append(nxt)
            current, path = nxt, target.path or "/"
        text = " ".join(filter(None, [*(p.get("title") or "" for p in pages), *(p["headers"].get("server", "") for p in pages),
                                       *(p["body"][:3000] for p in pages), path,
                                       *((p.get("cert") or {}).get("subject") or "" for p in pages),
                                       *((p.get("cert") or {}).get("issuer") or "" for p in pages)]))
        vendor, product, matched = fingerprint(text)
        title = next((p["title"] for p in reversed(pages) if p.get("title")), None)
        cert = next((p["cert"] for p in pages if p.get("cert")), None)
        login = bool(re.search(r"type=[\"']?password|login|sign in|log in|username", " ".join(p["body"] for p in pages), re.I))
        return {"port": port, "scheme": url.split(":")[0], "url": url, "status": current.get("status"),
                "title": title, "server": current["headers"].get("server") or first["headers"].get("server"),
                "vendor": vendor, "product": product, "matched": matched, "login_page": login,
                "certificate": cert, "self_signed": bool(cert and cert.get("self_signed"))}
    return None


def detect(ip: str, ports, timeout: float = 2.5) -> list[dict]:
    """Every web portal among the open ports (any port, not only 80/443), best first."""
    from backend.collectors.netutil import parallel

    found = [r for r in parallel(lambda p: probe(ip, p, timeout), sorted(set(ports)), workers=16) if r]
    found.sort(key=lambda r: (r["vendor"] is None, not r["login_page"], r["scheme"] != "https", r["port"]))
    return found
