# NetGuard

NetGuard is a Windows 11 desktop application for network change risk validation. It builds an L1–L3 model of a laboratory or authorised network from read-only evidence, finds misconfigurations with five rule packs, traces required traffic hop by hop to the first failing hop, scores proposed changes with a transparent formula, and lets an IT Manager approve a verified change before NetGuard applies it with a backup, post-change verification and automatic rollback: on laboratory devices, and on real-network devices for user groups that have that permission.

## Run

Requirements: Windows 11, Python 3.11 or later (first start needs internet to install dependencies), Microsoft Edge WebView2 Runtime (included with Windows 11).

- Double-click `Start_NetGuard.cmd`. It creates `.venv`, installs `requirements.txt` and opens the NetGuard window.
- Sign in with the default account `admin` / `admin` and change the password under Settings → Password if you wish. Passwords have no length or complexity rules.
- Forgot the password? Double-click `Reset_Admin_Password.cmd` to set the `admin` account back to `admin` / `admin`.
- A new installation starts empty: the dashboard shows three Get started steps (add a network, save a device login, analyze).
- If the start fails with "No module named pip", run `Start_NetGuard.cmd` again: the launcher now repairs pip with ensurepip, and rebuilds `.venv` if that fails (the old one is kept as `.venv.broken-<date>`).
- Data is kept in `data\` (database, encrypted vault key, settings). Back up this folder to keep your work.

The service listens on 127.0.0.1 only and accepts requests from the NetGuard window. Browser access is off by default and is turned on by an administrator:

```
.venv\Scripts\python.exe netguard.py --enable-web-access     (asks for an administrator login)
Start_NetGuard.cmd -Server                                   (or: python netguard.py --server)
```

Then open http://127.0.0.1:8001. `--disable-web-access` turns it off again.

Windows app: double-click `Build_NetGuard_App.cmd` to build `dist\NetGuard\NetGuard.exe` (desktop window) and `NetGuardCmd.exe` (the same commands in a console) with PyInstaller. Add `-RunTests` to run the backend tests first. Copy the whole `dist\NetGuard` folder to run it on another Windows PC.

## Workflow

1. **Networks → Virtual Lab**: connect to an EVE-NG or GNS3 server (self-signed lab certificates are accepted) and import a lab: nodes, cables, consoles and startup configurations.
   **Networks → Real Network**: pick the network adapter (its subnet is filled in), or type several ranges (`10.0.10.0/24, 10.0.20.0/24`), and press **Scan**. Live hosts are found with ICMP, TCP, ARP (native IP Helper API on Windows) and SNMPv3 engine discovery and identified from DNS, NetBIOS, mDNS, UPnP, banners, web portals, certificates and MAC vendors. This computer is part of the map, with its Wi-Fi association (SSID, BSSID). Every device is placed with a graded link: Confirmed or Inferred where LLDP/CDP, MAC tables, spanning tree or the Wi-Fi BSSID show it, Logical (same segment, routed subnet, traceroute hop) otherwise. Devices that offer SSH or SNMP are listed with one credential form; a read collects interfaces, LLDP/CDP neighbours, ARP, per-VLAN MAC, spanning-tree and routing tables, and the discovery continues to the neighbours with the same credentials (up to 3 hops). Saved profiles are tried automatically. Skip leaves the partial result.
   **Practice networks** (collapsed section on Networks → Virtual Lab): ready-made networks with one known fault (VLAN, routing, interface, ACL, loop, missing cable, IP conflict), several faults or none. No device exists, so a fix changes NetGuard's model only; **Fix All Now** fixes everything at once. **Start again** resets an exercise.
   **Import**: drop a Packet Tracer (.pkt/.pka), GNS3 (.gns3/.gns3project), EVE-NG (.unl/.zip) project or a set of configurations (.cfg/.txt/.conf/.zip). Devices, interfaces, cables, configurations, endpoints and flows are read from the file. A single configuration offers to add neighbour configurations or infer the connected subnets.
   **Other VLANs**: after NetGuard signs in to a router or layer 3 switch it reads that device's interface subnets and routes and sweeps each one (up to 16 subnets of /22 or smaller per crawl), inside the authorised ranges, or in private address space when "Scan other VLANs and subnets my routers report" is on. The scan summary lists the subnets scanned and, on hover, the ones left out and why.
   **Ports** (switch, router or firewall that was read): every port with its MAC addresses, IP, vendor, VLAN and device; uplinks to other network devices are marked so hosts behind them are not drawn on the wrong port.
   The **Topology Workspace** first asks which network to open. **Validation & Changes** and **Reports & History** group everything under its network.
2. **Collect Configs** (Topology Workspace) reads running configurations over the lab console or SSH using show commands only. Each snapshot is stored encrypted with its SHA-256.
3. **Analyze Network** runs the physical, Layer 2, Layer 3, ACL and security-hygiene rule packs and the required traffic intents. Findings are ordered by risk score.
4. **Propose Change** (or a suggested fix) is validated on a copy of the model: risk = 100 × S × (1 + I + E) / 24, bands Low < 25, Medium < 50, High < 75, Critical ≥ 75, and a verdict of Deploy, Deploy with caution or Do not deploy.
5. **Submit for Approval** → an **IT Manager** approves or rejects (a different account; a rejection needs a reason). Re-analysing or editing the change withdraws the approval.
6. **Execute** an approved change: re-validation on a fresh model copy (digital twin), encrypted backup of the running configuration, the commands, a fresh collection and verification of the intended state with no new finding or broken flow; otherwise the changed sections are restored from the backup and the restoration is verified. Laboratory devices are always eligible. A real-network device additionally needs the group permission "Apply approved changes to real-network devices", an approver who is neither the submitter nor the executor, a configurable platform and a hybrid risk within the limit; NetGuard records a live reachability baseline, arms the device's own revert timer where the platform has one (Cisco IOS `reload in`, FortiOS revert, Junos commit confirmed) and rolls back unless the engineer confirms within the window (2–60 minutes). Only a confirmed change is saved. Otherwise the engineer applies the commands and uses **Record as Deployed**.
   **Device access** (EVE-NG style): double-click a device, or use **Open CLI**, for an interactive terminal (SSH, Telnet or the lab console) in a movable window. Production terminals are read-only unless the group may configure, and every session is recorded. **Web GUI** lists the detected management portals (any port, vendor fingerprint, certificate fingerprint) and opens them in a NetGuard window that accepts self-signed certificates, or in the default browser if that window cannot open; an address box accepts an IP, `IP:port` or a full URL and works out HTTP or HTTPS; a port scan (common, well-known or all 65,535 ports) finds portals on custom ports.
   **Backup is optional.** Tick **Back up first** in the apply dialog to save the configuration NetGuard holds for the device; the device panel lists every backup with **Download** and has **Back up now** and **Current config**. The automatic undo does not depend on it: on lab and real devices NetGuard keeps its own restore point.
   **Approval is not the fix.** An approved change is applied only when someone presses **Apply**. Analyze shows each fix's state on its issue ("Waiting for approval", "Approved. Not applied yet" with **Apply Now**) and the dashboard lists approved fixes that are not applied yet.
   **Auto-Fix** is a group permission (Settings → User Accounts → groups): **Fix Now** on an issue or change validates the fix and applies it without waiting for approval, on lab and real-network devices. Administrators have every permission, Auto-Fix included; it can be granted to any other group. Backup, verification, the risk limit, the device revert timer, the confirmation window and automatic rollback always run, "Do not deploy" is never overridden and every use is recorded as "Auto-Fix by <user>". Settings → Security → Fix Safeguards tunes those safeguards.
7. **Reports & History**: every scan, analysis and assessment can be exported as PDF, HTML or JSON without passwords, passphrases or community strings.

User groups: Administrators create groups and choose their permissions (view, edit, import/export, discovery, analysis, propose, approve, execute, credential profiles, users and groups). Built-in groups: Administrators, Network Engineers, IT Managers. A change is never approved by the account that submitted it.

## AI

Advisory models in `backend/services/ai_engine.py` (pure Python, shipped in `data/models/`): a change-risk and blast-radius predictor shown in every assessment, a cross-device link misconfiguration classifier, peer-outlier and syslog classifiers, a root-cause analyzer and a remediation ranker in Analyze Network. The rule verdict (Deploy / caution / Do not deploy) stays deterministic. The hybrid risk shown with it is 0.65 × rules + 0.35 × the model's harm probability, never lower than the rules score, and self-healing refuses changes above the configured hybrid level. Training data in `data/datasets/` is synthetic and simulation-labelled; every applied fix is recorded as a real outcome. Settings → NetGuard AI shows each model in plain words with its held-out quality, learns automatically after a set number of new applied fixes (default 10) or on Retrain Now, and keeps every training as a numbered release (`data/models/versions/`). A new release goes into use only if no quality score drops (champion/challenger); a weaker one is kept as "Not used", and any release can be restored with one click. Rebuild from scratch: `python -m backend.ai.train --include-local`.

## Platforms

`backend/collectors/drivers.py` is the driver matrix: Cisco IOS/IOS-XE, NX-OS, ASA; FortiOS; pfSense and OPNsense (read; changed in their GUI); ArubaOS-Switch and AOS-CX; Ubiquiti EdgeOS/VyOS, EdgeSwitch and UniFi (read; changed by the controller); Ruijie; TP-Link JetStream; D-Link DES/DGS; Huawei VRP; MikroTik RouterOS; Juniper Junos; FiberHome (web GUI and SNMP); FRRouting. Each driver defines the read-only commands, the parser, the configuration syntax, how a change is saved, the device revert timer and the terminal guard.

## Security

- Device secrets and collected configurations are encrypted with AES-256-GCM; on Windows the vault key is protected with DPAPI for the signed-in Windows account.
- Host-header validation (DNS-rebinding protection), no CORS origins by default, login throttling, revocable sessions.
- Discovery and collection send no configuration. Telnet logins are not used by discovery or collection (an interactive terminal may use Telnet when a device offers nothing else, with a cleartext warning) and SNMPv1 is not used; SNMPv2c is used only with a read-only community the engineer saves (it is cleartext; prefer SNMPv3). The lab console is the exception, as EVE-NG/GNS3 expose node consoles over telnet on the lab server.

## Development

```
.venv\Scripts\python -m pytest backend/tests -q -p no:cacheprovider    backend and integration tests (383)
.venv\Scripts\python backend/tests/e2e_acceptance.py                   browser acceptance (Playwright + Chromium)
```

The integration tests run real Netmiko SSH/telnet sessions against Cisco IOS emulators, a pysnmp SNMPv3 agent and EVE-NG/GNS3 API test servers on 127.0.0.1.
