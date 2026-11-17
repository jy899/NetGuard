"""NetGuard browser acceptance test (optional, requires Playwright).

Runs against a real NetGuard server on a throw-away database and data folder:
manual topology CRUD (with a server restart to prove persistence), change risk validation, the
submit / IT Manager approval / record workflow, network analysis, an EVE-NG lab import with read-only console
collection and an approved laboratory change with backup, verification and rollback, read-only discovery,
report export (PDF, HTML, JSON), settings, role restrictions and responsive layout.

Local test endpoints (an EVE-NG API and Cisco IOS console emulators) run inside this script on 127.0.0.1.

    pip install -r requirements.txt
    python -m playwright install chromium
    python backend/tests/e2e_acceptance.py      # add --headed to watch it
"""
from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import Page, expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"


class Server:
    def __init__(self, db_url: str, log_path: Path):
        data = log_path.parent
        self.env = {**os.environ, "NETGUARD_DATABASE_URL": db_url, "NETGUARD_SECRET_KEY": "e2e-secret",
                    "NETGUARD_DATA_DIR": str(data), "NETGUARD_SETTINGS_FILE": str(data / "settings.json"),
                    "NETGUARD_VAULT_KEY_FILE": str(data / "vault.key"), "NETGUARD_AI_AUTO": "0"}
        self.env.pop("NETGUARD_DESKTOP_KEY", None)
        self.log_path = log_path
        self.proc = None

    def start(self):
        log = open(self.log_path, "a", encoding="utf-8")
        self.proc = subprocess.Popen(
            [os.environ.get("NETGUARD_PYTHON", sys.executable), "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", str(PORT)],
            cwd=ROOT, env=self.env, stdout=log, stderr=subprocess.STDOUT,
        )
        for _ in range(50):
            try:
                urllib.request.urlopen(f"{BASE}/api/health", timeout=1)
                return
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("Server did not start")

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=10)
            self.proc = None


results: list[tuple[str, bool]] = []


def step(name: str):
    def wrap(fn):
        def run(*args, **kwargs):
            try:
                value = fn(*args, **kwargs)
                results.append((name, True))
                print(f"  PASS  {name}")
                return value
            except Exception:
                results.append((name, False))
                print(f"  FAIL  {name}")
                raise
        return run
    return wrap


def node_point(page: Page, name: str) -> tuple[float, float]:
    expect(page.locator(".modal-backdrop")).to_have_count(0)
    # Wait until the node stays put for two frames: right after a reload the map can still be fitting or resizing,
    # and a position read mid-move sends the click onto a neighbouring link.
    return page.evaluate(
        """async (name) => {
            const cy = window.netguardWorkspace.cy;
            let last = null;
            for (let i = 0; i < 90; i++) {
                await new Promise(requestAnimationFrame);
                cy.resize();
                const node = cy.nodes().filter(n => n.data('label') === name)[0];
                const box = cy.container().getBoundingClientRect();
                const p = node.renderedPosition();
                const point = [box.left + p.x, box.top + p.y];
                if (last && Math.abs(last[0] - point[0]) < 0.5 && Math.abs(last[1] - point[1]) < 0.5 && !cy.animated()) {
                    return point;
                }
                last = point;
            }
            return last;
        }""",
        name,
    )


def positions(page: Page) -> dict[str, tuple[float, float]]:
    return page.evaluate(
        """() => Object.fromEntries(window.netguardWorkspace.cy.nodes().map(n =>
            [n.data('label'), [Math.round(n.position('x')), Math.round(n.position('y'))]]))"""
    )


def add_device(page: Page, palette_type: str, name: str, vendor="", model="", mgmt=""):
    page.click(f".ng-palette-item[data-device-type={palette_type}]")
    expect(page.locator("#dev-name")).to_be_focused()  # modal fully shown
    page.fill("#dev-name", name)
    page.fill("#dev-vendor", vendor)
    page.fill("#dev-model", model)
    page.fill("#dev-mgmt", mgmt)
    page.click("#device-submit")
    expect(page.locator("#device-modal")).to_be_hidden()
    expect(page.locator("[data-panel=device-name]")).to_have_text(name)


def select_node(page: Page, name: str):
    panel = page.locator("[data-panel=device-name]")
    if panel.count() and panel.first.inner_text().strip() == name:
        return  # already selected: a second quick click would be a double-click (which opens the console)
    x, y = node_point(page, name)
    page.mouse.click(x, y)
    try:
        try:
            expect(page.locator("[data-panel=device-name]")).to_have_text(name, timeout=2500)
        except AssertionError:
            page.wait_for_timeout(700)  # longer than the double-click interval, so a second click is not a double-click
            x, y = node_point(page, name)
            page.mouse.click(x, y)
            expect(page.locator("[data-panel=device-name]")).to_have_text(name)
    except AssertionError:
        debug_dir = ROOT / ".test-tmp"
        debug_dir.mkdir(exist_ok=True)
        page.screenshot(path=str(debug_dir / "selection-failure.png"), full_page=True)
        print(page.evaluate("""() => ({nodes: window.netguardWorkspace.cy.nodes().map(n => ({label:n.data('label'),position:n.renderedPosition()})), canvas:window.netguardWorkspace.cy.container().getBoundingClientRect().toJSON()})"""))
        raise


def add_interfaces(page: Page, device: str, interfaces: list[dict]):
    select_node(page, device)
    page.click("[data-action=manage-interfaces]")
    expect(page.locator("#if-name")).to_be_focused()
    pane = page.locator("#config-pane-interfaces")
    for iface in interfaces:
        page.fill("#if-name", iface["name"])
        if page.locator("#if-mode").count():
            page.select_option("#if-mode", iface.get("mode", "access"))
        for field, key in (("ip_address", "ip"), ("subnet_mask", "mask"), ("vlan_id", "vlan"), ("ospf_area", "ospf")):
            locator = page.locator(f"#if-{field}")
            if locator.count() and locator.is_visible():
                locator.fill(str(iface.get(key, "")))
        page.select_option("#if-status", iface.get("status", "up"))
        page.click("#if-submit")
        expect(pane.locator("[data-crud-table]")).to_contain_text(iface["name"])
    page.click("#config-modal .modal-footer button")
    expect(page.locator("#config-modal")).to_be_hidden()


def open_analysis_level(page: Page) -> str:
    expect(page.locator("[data-analysis=level]")).to_be_visible()
    return page.locator("[data-analysis=level]").inner_text()


def run(headed: bool, artifact_dir: Path | None = None, browser_channel: str | None = None, workflows_only: bool = False) -> int:
    tmp = Path(tempfile.mkdtemp(prefix="netguard-e2e-"))
    print(f"Isolated acceptance data and server log: {tmp}", flush=True)
    if artifact_dir:
        artifact_dir.mkdir(parents=True, exist_ok=True)

    def capture(page, filename):
        expect(page.locator(".modal-backdrop")).to_have_count(0)
        expect(page.locator(".ng-toast")).to_have_count(0, timeout=10000)
        page.evaluate("window.scrollTo(0, 0)")
        page.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
        page.screenshot(path=str((artifact_dir or tmp) / filename), full_page=True)

    server = Server(f"sqlite:///{(tmp / 'e2e.db').as_posix()}", tmp / "server.log")
    console_errors: list[str] = []
    server.start()
    try:
        with sync_playwright() as p:
            executable = os.environ.get("NETGUARD_E2E_CHROMIUM")  # an already installed Chromium, if the bundled one is missing
            browser = p.chromium.launch(headless=not headed, channel=browser_channel, executable_path=executable or None)
            page = browser.new_page(viewport={"width": 1440, "height": 900})
            page.on("console", lambda m: m.type == "error" and console_errors.append(m.text))
            page.on("pageerror", lambda e: console_errors.append(str(e)))
            page.on("dialog", lambda d: d.accept())

            @step("Login and reach dashboard")
            def login():
                page.goto(BASE)
                page.wait_for_url("**/login")
                page.fill("#username", "admin")
                page.fill("#password", "wrong-password")
                page.click("#login-submit")
                expect(page.locator("[data-form-error]")).to_contain_text("Invalid username or password")
                page.fill("#password", "admin")
                page.click("#login-submit")
                page.wait_for_url("**/dashboard")
                expect(page.locator('[data-stat="Networks"]')).to_have_text("0")

            @step("Create 'HQ Enterprise Network'")
            def create_network():
                page.click("a[href='/networks']:has-text('Networks')")
                page.wait_for_url("**/networks")
                # The button exists before the page module binds its handler; retry until the dialog opens.
                for _ in range(20):
                    page.click("#btn-new-network")
                    try:
                        page.locator("#net-name").wait_for(state="visible", timeout=1000)
                        break
                    except Exception:
                        continue
                page.fill("#net-name", "HQ Enterprise Network")
                page.fill("#net-description", "Demo enterprise network for NetGuard")
                page.select_option("#net-type", "Enterprise")
                page.click("#network-submit")
                expect(page.locator("#network-modal")).to_be_hidden()
                page.click("#saved-tab")
                expect(page.locator("tr[data-network-id]")).to_have_count(1)
                expect(page.locator("tr[data-network-id]")).to_contain_text("HQ Enterprise Network")

            @step("Edit network (and revert)")
            def edit_network():
                page.click("tr[data-network-id] [data-action=edit]")
                page.fill("#net-description", "Edited description")
                page.click("#network-submit")
                expect(page.locator("tr[data-network-id]")).to_contain_text("Edited description")
                page.click("tr[data-network-id] [data-action=edit]")
                page.fill("#net-description", "Demo enterprise network for NetGuard")
                page.click("#network-submit")
                expect(page.locator("tr[data-network-id]")).to_contain_text("Demo enterprise network")

            @step("Open network in Topology Workspace")
            def open_network():
                page.click("tr[data-network-id] a[data-action=open]")
                page.wait_for_url("**/topology?network=*")
                expect(page.locator("#canvas-empty")).to_contain_text("This map is empty")

            @step("Add R1, R2, SW1, Finance-PC")
            def add_devices():
                add_device(page, "router", "R1", "Cisco", "ISR 4331", "192.168.1.1")
                add_device(page, "router", "R2", "Cisco", "ISR 4331", "192.168.1.2")
                add_device(page, "switch", "SW1", "Cisco", "Catalyst 2960X-24TS-L", "192.168.1.11")
                add_device(page, "pc", "Finance-PC", "Dell", "OptiPlex", "")
                assert page.evaluate("window.netguardWorkspace.cy.nodes().length") == 4

            @step("Move devices by dragging")
            def move_devices():
                targets = {"R1": (0, -160), "R2": (0, -40), "SW1": (0, 80), "Finance-PC": (0, 200)}
                for name, (dx, dy) in targets.items():
                    x, y = node_point(page, name)
                    box = page.locator("#cy").bounding_box()
                    tx, ty = box["x"] + box["width"] / 2 + dx, box["y"] + box["height"] / 2 + dy
                    page.mouse.move(x, y)
                    page.mouse.down()
                    page.wait_for_timeout(150)  # allow the canvas drag gesture to begin
                    page.mouse.move((x + tx) / 2, (y + ty) / 2, steps=5)
                    page.mouse.move(tx, ty, steps=5)
                    page.mouse.up()
                    page.wait_for_function("""({name, tx, ty}) => {
                        const cy=window.netguardWorkspace.cy;
                        const p=cy.nodes().filter(n=>n.data('label')===name)[0].renderedPosition();
                        const box=cy.container().getBoundingClientRect();
                        return Math.abs(box.left+p.x-tx)<4 && Math.abs(box.top+p.y-ty)<4;
                    }""", arg={"name": name, "tx": tx, "ty": ty})
                expect(page.locator("#save-state")).to_have_text("Unsaved layout")

            @step("Create interfaces")
            def create_interfaces():
                add_interfaces(page, "R1", [
                    {"name": "Gi0/0/0", "ip": "10.0.12.1", "mask": "255.255.255.252"},
                    {"name": "Gi0/0/1", "ip": "10.10.10.1", "mask": "/24"},
                ])
                add_interfaces(page, "R2", [
                    {"name": "Gi0/0/0", "ip": "10.0.12.2", "mask": "255.255.255.252"},
                    {"name": "Gi0/0/1", "ip": "10.20.0.1", "mask": "255.255.255.0"},
                ])
                add_interfaces(page, "SW1", [{"name": "Gi1/0/24", "mode": "trunk"}, {"name": "Gi1/0/1", "vlan": 10}])
                add_interfaces(page, "Finance-PC", [
                    {"name": "eth0", "ip": "10.20.0.10", "mask": "255.255.255.0", "vlan": 10}
                ])
                # validation error is shown, not swallowed
                select_node(page, "R1")
                page.click("[data-action=manage-interfaces]")
                expect(page.locator("#if-name")).to_be_focused()
                page.fill("#if-name", "Gi0/0/9")
                page.fill("#if-ip_address", "10.0.0.300")
                page.fill("#if-subnet_mask", "255.255.255.0")
                page.click("#if-submit")
                expect(page.locator("#config-pane-interfaces [data-form-error]")).to_contain_text("not a valid IPv4 address")
                page.click("#config-modal .modal-footer button")
                expect(page.locator("#config-modal")).to_be_hidden()

            @step("Connect devices (Connect mode, Add Link, Connect To…)")
            def connect():
                # 1. Connect mode: click R1 then R2
                page.click("#btn-edit-menu")
                page.click("#btn-connect")
                for name in ("R1", "R2"):
                    x, y = node_point(page, name)
                    page.mouse.click(x, y)
                expect(page.locator("#link-modal")).to_be_visible()
                assert page.locator("#link-src-if option:checked").inner_text().startswith("Gi0/0/0")
                page.click("#link-submit")
                expect(page.locator("#link-modal")).to_be_hidden()
                # 2. Toolbar Add Link: R2 Gi0/0/1 <-> SW1 Gi1/0/24
                select_node(page, "R2")
                page.click("#btn-edit-menu")
                page.click("#btn-add-link")
                page.select_option("#link-dst-dev", label="SW1")
                page.select_option("#link-src-if", label="Gi0/0/1 (10.20.0.1)")
                page.click("#link-submit")
                expect(page.locator("#link-modal")).to_be_hidden()
                # 3. Panel Connect To…: SW1 Gi1/0/1 <-> Finance-PC eth0
                select_node(page, "SW1")
                page.click("[data-action=connect-from]")
                page.select_option("#link-dst-dev", label="Finance-PC")
                page.click("#link-submit")
                expect(page.locator("#link-modal")).to_be_hidden()
                assert page.evaluate("window.netguardWorkspace.cy.edges().length") == 3
                # in-use interface is not offered again
                select_node(page, "R1")
                page.click("[data-action=connect-from]")
                assert page.locator("#link-src-if option:has-text('Gi0/0/0')").is_disabled()
                page.click("#link-modal .modal-footer .btn-light")
                expect(page.locator("#link-modal")).to_be_hidden()

            @step("Delete a temporary device and a link")
            def delete_items():
                add_device(page, "server", "TEMP-SRV")
                page.click("[data-action=connect-from]")
                page.select_option("#link-dst-dev", label="R1")
                page.click("#link-submit")
                expect(page.locator("#link-modal")).to_be_hidden()
                # the new link is auto-selected; delete it via the panel
                expect(page.locator("#side-panel")).to_contain_text("Selected Link")
                expect(page.locator("#side-panel")).to_contain_text("TEMP-SRV")
                page.click("[data-action=delete-link]")
                page.click(".modal.show [data-ng-confirm]")
                expect(page.locator(".ng-toast", has_text="Link deleted")).to_be_visible()
                # delete device via keyboard
                select_node(page, "TEMP-SRV")
                page.locator("#cy").focus()
                page.keyboard.press("Delete")
                page.click(".modal.show [data-ng-confirm]")
                expect(page.locator(".ng-toast", has_text="TEMP-SRV deleted")).to_be_visible()
                page.wait_for_function("() => window.netguardWorkspace.cy.nodes().length === 4"
                                       " && window.netguardWorkspace.cy.edges().length === 3")

            @step("Save topology")
            def save():
                page.click("#btn-save")
                expect(page.locator("#save-state")).to_have_text("Saved")
                return positions(page)

            login()
            if not workflows_only:
                create_network()
                edit_network()
                open_network()
                add_devices()
                move_devices()
                create_interfaces()
                connect()
                delete_items()
                saved_positions = save()
                page.screenshot(path=str(tmp / "topology_saved.png"))

            @step("Restart server and reload: topology restored")
            def restart_and_reload():
                server.stop()
                server.start()
                page.reload()
                page.wait_for_function("() => window.netguardWorkspace && window.netguardWorkspace.cy.nodes().length === 4")
                assert positions(page) == saved_positions, (positions(page), saved_positions)
                assert page.evaluate("window.netguardWorkspace.cy.edges().length") == 3
                labels = page.evaluate(
                    "window.netguardWorkspace.cy.edges().map(e => e.source().data('label') + ' ' + "
                    "e.data('sourceLabel') + ' <-> ' + e.target().data('label') + ' ' + e.data('targetLabel'))"
                )
                assert "R1 Gi0/0/0 <-> R2 Gi0/0/0" in labels, labels
                assert "SW1 Gi1/0/1 <-> Finance-PC eth0" in labels, labels

            @step("Click R1: details shown in right panel")
            def click_r1():
                select_node(page, "R1")
                panel = page.locator("#side-panel")
                expect(panel.locator("[data-panel=vendor]")).to_have_text("Cisco")
                expect(panel.locator("[data-panel=management-ip]")).to_have_text("192.168.1.1")
                expect(panel).to_contain_text("Gi0/0/0")
                expect(panel).to_contain_text("10.0.12.1/30")
                expect(panel).to_contain_text("10.10.10.1/24")

            @step("Edit R1 and verify it persists")
            def edit_r1():
                page.click("[data-action=edit-device]")
                expect(page.locator("#dev-name")).to_be_focused()
                page.fill("#dev-model", "ISR 4331")
                page.fill("#dev-mgmt", "192.168.1.254")
                page.click("#device-submit")
                expect(page.locator("#device-modal")).to_be_hidden()
                expect(page.locator("[data-panel=model]")).to_have_text("ISR 4331")
                page.reload()
                page.wait_for_function("() => window.netguardWorkspace && window.netguardWorkspace.cy.nodes().length === 4")
                select_node(page, "R1")
                expect(page.locator("[data-panel=model]")).to_have_text("ISR 4331")
                expect(page.locator("[data-panel=management-ip]")).to_have_text("192.168.1.254")
                assert positions(page) == saved_positions

            @step("Dashboard reflects the built network")
            def dashboard_check():
                page.click("a[href='/dashboard']")
                expect(page.locator('[data-stat="Networks"]')).to_have_text("1")
                expect(page.locator('[data-stat="Devices"]')).to_have_text("4")
                expect(page.locator("#recent-networks")).to_contain_text("HQ Enterprise Network")

            def propose(device: str, category: str, change_type: str, fields: dict, selects: dict | None = None):
                select_node(page, device)
                page.click("[data-action=propose-change]")
                expect(page.locator("#change-modal")).to_be_visible()
                expect(page.locator("#chg-fields input, #chg-fields select").first).to_be_focused()
                page.select_option("#chg-category", category)
                page.select_option("#chg-type", change_type)
                for selector, value in (selects or {}).items():
                    page.select_option(selector, value)
                    expect(page.locator(selector)).to_have_value(value)
                try:
                    for selector, value in fields.items():
                        expect(page.locator(selector)).to_be_visible()
                        page.fill(selector, value)
                except Exception:
                    page.screenshot(path=str((artifact_dir or tmp) / "change-form-failure.png"), full_page=True)
                    (artifact_dir or tmp).joinpath("change-form-failure.html").write_text(page.locator("#change-modal").evaluate("element => element.outerHTML"), encoding="utf-8")
                    raise
                page.click("#change-submit")
                expect(page.locator("#change-modal")).to_be_hidden()

            @step("Practice network opens in the topology workspace")
            def golden_open():
                # Example networks are no longer offered in the interface; the test fixture is created through the API.
                token = page.evaluate("localStorage.getItem('netguard.token')")
                created = page.request.post(f"{BASE}/api/networks/samples", headers={"Authorization": f"Bearer {token}"},
                                            data={"scenario": "healthy"}).json()
                page.goto(f"{BASE}/topology?network={created['network_id']}")
                page.wait_for_function("() => window.netguardWorkspace?.cy.nodes().length === 11")
                expect(page.locator("#side-panel")).to_contain_text("Required Flows")
                expect(page.locator("#environment-badge")).to_have_text("Practice network")

            @step("R1 OSPF Area 0 -> 1 is HIGH risk with S/I/E factors, DO NOT DEPLOY, submission blocked")
            def golden_high():
                select_node(page, "R1")
                expect(page.locator("[data-panel=ospf]")).to_contain_text("Area 0")
                propose("R1", "routing", "ospf_area", {"#chg-area": "1", "#chg-reason": "Network redesign"})
                assert open_analysis_level(page) == "HIGH RISK"
                score = int(page.locator("[data-analysis=score]").inner_text())
                expect(page.locator("[data-analysis=formula]")).to_contain_text(f"= {score}")
                assert 50 <= score < 75, score
                expect(page.locator("[data-analysis=recommendation]")).to_have_text("DO NOT DEPLOY")
                expect(page.locator("[data-action=submit-change]")).to_have_count(0)
                expect(page.locator("#side-panel")).to_contain_text("Submission is blocked")
                expect(page.locator("[data-analysis=explanation]")).to_contain_text("from Area 0 to Area 1")
                expect(page.locator("[data-analysis=explanation]")).to_contain_text("OSPF adjacency")
                expect(page.locator(".ng-flow", has_text="Finance-PC").first).to_contain_text("ERP")
                highlighted = page.evaluate("""() => {
                    const cy = window.netguardWorkspace.cy;
                    return {fail: cy.edges('.ng-fail').map(e => e.source().data('label') + '-' + e.target().data('label')),
                            affected: cy.nodes('.ng-affected').map(n => n.data('label')).sort()};
                }""")
                assert highlighted["fail"] == ["R1-R2"], highlighted
                assert highlighted["affected"] == ["R1", "R2"], highlighted
                page.click(".ng-flow >> nth=0")
                assert page.evaluate("window.netguardWorkspace.cy.edges('.ng-focus').length") >= 5

            @step("Modify Area back to 0, re-analyse is LOW / PASS")
            def golden_low():
                page.click("[data-action=modify-change]")
                expect(page.locator("#chg-area")).to_be_focused()
                page.fill("#chg-area", "0")
                page.click("#change-submit")
                expect(page.locator("[data-analysis=level]")).to_have_text("LOW RISK")
                expect(page.locator("[data-analysis=recommendation]")).to_have_text("DEPLOY")
                expect(page.locator("#side-panel")).to_contain_text("Validation PASS")
                assert page.evaluate("window.netguardWorkspace.cy.edges('.ng-fail').length") == 0

            @step("Save assessment, submit for approval, IT Manager approves, engineer applies it to the practice network")
            def golden_save():
                page.click("[data-action=save-assessment]")
                expect(page.locator("[data-action=save-assessment]")).to_have_text("Assessment Saved")
                page.click("[data-action=submit-change]")
                expect(page.locator("#side-panel")).to_contain_text("Waiting for IT Manager approval")
                change_id = int(re.search(r"change=(\d+)", page.url).group(1))
                network_id = int(re.search(r"network=(\d+)", page.url).group(1))
                managers = next(g["id"] for g in api_get("/groups") if g["name"] == "IT Managers")
                api_post("/accounts", {"username": "manager", "password": "Manager-Pass1", "group_id": managers})
                manager = browser.new_page(viewport={"width": 1440, "height": 900})
                manager.on("pageerror", lambda e: console_errors.append(str(e)))
                manager.goto(f"{BASE}/login")
                manager.fill("#username", "manager")
                manager.fill("#password", "Manager-Pass1")
                manager.click("#login-submit")
                manager.wait_for_url("**/dashboard")
                manager.goto(f"{BASE}/topology?network={network_id}&change={change_id}")
                expect(manager.locator("[data-action=approve-change]")).to_be_visible()
                # IT Manager accounts are read-only: editing controls are hidden.
                expect(manager.locator("#btn-add-device")).to_be_hidden()
                expect(manager.locator("[data-action=modify-change]")).to_have_count(0)
                manager.click("[data-action=reject-change]")
                manager.click("#decision-submit")
                expect(manager.locator("#decision-error")).to_contain_text("reason")
                manager.click("#decision-modal .btn-light")
                expect(manager.locator("#decision-modal")).to_be_hidden()
                manager.click("[data-action=approve-change]")
                manager.fill("#decision-note", "Approved for the maintenance window")
                manager.click("#decision-submit")
                expect(manager.locator("#side-panel")).to_contain_text("Approved by manager")
                manager.goto(f"{BASE}/changes?network={network_id}")
                expect(manager.locator("#change-list")).to_contain_text("Approved")
                manager.close()
                page.reload()
                # A practice network has no device: the approved fix is applied to NetGuard's model and checked.
                expect(page.locator("[data-action=apply-change]")).to_have_count(0)
                page.click("[data-action=execute-change]")
                expect(page.locator("#execute-where")).to_contain_text("no device is contacted")
                expect(page.locator("#execute-connection")).to_be_hidden()
                page.click("#execute-submit")
                expect(page.locator("#execute-result")).to_contain_text("Fixed and checked", timeout=30000)
                page.click("#execute-close")
                expect(page.locator("#side-panel")).to_contain_text("Fixed in the practice network")

            @step("Second demo: ACL blocking Finance-PC -> ERP TCP/443 is CRITICAL")
            def golden_acl():
                propose("R3", "acl", "acl_add",
                        {"#chg-port": "443", "#chg-source": "10.20.0.0/24", "#chg-destination": "192.168.30.10"},
                        {"#chg-acl_action": "deny", "#chg-protocol": "tcp"})
                assert open_analysis_level(page) == "CRITICAL RISK"
                expect(page.locator("[data-analysis=recommendation]")).to_have_text("DO NOT DEPLOY")
                expect(page.locator(".ng-finding")).to_contain_text("ACL001")
                expect(page.locator(".ng-flow.ng-flow >> nth=0")).to_contain_text("Finance ERP access")
                assert int(page.locator("[data-analysis=score]").inner_text()) >= 75
                capture(page, "fyp1-acl-assessment.png")
                page.keyboard.press("Escape")
                expect(page.locator("[data-analysis=level]")).to_have_count(0)

            @step("Changes and validation use one section while existing assessment reports remain functional")
            def history_pages():
                page.goto(f"{BASE}/reports")
                page.select_option("#filter-kind", "assessment")
                saved = len(api_get("/assessments?saved=true"))
                expect(page.locator("#report-list tbody tr")).to_have_count(saved)
                expect(page.locator("#report-list")).to_contain_text("OSPF Area")
                page.locator("#report-list a", has_text="View Report").first.click()
                expect(page.locator(".ng-report")).to_contain_text("LOW RISK")
                page.goto(f"{BASE}/changes")
                expect(page.locator("#change-list tbody tr")).to_have_count(2)
                page.click("#validation-tab")
                expect(page.locator("#run-checks")).to_contain_text("ACL001")
                expect(page.locator("#run-checks")).to_contain_text("Baseline and proposed configuration")
                page.click("#rules-tab")
                expect(page.locator("#rule-list tbody tr")).to_have_count(len(api_get("/rules")))
                page.goto(f"{BASE}/settings")
                expect(page.locator("#account-info")).to_contain_text("Administrator")
                page.goto(f"{BASE}/dashboard")
                expect(page.locator('[data-stat="Changes"]')).to_have_text(str(len(api_get("/changes"))))
            def api_get(path):
                token = page.evaluate("localStorage.getItem('netguard.token')")
                response = page.request.get(f"{BASE}/api{path}", headers={"Authorization": f"Bearer {token}"})
                assert response.ok, response.text()
                return response.json()

            def api_post(path, payload):
                token = page.evaluate("localStorage.getItem('netguard.token')")
                response = page.request.post(f"{BASE}/api{path}", headers={"Authorization": f"Bearer {token}"}, data=payload)
                assert response.ok, response.text()
                return response.json()

            def api_put(path, payload):
                token = page.evaluate("localStorage.getItem('netguard.token')")
                response = page.request.put(f"{BASE}/api{path}", headers={"Authorization": f"Bearer {token}"}, data=payload)
                assert response.ok, response.text()
                return response.json()

            def assert_secret_fields_absent(value):
                if isinstance(value, dict):
                    forbidden = {"password", "password_enc", "encrypted_password", "password_hash", "ciphertext"}
                    assert not forbidden.intersection(value), f"Secret field exposed: {forbidden.intersection(value)}"
                    for item in value.values():
                        assert_secret_fields_absent(item)
                elif isinstance(value, list):
                    for item in value:
                        assert_secret_fields_absent(item)

            @step("Network analysis: findings ordered by risk; fixes are validated and submitted for approval, never applied directly")
            def health_check():
                response = api_post("/networks/demo?faulty=true", {})
                page.goto(f"{BASE}/topology?network={response['id']}")
                page.wait_for_function("() => window.netguardWorkspace?.cy.nodes().length === 11")
                page.click("#btn-health")
                expect(page.locator("[data-health=status]")).to_have_text("4 ISSUES FOUND")
                assert page.evaluate("window.netguardWorkspace.cy.edges('.ng-fail').length") >= 3
                scores = [int(re.search(r"Risk (\d+)", t).group(1)) for t in page.locator(".ng-issue").all_inner_texts()]
                assert scores == sorted(scores, reverse=True) and len(scores) == 4, scores
                # Cancelling the confirmation changes nothing.
                page.click("[data-action=apply-fix] >> nth=0")
                page.click(".modal.show .modal-footer .btn-light")
                assert api_get(f"/changes?network_id={response['id']}") == []
                page.click("[data-action=apply-fix] >> nth=0")
                page.click(".modal.show [data-ng-confirm]")
                expect(page.locator("#side-panel")).to_contain_text("Waiting for IT Manager approval")
                expect(page.locator("pre.ng-cli").first).to_be_visible()
                page.click("[data-action=close-analysis]")
                expect(page.locator("[data-health=status]")).to_have_text("4 ISSUES FOUND")  # the model is unchanged
                page.click("[data-action=fix-all]")
                page.click(".modal.show [data-ng-confirm]")
                expect(page.locator(".ng-toast", has_text="for approval")).to_be_visible(timeout=20000)
                changes = api_get(f"/changes?network_id={response['id']}")
                assert len(changes) >= 4 and all(c["status"] == "pending_approval" for c in changes), [c["status"] for c in changes]
                page.goto(f"{BASE}/changes?network={response['id']}")
                page.select_option("#filter-status", "pending_approval")
                expect(page.locator("#change-list tbody tr")).to_have_count(len(changes))
                expect(page.locator("#change-list")).to_contain_text("Awaiting approval")

            @step("AI insights: root causes, anomalies and ranked fixes appear in the network analysis")
            def ai_insights():
                response = api_post("/networks/samples", {"scenario": "routing"})
                page.goto(f"{BASE}/topology?network={response['network_id']}")
                page.wait_for_function("() => window.netguardWorkspace?.cy.nodes().length > 4")
                page.click("#btn-health")
                expect(page.locator("[data-health=ai]")).to_contain_text("OSPF001")
                expect(page.locator("[data-fix-ai]").first).to_contain_text("AI repair likelihood")
                insight = api_get(f"/ai/networks/{response['network_id']}/insights")
                assert insight["root_causes"][0]["rule_id"] == "OSPF001", insight["root_causes"]

            @step("Project import: a Packet Tracer file builds the whole topology; one config offers neighbour inference")
            def project_import():
                from backend.collectors import packet_tracer
                from backend.tests.test_project_import import PT_XML
                page.goto(f"{BASE}/networks")
                page.click("#btn-import")
                page.set_input_files("#imp-project", files=[{"name": "branch.pkt", "mimeType": "application/octet-stream",
                                                             "buffer": packet_tracer.encode(PT_XML)}])
                expect(page.locator("#imp-project-list")).to_contain_text("branch.pkt")
                page.click("#imp-submit")
                page.wait_for_url("**/topology?network=*")
                page.wait_for_function("() => window.netguardWorkspace?.cy.nodes().length === 4")
                assert len(api_get(f"/networks/{re.search(r'network=(\d+)', page.url).group(1)}/topology")["links"]) == 3
                page.goto(f"{BASE}/networks")
                page.click("#btn-import")
                edge = b"hostname EDGE\ninterface Gi0/0\n ip address 10.9.9.1 255.255.255.252\nip route 0.0.0.0 0.0.0.0 10.9.9.2\n"
                page.set_input_files("#imp-project", files=[{"name": "EDGE.cfg", "mimeType": "text/plain", "buffer": edge}])
                page.click("#imp-submit")
                expect(page.locator("#imp-single")).to_contain_text("One device was imported")
                page.click("#imp-infer")
                page.wait_for_url("**/topology?network=*")
                page.wait_for_function("() => window.netguardWorkspace?.cy.nodes().length >= 2")
                page.goto(f"{BASE}/networks")
                page.click("[data-provider='eve-ng']")
                assert page.locator("#provider-insecure").count() == 0
                expect(page.locator("#provider-form")).not_to_contain_text("never stored")
                page.keyboard.press("Escape")

            @step("EVE-NG lab import, read-only console collection, approved change executed on the lab device and verified; double-click opens the lab console terminal")
            def lab_workflow():
                from backend.tests.fixtures.ios_emulator import Device, TelnetEmulator
                from backend.tests.fixtures.lab_servers import eve_ng
                r1_cfg = ("hostname R1\ninterface Ethernet0/0\n ip address 10.0.10.1 255.255.255.0\ninterface Ethernet0/1\n"
                          " ip address 10.0.20.1 255.255.255.0\nline vty 0 4\n transport input ssh\n access-class 5 in\n"
                          "access-list 5 permit 10.0.10.0 0.0.0.255\n")
                sw1_cfg = ("hostname SW1\nvlan 10\n name USERS\nvlan 20\n name SERVERS\n" +
                           "".join(f"interface GigabitEthernet0/{n}\n switchport mode access\n switchport access vlan {v}\n"
                                   for n, v in ((0, 10), (1, 20), (2, 20), (3, 20))) + "line vty 0 4\n transport input ssh\n")
                version = "Cisco IOS Software, Linux Software (I86BI_LINUX-ADVENTERPRISEK9-M), Version 15.7(3)M3\nR1 uptime is 1 hour\n"
                r1 = Device("R1", r1_cfg, {"show version": version})
                sw1 = Device("SW1", sw1_cfg, {"show version": version.replace("R1", "SW1").replace("Linux Software", "vios_l2 Software")})
                consoles = {"R1": TelnetEmulator(r1), "SW1": TelnetEmulator(sw1)}
                server = eve_ng({
                    "path": "/NetGuard/branch.unl", "name": "Branch",
                    "nodes": {"1": {"id": 1, "name": "R1", "template": "iol", "type": "iol", "status": 2, "left": 300, "top": 100,
                                    "url": f"telnet://127.0.0.1:{consoles['R1'].port}"},
                              "2": {"id": 2, "name": "SW1", "template": "viosl2", "type": "qemu", "status": 2, "left": 300, "top": 260,
                                    "url": f"telnet://127.0.0.1:{consoles['SW1'].port}"},
                              "3": {"id": 3, "name": "PC1", "template": "vpcs", "type": "vpcs", "status": 2, "left": 200, "top": 420},
                              "4": {"id": 4, "name": "PC2", "template": "vpcs", "type": "vpcs", "status": 2, "left": 400, "top": 420}},
                    "interfaces": {"1": [{"name": "e0/0", "network_id": 1}, {"name": "e0/1", "network_id": 4}],
                                   "2": [{"name": f"Gi0/{n}", "network_id": n + 1} for n in range(4)],
                                   "3": [{"name": "eth0", "network_id": 2}], "4": [{"name": "eth0", "network_id": 3}]},
                    "networks": {str(i): {"id": i, "name": f"Net{i}", "type": "bridge", "visibility": 0} for i in range(1, 5)},
                    "configs": {"1": r1_cfg, "2": sw1_cfg}})
                try:
                    page.goto(f"{BASE}/networks")
                    page.click("[data-provider='eve-ng']")
                    page.fill("#provider-server", server.url)
                    page.fill("#provider-user", "admin")
                    page.fill("#provider-password", "wrong")
                    page.click("#provider-connect")
                    expect(page.locator("#provider-form [data-form-error]")).to_be_visible()
                    page.fill("#provider-password", "eve")
                    page.click("#provider-connect")
                    expect(page.locator("#provider-project")).to_be_visible()
                    page.click("#provider-project-open")
                    page.wait_for_url("**/topology?network=*")
                    page.wait_for_function("() => window.netguardWorkspace?.cy.nodes().length === 4")
                    expect(page.locator("#environment-badge")).to_have_text("Virtual lab · EVE-NG")
                    nid = int(re.search(r"network=(\d+)", page.url).group(1))
                    topo = api_get(f"/networks/{nid}/topology")
                    assert {l["evidence_grade"] for l in topo["links"]} == {"Confirmed"}
                    devices = {d["name"]: d for d in topo["devices"]}
                    for name, ip, gw in (("PC1", "10.0.10.10", "10.0.10.1"), ("PC2", "10.0.20.10", "10.0.20.1")):
                        eth0 = next(i for i in devices[name]["interfaces"] if i["name"] == "eth0")
                        api_put(f"/interfaces/{eth0['id']}", {"name": "eth0", "ip_address": ip, "subnet_mask": "255.255.255.0", "status": "up"})
                        api_put(f"/devices/{devices[name]['id']}", {"name": name, "device_type": "pc", "default_gateway": gw})
                    api_post(f"/networks/{nid}/intents", {"name": "PC1 to PC2", "source_device_id": devices["PC1"]["id"],
                                                          "destination_device_id": devices["PC2"]["id"], "protocol": "icmp",
                                                          "expected_action": "allow", "criticality": "critical"})
                    page.reload()
                    page.wait_for_function("() => window.netguardWorkspace?.cy.nodes().length === 4")
                    page.click("#btn-collect")
                    expect(page.locator("#collect-devices input")).to_have_count(2)
                    page.select_option("#collect-transport", "console")
                    page.click("#collect-submit")
                    expect(page.locator("#collect-result .border-success")).to_have_count(2, timeout=30000)
                    expect(page.locator("#collect-result")).to_contain_text("SHA-256")
                    page.click("#collect-modal .modal-footer .btn-light")
                    page.click("#btn-health")
                    vlan_issue = page.locator(".ng-issue", has_text="VLAN001")
                    expect(vlan_issue).to_contain_text("Layer 2")
                    vlan_issue.locator("[data-action=apply-fix]").first.click()
                    page.click(".modal.show [data-ng-confirm]")
                    expect(page.locator("#side-panel")).to_contain_text("Waiting for IT Manager approval")
                    change_id = int(re.search(r"change=(\d+)", page.url).group(1))
                    manager_token = page.request.post(f"{BASE}/api/auth/login", data={"username": "manager", "password": "Manager-Pass1"}).json()["access_token"]
                    approved = page.request.post(f"{BASE}/api/changes/{change_id}/approve", headers={"Authorization": f"Bearer {manager_token}"},
                                                 data={"note": "Lab window"})
                    assert approved.ok, approved.text()
                    page.reload()
                    page.click("[data-action=execute-change]")
                    expect(page.locator("#execute-commands")).to_contain_text("switchport access vlan")
                    page.select_option("#execute-transport", "console")
                    page.check("#execute-backup")
                    page.click("#execute-submit")
                    expect(page.locator("#execute-result")).to_contain_text("Fixed and checked", timeout=60000)
                    expect(page.locator("#execute-result")).to_contain_text("Backup saved")
                    expect(page.locator("#execute-result [data-download-backup]")).to_be_visible()
                    expect(page.locator("#execute-result")).to_contain_text("Verification passed")
                    capture_modal = (artifact_dir or tmp) / "lab-execution.png"
                    page.screenshot(path=str(capture_modal), full_page=True)
                    page.click("#execute-close")
                    expect(page.locator("#side-panel")).to_contain_text("laboratory device and checked")
                    running = sw1.running()
                    assert "switchport access vlan 10" in running.split("interface GigabitEthernet0/1")[1].split("interface")[0], running
                    page.click("[data-action=close-analysis]")
                    page.click("#btn-health")
                    expect(page.locator(".ng-issue", has_text="VLAN001")).to_have_count(0)
                    # EVE-NG style: double-clicking a lab node opens its console in a floating xterm.js terminal.
                    page.click("[data-action=close-health]")
                    x, y = node_point(page, "R1")
                    page.mouse.dblclick(x, y)
                    expect(page.locator("#term-modal")).to_be_visible()
                    expect(page.locator("#term-transport")).to_contain_text("Lab console")
                    page.click("#term-connect")
                    terminal = page.locator(".ng-term-window").last
                    expect(terminal).to_contain_text("LAB")
                    expect(terminal.locator(".xterm-rows")).to_contain_text("Connected", timeout=15000)
                    terminal.locator(".xterm-helper-textarea").focus()
                    page.keyboard.type("show version")
                    page.keyboard.press("Enter")
                    expect(terminal.locator(".xterm-rows")).to_contain_text("Cisco IOS Software", timeout=15000)
                    page.screenshot(path=str((artifact_dir or tmp) / "lab-terminal.png"), full_page=True)
                    terminal.locator("[data-term-close]").click()
                    expect(page.locator(".ng-term-window")).to_have_count(0)
                    terminal_rows = api_get(f"/history?network_id={nid}&kind=terminal")
                    assert terminal_rows and terminal_rows[0]["summary"]["mode"] == "full", terminal_rows
                finally:
                    server.close()
                    for console in consoles.values():
                        console.close()
                return nid

            @step("Real Network discovery: one Scan, live progress, a results table with evidence; exclusions are honoured")
            def discovery_scan():
                page.goto(f"{BASE}/networks?environment=real")
                expect(page.locator("#scan-interface option", has_text="Other range")).to_be_attached()  # adapters detected
                assert page.locator("#scan-authorized").count() == 0  # no extra permission step
                page.fill("#scan-target", "127.0.0.0/30")
                page.click("#scan-options summary")
                page.fill("#scan-excluded", "127.0.0.2")
                page.fill("#scan-untrusted", "203.0.113.0/24")
                expect(page.locator("#scan-target")).to_have_value("127.0.0.0/30")
                page.click("#scan-start")
                expect(page.locator("#scan-progress")).to_be_visible()
                expect(page.locator("[data-scan=devices], #scan-table p")).to_be_visible(timeout=120000)
                networks = [n for n in api_get("/networks") if n.get("source") == "discovery"]
                assert networks, "the scan did not create a discovery workspace"
                result = api_get(f"/discovery/{networks[-1]['id']}")
                assert result["report"]["scope"]["untrusted"] == ["203.0.113.0/24"], result["report"]["scope"]
                assert "127.0.0.2/32" in result["report"]["scope"]["excluded"], result["report"]["scope"]
                assert result["mode"] == "live" and "127.0.0.2" not in {d["ip"] for d in result["devices"]}
                for device in result["devices"]:  # every device rests on observed evidence
                    assert device["provenance"], device
                if result["devices"]:
                    page.locator("[data-device-details]").first.click()
                    expect(page.locator("#device-details")).to_contain_text("Discovery evidence")
                    page.keyboard.press("Escape")

            @step("Reports export as PDF, HTML and JSON from the server without secrets")
            def report_exports(lab_network_id):
                page.goto(f"{BASE}/topology?network={lab_network_id}")
                page.wait_for_function("() => window.netguardWorkspace?.cy.nodes().length === 4")
                page.click("#btn-report")
                page.wait_for_url("**/reports?record=*")
                expect(page.locator(".ng-report")).to_contain_text("Device Inventory")
                expect(page.locator(".ng-report")).not_to_contain_text("[object Object]")
                expect(page.locator(".ng-report")).not_to_contain_text("Simulated")
                import json
                for fmt in ("pdf", "html", "json"):
                    with page.expect_download() as info:
                        page.click(f"[data-export={fmt}]")
                    destination = (artifact_dir or tmp) / f"lab-report.{fmt}"
                    info.value.save_as(destination)
                    raw = destination.read_bytes()
                    if fmt == "pdf":
                        assert raw.startswith(b"%PDF"), raw[:20]
                    elif fmt == "html":
                        assert b"Findings" in raw or b"Summary" in raw
                    else:
                        data = json.loads(raw)
                        assert data["kind"] == "report"
                        assert_secret_fields_absent(data)
                    assert b"Lab-Pass1" not in raw and b"Manager-Pass1" not in raw
                capture(page, "lab-report.png")
                page.goto(f"{BASE}/reports")
                page.select_option("#filter-kind", "assessment")
                page.locator("#report-list a", has_text="View Report").first.click()
                expect(page.locator("[data-analysis=formula]")).to_be_visible()
                with page.expect_download() as info:
                    page.click("[data-export=pdf]")
                assert info.value.path().read_bytes().startswith(b"%PDF")

            @step("Undo Fix on the toolbar: confirm, and the practice network is back as before the fix")
            def toolbar_undo_fix():
                created = page.evaluate("""async () => {
                    const r = await fetch('/api/networks/samples', {method: 'POST', headers: {'Content-Type': 'application/json',
                      Authorization: 'Bearer ' + localStorage.getItem('netguard.token')}, body: JSON.stringify({scenario: 'interface', name: 'Undo practice'})});
                    return (await r.json()).network_id; }""")
                page.goto(f"{BASE}/topology?network={created}")
                expect(page.locator("#btn-undo-fix")).to_be_disabled()  # nothing applied yet
                page.click("#btn-health")
                first_issue = page.locator("[data-issue-card]").first
                expect(first_issue).to_be_visible()
                issues_before = page.locator("[data-issue-card]").count()
                page.locator("[data-action=auto-fix]").first.click()
                page.click("#execute-submit")
                expect(page.locator("#execute-result")).to_contain_text("Fixed and checked", timeout=30000)
                page.click("#execute-close")
                expect(page.locator("#btn-undo-fix")).to_be_enabled()
                expect(page.locator("[data-health=applied-fixes]")).to_contain_text("Applied fixes")
                page.click("#btn-undo-fix")
                expect(page.locator(".modal.show")).to_contain_text("Undo this fix?")
                expect(page.locator(".modal.show")).to_contain_text("After undo")
                page.click(".modal.show [data-ng-confirm]")
                expect(page.locator(".ng-toast, .toast").last).to_contain_text("Fix undone")
                expect(page.locator("#btn-undo-fix")).to_be_disabled()
                expect(page.locator("[data-health=applied-fixes]")).to_have_count(0)
                expect(page.locator("[data-issue-card]")).to_have_count(issues_before)
                page.goto(f"{BASE}/changes?network={created}")
                expect(page.locator("#change-list")).to_contain_text("Undone")

            @step("Six navigation items and a minimal login interface; no simulation wording remains")
            def professional_shell():
                expect(page.locator(".ng-nav a")).to_have_count(6)
                assert [text.strip() for text in page.locator(".ng-nav a").all_text_contents()] == ["Dashboard", "Networks", "Topology Workspace", "Validation & Changes", "Reports & History", "Settings"]
                for path in ("/dashboard", "/networks", "/networks?environment=real", "/changes", "/settings"):
                    page.goto(f"{BASE}{path}")
                    page.wait_for_load_state("networkidle")
                    for forbidden in ("Simulation mode", "simulated", "Simulated", "Use Sample Credentials"):
                        expect(page.locator("body")).not_to_contain_text(forbidden)
                other = browser.new_page()
                other.goto(f"{BASE}/login")
                expect(other.locator("input")).to_have_count(2)
                expect(other.locator("button")).to_have_count(1)
                expect(other.locator("button")).to_have_text("Sign In")
                other.close()

            @step("Settings: profile without email, encrypted credential profiles, AI models and security information")
            def settings_profiles():
                page.goto(f"{BASE}/settings")
                expect(page.locator("#account-info")).to_contain_text("Administrators")
                expect(page.locator("#account-permissions li")).to_have_count(len(api_get("/permissions")))
                assert page.locator("#profile-email").count() == 0 and "Email" not in page.locator("#profile-pane").inner_text()
                expect(page.locator("#sessions-pane")).not_to_contain_text("Other browser sessions are not listed")
                expect(page.locator("#security-pane")).not_to_contain_text("listens on 127.0.0.1 only")
                page.click("#ai-tab")
                expect(page.locator("#ai-info")).to_contain_text("Change risk")
                expect(page.locator("#ai-versions")).to_contain_text("In use")
                page.click("#credentials-tab")
                page.click("#btn-add-credential")
                assert page.locator("#credential-method option").all_inner_texts() == ["SSH", "SNMPv3 (authPriv)", "SNMPv2c (read-only community)"]
                page.fill("#credential-name", "Lab routers")
                page.fill("#credential-username", "netguard")
                page.fill("#credential-password", "Lab-Pass1")
                page.click("#credential-submit")
                expect(page.locator("#credential-modal")).to_be_hidden()
                row = page.locator("#credential-list tr", has_text="Lab routers")
                row.locator("[data-profile-action=edit]").click()
                expect(page.locator("#credential-password")).to_have_value("")
                page.fill("#credential-notes", "Edited without replacing the password")
                page.click("#credential-submit")
                expect(page.locator("#credential-modal")).to_be_hidden()
                expect(row).to_contain_text("Edited without replacing")
                assert_secret_fields_absent(api_get("/credential-profiles"))
                import sqlite3
                with sqlite3.connect(tmp / "e2e.db") as connection:
                    stored = [value for (value,) in connection.execute("SELECT password_enc FROM credential_profiles") if value]
                    assert stored and all(str(value).startswith("enc2:") and "Lab-Pass1" not in str(value) for value in stored), stored
                    configs = [value for (value,) in connection.execute("SELECT text_enc FROM device_configs")]
                    assert configs and all(str(value).startswith("enc2:") for value in configs)
                row.locator("[data-profile-action=delete]").click()
                page.click(".modal.show [data-ng-confirm]")
                expect(row).to_have_count(0)
                page.click("#security-tab")
                expect(page.locator("#security-info")).to_contain_text("AES-256-GCM")
                expect(page.locator("#security-info")).to_contain_text("Desktop window only")

            @step("User groups: a custom group grants granular permissions; session revocation invalidates older tokens")
            def settings_accounts_sessions():
                page.goto(f"{BASE}/settings")
                page.click("#accounts-tab")
                expect(page.locator("#account-list")).not_to_contain_text("Email")
                page.click("#btn-add-group")
                page.fill("#group-name", "Auditors")
                page.fill("#group-description", "Read-only review")
                page.check("#perm-topology\\.view")
                page.click("#group-submit")
                expect(page.locator("#group-modal")).to_be_hidden()
                expect(page.locator("#group-list tr", has_text="Auditors")).to_contain_text("View")
                page.click("#btn-add-account")
                page.fill("#account-username", "reviewer")
                page.fill("#account-password", "ReviewerPass123")
                page.select_option("#account-group", label="Auditors")
                page.click("#account-submit")
                expect(page.locator("#account-modal")).to_be_hidden()
                row = page.locator("#account-list tr", has_text="reviewer")
                expect(row).to_contain_text("Auditors")
                login = page.request.post(f"{BASE}/api/auth/login", data={"username": "reviewer", "password": "ReviewerPass123"}).json()
                headers = {"Authorization": "Bearer " + login["access_token"]}
                assert page.request.get(f"{BASE}/api/accounts", headers=headers).status == 403
                assert page.request.post(f"{BASE}/api/networks", headers=headers, data={"name": "x"}).status == 403
                assert page.request.get(f"{BASE}/api/networks", headers=headers).ok
                # Granting a permission to the group takes effect on the next request.
                page.locator("#group-list tr", has_text="Auditors").locator("[data-group-action=edit]").click()
                page.check("#perm-network\\.edit")
                page.click("#group-submit")
                expect(page.locator("#group-modal")).to_be_hidden()
                created = page.request.post(f"{BASE}/api/networks", headers=headers, data={"name": "Auditor sandbox"})
                assert created.status == 201, created.text()
                page.request.delete(f"{BASE}/api/networks/{created.json()['id']}", headers={"Authorization": "Bearer " + page.evaluate("localStorage.getItem('netguard.token')")})
                row.locator("[data-account-action=delete]").click()
                page.click(".modal.show [data-ng-confirm]")
                expect(row).to_have_count(0)
                earlier = page.evaluate("localStorage.getItem('netguard.token')")
                page.click("#profile-tab")
                page.click("#btn-revoke-sessions")
                page.click(".modal.show [data-ng-confirm]")
                expect(page.locator(".ng-toast", has_text="Other sessions signed out")).to_be_visible()
                assert page.request.get(f"{BASE}/api/auth/me", headers={"Authorization": "Bearer " + earlier}).status == 401
                assert api_get("/auth/me")["username"] == "admin"

            @step("Host header is validated (DNS rebinding protection)")
            def host_header():
                response = page.request.get(f"{BASE}/api/health", headers={"Host": "attacker.example"})
                assert response.status == 421, response.status

            @step("Layout fits at 1366x768 and 1920x1080")
            def screen_sizes():
                for width, height in ((1366, 768), (1920, 1080)):
                    page.set_viewport_size({"width": width, "height": height})
                    network = next(item for item in api_get("/networks") if item["device_count"] >= 4)
                    page.goto(f"{BASE}/topology?network={network['id']}")
                    page.wait_for_function("() => window.netguardWorkspace && window.netguardWorkspace.cy.nodes().length >= 4")
                    assert not page.evaluate("document.documentElement.scrollWidth > window.innerWidth"), f"horizontal overflow at {width}px"
                    cy_box = page.locator("#cy").bounding_box()
                    assert cy_box["width"] > 500 and cy_box["height"] > 400, cy_box
                    page.screenshot(path=str((artifact_dir or tmp) / f"topology_{width}.png"))
                page.set_viewport_size({"width": 1440, "height": 900})

            @step("No horizontal overflow at 390px (phone width) on any page")
            def phone_width():
                page.set_viewport_size({"width": 390, "height": 844})
                for path in ("/dashboard", "/networks", "/networks?environment=real", "/topology", "/changes", "/reports", "/settings", "/settings?tab=credentials"):
                    page.goto(f"{BASE}{path}")
                    page.wait_for_load_state("networkidle")
                    assert not page.evaluate("() => document.documentElement.scrollWidth > window.innerWidth"), f"horizontal overflow at 390px on {path}"
                page.set_viewport_size({"width": 1440, "height": 900})

            @step("Logout returns to login and protects pages")
            def logout():
                token = page.evaluate("() => localStorage.getItem('netguard.token')")
                page.click("#ng-user-menu")
                page.click("#ng-logout")
                page.wait_for_url("**/login")
                assert page.request.get(f"{BASE}/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status == 401
                page.goto(f"{BASE}/topology")
                page.wait_for_url("**/login?next=*")

            if not workflows_only:
                restart_and_reload()
                click_r1()
                edit_r1()
                dashboard_check()
            golden_open()
            golden_high()
            golden_low()
            golden_save()
            golden_acl()
            history_pages()
            health_check()
            ai_insights()
            project_import()
            lab_network = lab_workflow()
            discovery_scan()
            report_exports(lab_network)
            toolbar_undo_fix()
            professional_shell()
            settings_profiles()
            settings_accounts_sessions()
            host_header()
            screen_sizes()
            phone_width()
            logout()
            browser.close()
    finally:
        server.stop()

    log_text = (tmp / "server.log").read_text(encoding="utf-8")
    assert "Lab-Pass1" not in log_text, "A typed device secret reached the server log"
    server_errors = log_text.count("Traceback") + log_text.count(" 500 ")
    # Negative tests deliberately trigger 401, 403, 409, 421 and 422 responses; browsers log those to the console.
    expected = [e for e in console_errors if "Failed to load resource" in e and any(c in e for c in ("401", "403", "409", "421", "422"))]
    console_errors = [e for e in console_errors if e not in expected]
    print(f"\nExpected HTTP 4xx logs from negative tests: {len(expected)}")
    print(f"Unexpected browser console errors: {len(console_errors)}")
    for err in console_errors:
        print(f"  - {err}")
    print(f"Server exceptions / 500 responses: {server_errors}")
    print(f"Artifacts (screenshots, exported reports, server log): {artifact_dir or tmp}")
    failed = [name for name, ok in results if not ok]
    ok = not failed and not console_errors and server_errors == 0
    print(f"\n{'ACCEPTANCE PASSED' if ok else 'ACCEPTANCE FAILED'}: {sum(ok for _, ok in results)}/{len(results)} steps")
    return 0 if ok else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--workflows-only", action="store_true", help="Skip the manual topology CRUD and restart regression")
    parser.add_argument("--port", type=int, default=0, help="Local test port; 0 selects an available port")
    parser.add_argument("--artifacts", type=Path, help="Optional folder for screenshots and exported reports")
    parser.add_argument("--browser-channel", choices=["chrome", "msedge"], help="Use an installed browser instead of a Playwright browser download")
    args = parser.parse_args()
    if args.port:
        PORT = args.port
    else:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            PORT = listener.getsockname()[1]
    BASE = f"http://127.0.0.1:{PORT}"
    sys.exit(run(args.headed, args.artifacts, args.browser_channel, args.workflows_only))
