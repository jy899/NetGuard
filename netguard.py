"""NetGuard desktop application (Windows 11) and its administrative commands.

    NetGuard.exe                       open the desktop application (pywebview window)
    NetGuard.exe --enable-web-access   allow a local browser at http://127.0.0.1:8001 (asks for an administrator)
    NetGuard.exe --disable-web-access  turn browser access off again
    NetGuard.exe --server              run the local service without a window (browser access must be enabled)
    NetGuard.exe --reset-admin         set the admin account back to admin / admin (Reset_Admin_Password.cmd)

From source, use "python netguard.py" with the same options. The service only listens on 127.0.0.1.
"""
from __future__ import annotations

import argparse
import getpass
import os
import secrets
import socket
import sys
import threading
import time
from pathlib import Path

if getattr(sys, "frozen", False):  # PyInstaller: data stays next to the executable, code in the bundle
    os.environ.setdefault("NETGUARD_DATA_DIR", str(Path(sys.executable).resolve().parent / "data"))
    sys.path.insert(0, str(Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))))
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

DEFAULT_PORT = int(os.getenv("NETGUARD_PORT", "8001"))

# NetGuard.exe is a window without a console: Python then has no stdout/stderr, and the web server's logging
# fails on start ("'NoneType' object has no attribute 'isatty'"). Its output goes to data/netguard.log instead.
WINDOWED = sys.stdout is None or sys.stderr is None
if WINDOWED:
    _log_dir = Path(os.environ.get("NETGUARD_DATA_DIR") or Path(__file__).resolve().parent / "data")
    _log_dir.mkdir(parents=True, exist_ok=True)
    _log = open(_log_dir / "netguard.log", "w", encoding="utf-8", buffering=1)  # noqa: SIM115 - open for the run
    sys.stdout = sys.stdout or _log
    sys.stderr = sys.stderr or _log


def _tell(message: str) -> None:
    """Show a message: in the console, or (NetGuard.exe has none) in a Windows message box."""
    print(message)
    if WINDOWED and sys.platform == "win32":
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, message, "NetGuard", 0x40)


def _admin_check(username: str | None, password: str | None) -> bool:
    from sqlalchemy import select

    from backend.core.permissions import is_admin
    from backend.core.security import verify_password
    from backend.database.init_db import init_db
    from backend.database.session import SessionLocal
    from backend.models import User

    init_db()
    username = username or input("Administrator username: ").strip()
    password = password if password is not None else getpass.getpass("Password: ")
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))
        return bool(user and user.is_active and is_admin(user) and verify_password(password, user.password_hash))


def set_web_access(enabled: bool, username: str | None = None, password: str | None = None) -> int:
    from backend.core.access import write_app_settings

    if not _admin_check(username, password):
        print("Only an active NetGuard administrator can change web access. Nothing was changed.")
        return 2
    write_app_settings(web_access=enabled)
    if enabled:
        print(f"Web access enabled. While NetGuard runs, open http://127.0.0.1:{DEFAULT_PORT} in a browser on this computer.")
    else:
        print("Web access disabled. Only the NetGuard desktop window can use the service.")
    return 0


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return sock.connect_ex(("127.0.0.1", port)) != 0


def _start_server(port: int):
    import uvicorn

    from backend.main import app

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False,
                            use_colors=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            return server, thread
        time.sleep(0.05)
    _tell("The NetGuard service did not start. Details are in data\\netguard.log.")
    raise SystemExit(1)


def run_desktop(port: int) -> int:
    key = secrets.token_urlsafe(32)
    os.environ["NETGUARD_DESKTOP_KEY"] = key  # read once by the settings, before the app is imported
    if not _port_free(port):
        port = next(p for p in range(port + 1, port + 50) if _port_free(p))
    server, thread = _start_server(port)
    url = f"http://127.0.0.1:{port}/desktop-session?key={key}"
    try:
        import webview
    except ImportError:
        _tell("The desktop window needs pywebview (pip install pywebview).")
        server.should_exit = True
        return 1
    from backend.core.config import DATA_DIR

    webview.settings["ALLOW_DOWNLOADS"] = True
    # Device management portals almost always present self-signed certificates. NetGuard shows each portal's
    # certificate SHA-256 fingerprint before opening it, so the operator can verify the device it connects to.
    webview.settings["IGNORE_SSL_ERRORS"] = True

    class DesktopApi:
        """Called from the NetGuard pages (window.pywebview.api) to open device web GUIs in their own windows."""

        def open_portal(self, target: str, title: str = "Device web management") -> bool:
            from urllib.parse import urlsplit

            parts = urlsplit(str(target))
            if parts.scheme not in ("http", "https") or not parts.hostname:
                return False
            try:
                webview.create_window(str(title)[:80] or "Device web management", target, width=1280, height=860)
                return True
            except Exception:  # noqa: BLE001 - no second window on this GUI backend: use the default browser
                import webbrowser

                return bool(webbrowser.open(target))

        def open_external(self, target: str) -> bool:
            import webbrowser
            from urllib.parse import urlsplit

            if urlsplit(str(target)).scheme not in ("http", "https"):
                return False
            return webbrowser.open(target)

    webview.create_window("NetGuard", url, width=1440, height=900, min_size=(1100, 700), js_api=DesktopApi())
    try:
        webview.start(private_mode=False, storage_path=str(DATA_DIR / "webview"))
    except Exception as exc:  # noqa: BLE001 - no GUI backend (for example Microsoft Edge WebView2 missing)
        _tell(f"The desktop window could not open ({exc}). Install the Microsoft Edge WebView2 Runtime "
              "(free from Microsoft), then start NetGuard again.")
        return 1
    finally:
        server.should_exit = True
        thread.join(timeout=5)
    return 0


def run_server(port: int) -> int:
    from backend.core.access import web_access_enabled

    os.environ.setdefault("NETGUARD_DESKTOP_KEY", secrets.token_urlsafe(32))
    if not web_access_enabled():
        print("Web access is disabled. Run 'NetGuard --enable-web-access' as an administrator first.")
        return 2
    server, thread = _start_server(port)
    print(f"NetGuard is running at http://127.0.0.1:{port} (Ctrl+C stops it).")
    try:
        while thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        server.should_exit = True
    return 0


def reset_admin() -> int:
    """Forgotten password: put the built-in admin account back to admin / admin, re-enable it and sign it out
    everywhere. No other account is changed."""
    from sqlalchemy import select

    from backend.core.security import hash_password
    from backend.database.init_db import init_db
    from backend.database.session import SessionLocal
    from backend.models import User

    init_db()  # creates the database and the admin account if they do not exist yet
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
        if user is None:
            print("There is no account named admin; nothing was changed.")
            return 1
        user.password_hash = hash_password("admin")
        user.is_active = True
        user.token_version = (user.token_version or 0) + 1  # old sessions stop working
        db.commit()
    print("The admin account is now admin / admin.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="NetGuard", description="NetGuard desktop application")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--enable-web-access", action="store_true", help="allow a local browser to use NetGuard")
    group.add_argument("--disable-web-access", action="store_true", help="allow only the desktop window")
    group.add_argument("--server", action="store_true", help="run the local service without a window")
    group.add_argument("--reset-admin", action="store_true", help="set the admin account back to admin / admin")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--user", help="administrator username (web access commands)")
    parser.add_argument("--password", help="administrator password (prompted when omitted)")
    args = parser.parse_args(argv)
    if args.enable_web_access or args.disable_web_access:
        return set_web_access(args.enable_web_access, args.user, args.password)
    if args.reset_admin:
        return reset_admin()
    if args.server:
        return run_server(args.port)
    return run_desktop(args.port)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001 - NetGuard.exe has no console: log the error and say where it is
        import traceback

        traceback.print_exc()
        if not WINDOWED:
            raise
        _tell("NetGuard stopped because of an unexpected error. Details are in data\\netguard.log.")
        sys.exit(1)
