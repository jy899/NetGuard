# PyInstaller build of the NetGuard Windows desktop application.
#   Build_NetGuard_App.cmd   (or: .venv\Scripts\python -m PyInstaller --noconfirm netguard.spec)
# Output: dist\NetGuard\NetGuard.exe (desktop window) and NetGuardCmd.exe (console: --enable-web-access, --server).
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = [("frontend", "frontend"), ("data/models", "data/models"), ("data/datasets", "data/datasets")]  # AI models and training data
for package in ("ntc_templates", "netaddr", "reportlab", "webview"):
    datas += collect_data_files(package)
datas += collect_data_files("pysnmp", include_py_files=True)  # MIB modules are loaded from files at run time
hiddenimports = [m for m in collect_submodules("backend") if not m.startswith("backend.tests")]  # tests stay out
for package in ("uvicorn", "netmiko", "pysnmp", "pyasn1", "paramiko", "textfsm", "sqlalchemy.dialects.sqlite", "psutil"):
    hiddenimports += collect_submodules(package)

a = Analysis(["netguard.py"], datas=datas, hiddenimports=hiddenimports, excludes=["tkinter", "pytest", "playwright", "PyInstaller", "backend.tests"])
pyz = PYZ(a.pure)
desktop = EXE(pyz, a.scripts, [], exclude_binaries=True, name="NetGuard", console=False)
console = EXE(pyz, a.scripts, [], exclude_binaries=True, name="NetGuardCmd", console=True)
coll = COLLECT(desktop, console, a.binaries, a.datas, name="NetGuard")
