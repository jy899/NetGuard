@echo off
setlocal
cd /d "%~dp0"
echo NetGuard - build the Windows app (NetGuard.exe)
echo.
if not exist ".venv\Scripts\python.exe" (
  echo Creating the Python environment...
  where py >nul 2>nul && (py -3 -m venv .venv) || (python -m venv .venv)
)
if not exist ".venv\Scripts\python.exe" (
  echo Python 3.11 or later is required. Install it from python.org and tick "Add python.exe to PATH".
  goto :fail
)
echo Installing packages. The first time needs an internet connection...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt || goto :fail
if /i "%~1"=="-RunTests" (
  echo Running the backend tests...
  ".venv\Scripts\python.exe" -m pytest backend/tests -q -p no:cacheprovider || goto :fail
)
echo Building NetGuard.exe. This takes a few minutes...
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean netguard.spec || goto :fail
if not exist "dist\NetGuard\data" mkdir "dist\NetGuard\data"
echo.
echo Done: dist\NetGuard\NetGuard.exe
echo Copy the whole dist\NetGuard folder to run NetGuard on another Windows PC. Sign in with admin / admin.
pause
exit /b 0

:fail
echo.
echo The build stopped. See the messages above.
pause
exit /b 1
