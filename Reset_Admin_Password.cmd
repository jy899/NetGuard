@echo off
cd /d "%~dp0"
echo NetGuard - reset the admin password
echo.
if not exist ".venv\Scripts\python.exe" (
  echo NetGuard is not set up yet. Run Start_NetGuard.cmd once first.
  pause
  exit /b 1
)
echo This sets the "admin" account back to: admin / admin
set /p answer=Type YES to continue: 
if /i not "%answer%"=="YES" (
  echo Cancelled. Nothing was changed.
  pause
  exit /b 0
)
".venv\Scripts\python.exe" netguard.py --reset-admin
if errorlevel 1 (
  echo The password could not be reset. See the message above.
) else (
  echo Done. Sign in with admin / admin.
)
pause
