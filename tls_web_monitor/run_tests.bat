@echo off
cd /d "%~dp0"
echo ==============================================================================
echo   Running Automated Pytest Suite (Module 1, 2, 3 Verification)
echo ==============================================================================
..\venv\Scripts\python.exe -m pytest tests -v
pause

