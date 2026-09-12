@echo off
rem swe2-jailbreak-proxy - Windows launcher
rem Set JB_SWE_HOST / JB_SWE_PORT below to bind somewhere else.
setlocal

set JB_SWE_HOST=127.0.0.1
set JB_SWE_PORT=8889
rem set JB_SWE_SYSTEM_FILE=%~dp0prompts\override-compact.txt
rem set JB_SWE_CRED=%APPDATA%\devin\credentials.toml

cd /d %~dp0
python swe2_jb_proxy.py %*
