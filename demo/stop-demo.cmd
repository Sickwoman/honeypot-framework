@echo off
title Honeypot stop demo
wsl -d Ubuntu-24.04 -u root --cd "%~dp0.." -- bash demo/stop-demo.sh
pause
