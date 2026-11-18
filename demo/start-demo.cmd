@echo off
title Honeypot start demo
wsl -d Ubuntu-24.04 -u root --cd "%~dp0.." -- bash demo/start-demo.sh
pause
