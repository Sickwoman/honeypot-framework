@echo off
title Honeypot attack demo
wsl -d Ubuntu-24.04 -u root --cd "%~dp0.." -- bash demo/attack-demo.sh
pause
