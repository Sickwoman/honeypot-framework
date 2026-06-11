# OpenCanary Multi-Service Honeypot

## Status
Running - replaces Dionaea (incompatible with Python 3.13)

## Active Services
- FTP port 21
- HTTP port 80
- MySQL port 3306
- SSH port 2223
- Telnet port 23
- Port scan detection

## Log location
/var/tmp/opencanary.log

## Start/Stop
opencanaryd --start
opencanaryd --stop
opencanaryd --status
