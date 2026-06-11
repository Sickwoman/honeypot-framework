# Cowrie SSH Honeypot

## Status
Running on port 2222

## What it captures
- All login attempts and credentials
- Every command executed in fake shell
- File download attempts
- Full TTY session recordings

## Log location
/home/cowrie/cowrie/var/log/cowrie/cowrie.log

## Start/Stop
cowrie start
cowrie stop
cowrie status

## Key findings so far
- Fake hostname: webserver01
- Accepted services: SSH on port 2222
