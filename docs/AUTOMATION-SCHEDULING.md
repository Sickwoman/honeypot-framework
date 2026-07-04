# Automation & Scheduling Guide

## Overview
Complete automation setup for backups, reports, monitoring, and maintenance tasks using cron jobs.

## 1. Setup Automated Backups

### Manual Backup
./scripts/automated-backup.sh backup

### Check Backup Status
./scripts/automated-backup.sh status

### Restore from Backup
./scripts/automated-backup.sh restore /path/to/backup.tar.gz

## 2. Install Cron Jobs

### Verify Installation
crontab -l

## 3. Backup Recovery

### List available backups
ls -lh /home/moksh/honeypot-backups/

### After restoration
sudo systemctl restart cowrie opencanary elk-stack
./scripts/check-services.sh

## Quick Reference Commands

crontab -l
crontab -e
./scripts/automated-backup.sh backup
./scripts/schedule-reports.sh all
tail -f /var/log/honeypot*.log
sudo systemctl restart cron

