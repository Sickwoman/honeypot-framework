#!/bin/bash
BACKUP_DIR="/home/moksh/honeypot-backups"
mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/honeypot-backup-$(date +%Y%m%d_%H%M%S).tar.gz \
  /home/cowrie/cowrie/etc/ \
  /etc/opencanaryd/ \
  /home/moksh/Desktop/honeypot-framework/docs/ 2>/dev/null || true
echo "Backup created"
