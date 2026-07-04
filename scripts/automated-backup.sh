#!/bin/bash

################################################################################
# Automated Backup Script
# Schedules and manages honeypot backups with rotation
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
BACKUP_DIR="/home/moksh/honeypot-backups"
BACKUP_RETENTION_DAYS=30
LOG_FILE="/var/log/honeypot-backup.log"
MAX_BACKUPS=10

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  💾 AUTOMATED BACKUP MANAGER                                  ║"
echo "║  Manages scheduled backups with rotation and cleanup          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Create log file
mkdir -p $(dirname $LOG_FILE)
touch $LOG_FILE

log_message() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> $LOG_FILE
}

# Function to create backup
create_backup() {
  echo -e "${YELLOW}Creating backup...${NC}"
  log_message "Starting backup creation"
  
  BACKUP_FILE="$BACKUP_DIR/honeypot-backup-$(date +%Y%m%d_%H%M%S).tar.gz"
  
  # Create backup directory
  mkdir -p $BACKUP_DIR
  
  # Backup Cowrie
  tar -czf /tmp/cowrie-backup.tar.gz \
    /home/cowrie/cowrie/etc/cowrie.cfg \
    /home/cowrie/cowrie/var/log/cowrie/ 2>/dev/null || true
  
  # Backup OpenCanary
  tar -czf /tmp/opencanary-backup.tar.gz \
    /etc/opencanaryd/opencanary.conf \
    /var/tmp/opencanary.log 2>/dev/null || true
  
  # Backup ELK Stack
  tar -czf /tmp/elk-backup.tar.gz \
    /root/elk-stack/docker-compose.yml \
    /root/elk-stack/logstash.conf 2>/dev/null || true
  
  # Backup Elasticsearch indices
  curl -s -u elastic:changeme -k \
    https://localhost:9200/_snapshot/backup \
    -X PUT 2>/dev/null || true
  
  # Create master backup
  tar -czf $BACKUP_FILE \
    /tmp/cowrie-backup.tar.gz \
    /tmp/opencanary-backup.tar.gz \
    /tmp/elk-backup.tar.gz \
    /home/moksh/Desktop/honeypot-framework/docs/ \
    /etc/systemd/system/honeypot* \
    /etc/logrotate.d/honeypot 2>/dev/null || true
  
  # Cleanup temp files
  rm -f /tmp/*-backup.tar.gz 2>/dev/null || true
  
  if [ -f "$BACKUP_FILE" ]; then
    SIZE=$(du -h $BACKUP_FILE | cut -f1)
    echo -e "${GREEN}✓ Backup created: $BACKUP_FILE ($SIZE)${NC}"
    log_message "Backup created successfully: $BACKUP_FILE ($SIZE)"
    return 0
  else
    echo -e "${RED}✗ Backup creation failed${NC}"
    log_message "Backup creation failed"
    return 1
  fi
}

# Function to cleanup old backups
cleanup_old_backups() {
  echo -e "${YELLOW}Cleaning up old backups...${NC}"
  
  # Delete backups older than retention period
  find $BACKUP_DIR -name "honeypot-backup-*.tar.gz" -mtime +$BACKUP_RETENTION_DAYS -delete
  
  # Keep only latest MAX_BACKUPS
  ls -t $BACKUP_DIR/honeypot-backup-*.tar.gz 2>/dev/null | tail -n +$((MAX_BACKUPS+1)) | xargs -r rm
  
  REMAINING=$(ls -1 $BACKUP_DIR/honeypot-backup-*.tar.gz 2>/dev/null | wc -l)
  echo -e "${GREEN}✓ Cleanup complete. Remaining backups: $REMAINING${NC}"
  log_message "Cleanup complete. Remaining backups: $REMAINING"
}

# Function to verify backup integrity
verify_backup() {
  local BACKUP_FILE=$1
  
  echo -e "${YELLOW}Verifying backup integrity...${NC}"
  
  if tar -tzf $BACKUP_FILE > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Backup integrity verified${NC}"
    log_message "Backup integrity verified: $BACKUP_FILE"
    return 0
  else
    echo -e "${RED}✗ Backup integrity check failed${NC}"
    log_message "Backup integrity check failed: $BACKUP_FILE"
    return 1
  fi
}

# Function to show backup status
backup_status() {
  echo -e "${YELLOW}Backup Status:${NC}"
  echo ""
  
  if [ ! -d "$BACKUP_DIR" ]; then
    echo "No backups found"
    return
  fi
  
  echo "Backup Directory: $BACKUP_DIR"
  echo "Retention Period: $BACKUP_RETENTION_DAYS days"
  echo "Max Backups: $MAX_BACKUPS"
  echo ""
  echo "Recent Backups:"
  ls -lh $BACKUP_DIR/honeypot-backup-*.tar.gz 2>/dev/null | tail -5 | awk '{print $9, "(" $5 ")"}'
  echo ""
  
  TOTAL_SIZE=$(du -sh $BACKUP_DIR 2>/dev/null | cut -f1)
  echo "Total backup size: $TOTAL_SIZE"
}

# Function to restore backup
restore_backup() {
  local BACKUP_FILE=$1
  
  if [ ! -f "$BACKUP_FILE" ]; then
    echo -e "${RED}Error: Backup file not found: $BACKUP_FILE${NC}"
    return 1
  fi
  
  echo -e "${YELLOW}⚠️  WARNING: This will restore from backup${NC}"
  echo "Backup: $BACKUP_FILE"
  read -p "Continue? (yes/no): " CONFIRM
  
  if [ "$CONFIRM" != "yes" ]; then
    echo "Restore cancelled"
    return 0
  fi
  
  echo -e "${YELLOW}Restoring backup...${NC}"
  tar -xzf $BACKUP_FILE -C / 2>/dev/null || true
  
  echo -e "${GREEN}✓ Restore complete${NC}"
  echo "Run: sudo systemctl restart cowrie opencanary elk-stack"
  log_message "Backup restored: $BACKUP_FILE"
}

# Menu
case "${1:-backup}" in
  backup)
    create_backup && verify_backup "$BACKUP_FILE" && cleanup_old_backups
    ;;
  status)
    backup_status
    ;;
  cleanup)
    cleanup_old_backups
    ;;
  restore)
    if [ -z "$2" ]; then
      echo "Usage: $0 restore <backup-file>"
      ls -lh $BACKUP_DIR/honeypot-backup-*.tar.gz 2>/dev/null | tail -10
      exit 1
    fi
    restore_backup "$2"
    ;;
  logs)
    tail -20 $LOG_FILE
    ;;
  *)
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 backup      - Create backup"
    echo "  $0 status      - Show backup status"
    echo "  $0 cleanup     - Cleanup old backups"
    echo "  $0 restore <file> - Restore from backup"
    echo "  $0 logs        - Show backup logs"
    ;;
esac

