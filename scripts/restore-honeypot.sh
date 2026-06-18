#!/bin/bash

################################################################################
# Honeypot Restore Script
# Restores honeypot data from backup
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  🔄 HONEYPOT RESTORE SCRIPT                                   ║"
echo "║  Restores honeypot from backup archive                        ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ -z "$1" ]; then
  echo -e "${RED}Error: No backup file specified${NC}"
  echo "Usage: ./restore-honeypot.sh <backup-file>"
  echo ""
  echo "Available backups:"
  ls -lh /home/moksh/honeypot-backups/
  exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
  echo -e "${RED}Error: Backup file not found: $BACKUP_FILE${NC}"
  exit 1
fi

echo -e "${YELLOW}⚠️  WARNING${NC}"
echo "This will restore honeypot from backup."
echo "Current data will be overwritten."
echo ""
read -p "Continue? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
  echo "Restore cancelled"
  exit 0
fi

echo ""
echo -e "${YELLOW}[1/4]${NC} Extracting backup..."
tar -xzf $BACKUP_FILE -C /tmp/

echo -e "${YELLOW}[2/4]${NC} Restoring Cowrie..."
tar -xzf /tmp/cowrie-backup-*.tar.gz -C / 2>/dev/null || true

echo -e "${YELLOW}[3/4]${NC} Restoring OpenCanary..."
tar -xzf /tmp/opencanary-backup-*.tar.gz -C / 2>/dev/null || true

echo -e "${YELLOW}[4/4]${NC} Restoring ELK Stack..."
tar -xzf /tmp/elk-backup-*.tar.gz -C / 2>/dev/null || true

echo ""
echo -e "${GREEN}✓ Restore Complete${NC}"
echo ""
echo "📋 Next steps:"
echo "   1. sudo systemctl restart cowrie"
echo "   2. sudo systemctl restart opencanary"
echo "   3. sudo systemctl restart elk-stack"
echo "   4. Verify services: systemctl status cowrie opencanary elk-stack"
echo ""
