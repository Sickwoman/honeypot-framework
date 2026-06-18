#!/bin/bash

################################################################################
# Honeypot Backup Script
# Backs up all honeypot data, configs, and logs
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
BACKUP_DIR="/home/moksh/honeypot-backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/honeypot-backup-$TIMESTAMP.tar.gz"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  💾 HONEYPOT BACKUP SCRIPT                                    ║"
echo "║  Backing up all honeypot data and configurations              ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Create backup directory
mkdir -p $BACKUP_DIR

echo -e "${YELLOW}[1/5]${NC} Backing up Cowrie data..."
tar -czf /tmp/cowrie-backup-$TIMESTAMP.tar.gz \
  /home/cowrie/cowrie/etc/cowrie.cfg \
  /home/cowrie/cowrie/var/log/cowrie/ \
  2>/dev/null || true

echo -e "${YELLOW}[2/5]${NC} Backing up OpenCanary data..."
tar -czf /tmp/opencanary-backup-$TIMESTAMP.tar.gz \
  /etc/opencanaryd/opencanary.conf \
  /var/tmp/opencanary.log \
  2>/dev/null || true

echo -e "${YELLOW}[3/5]${NC} Backing up ELK Stack configuration..."
tar -czf /tmp/elk-backup-$TIMESTAMP.tar.gz \
  /root/elk-stack/docker-compose.yml \
  /root/elk-stack/logstash.conf \
  2>/dev/null || true

echo -e "${YELLOW}[4/5]${NC} Backing up Terraform configuration..."
tar -czf /tmp/terraform-backup-$TIMESTAMP.tar.gz \
  /home/moksh/Desktop/honeypot-framework/terraform/ \
  2>/dev/null || true

echo -e "${YELLOW}[5/5]${NC} Creating master backup archive..."
tar -czf $BACKUP_FILE \
  /tmp/cowrie-backup-$TIMESTAMP.tar.gz \
  /tmp/opencanary-backup-$TIMESTAMP.tar.gz \
  /tmp/elk-backup-$TIMESTAMP.tar.gz \
  /tmp/terraform-backup-$TIMESTAMP.tar.gz \
  /home/moksh/Desktop/honeypot-framework/docs/ \
  /etc/systemd/system/honeypot* \
  /etc/logrotate.d/honeypot \
  2>/dev/null || true

# Cleanup temporary backups
rm -f /tmp/*-backup-$TIMESTAMP.tar.gz

# Calculate backup size
BACKUP_SIZE=$(du -h $BACKUP_FILE | cut -f1)

echo ""
echo -e "${GREEN}✓ Backup Complete${NC}"
echo ""
echo "📊 Backup Summary:"
echo "   Location: $BACKUP_FILE"
echo "   Size: $BACKUP_SIZE"
echo "   Timestamp: $TIMESTAMP"
echo ""
echo "📋 What was backed up:"
echo "   • Cowrie SSH honeypot config and logs"
echo "   • OpenCanary multi-service config and logs"
echo "   • ELK Stack Docker configurations"
echo "   • Terraform infrastructure code"
echo "   • Documentation"
echo "   • Systemd service files"
echo ""
echo "🔒 Backup Tips:"
echo "   • Store in secure location"
echo "   • Keep off-site copy (cloud storage)"
echo "   • Test restore regularly"
echo ""
