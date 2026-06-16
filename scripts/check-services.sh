#!/bin/bash

################################################################################
# Honeypot Services Health Check Script
# Monitors Cowrie, OpenCanary, and ELK Stack status
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  🍯 HONEYPOT SERVICES HEALTH CHECK                            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

check_service() {
  local service=$1
  local name=$2
  
  if systemctl is-active --quiet $service; then
    echo -e "${GREEN}✓${NC} $name is running"
    systemctl status $service --no-pager | grep "Active:" | sed 's/^/  /'
  else
    echo -e "${RED}✗${NC} $name is NOT running"
    systemctl status $service --no-pager | grep "Active:" | sed 's/^/  /'
  fi
}

echo "SERVICE STATUS:"
echo "───────────────────────────────────────────────────────────────"
check_service "cowrie.service" "Cowrie SSH Honeypot"
echo ""
check_service "opencanary.service" "OpenCanary Multi-Service"
echo ""
check_service "elk-stack.service" "ELK Stack (Docker)"

echo ""
echo "PORT AVAILABILITY:"
echo "───────────────────────────────────────────────────────────────"

check_port() {
  local port=$1
  local service=$2
  
  if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
    echo -e "${GREEN}✓${NC} $service (port $port) is listening"
  else
    echo -e "${YELLOW}⚠${NC} $service (port $port) is NOT listening"
  fi
}

check_port 2222 "Cowrie SSH"
check_port 21 "OpenCanary FTP"
check_port 80 "OpenCanary HTTP"
check_port 3306 "OpenCanary MySQL"
check_port 2223 "OpenCanary SSH"
check_port 23 "OpenCanary Telnet"
check_port 9200 "Elasticsearch"
check_port 5601 "Kibana"

echo ""
echo "RECENT LOGS:"
echo "───────────────────────────────────────────────────────────────"
echo "Cowrie (last 3 entries):"
sudo journalctl -u cowrie.service -n 3 --no-pager | sed 's/^/  /'

echo ""
echo "OpenCanary (last 3 entries):"
sudo journalctl -u opencanary.service -n 3 --no-pager | sed 's/^/  /'

echo ""
echo "ELK Stack (last 3 entries):"
sudo journalctl -u elk-stack.service -n 3 --no-pager | sed 's/^/  /'

echo ""
echo "QUICK STATS:"
echo "───────────────────────────────────────────────────────────────"
echo "Cowrie log size: $(du -sh /home/cowrie/cowrie/var/log/cowrie/ 2>/dev/null || echo 'N/A')"
echo "OpenCanary log size: $(du -sh /var/tmp/opencanary.log 2>/dev/null || echo 'N/A')"
echo "Uptime: $(uptime -p)"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  End of Health Check                                          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
