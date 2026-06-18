#!/bin/bash

################################################################################
# Honeypot Attack Simulator
# Generates realistic attack traffic for testing honeypot capture
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  🎯 HONEYPOT ATTACK SIMULATOR                                 ║"
echo "║  Generates test traffic for honeypot validation               ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Configuration
COWRIE_HOST="localhost"
COWRIE_PORT="2222"
OPENCANARY_HOST="localhost"

# Test functions
test_cowrie_ssh() {
  echo -e "${YELLOW}[TEST 1/5]${NC} Cowrie SSH Honeypot (Port 2222)"
  
  # Attempt multiple login failures
  for i in {1..5}; do
    echo -e "  Attempt $i: Testing SSH connection..."
    sshpass -p "wrongpassword$i" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
      root@$COWRIE_HOST -p $COWRIE_PORT "whoami" 2>/dev/null || true
    sleep 1
  done
  
  echo -e "${GREEN}  ✓ Cowrie SSH tests complete${NC}"
}

test_opencanary_ftp() {
  echo -e "${YELLOW}[TEST 2/5]${NC} OpenCanary FTP (Port 21)"
  
  (echo "open $OPENCANARY_HOST 21"; 
   sleep 1
   echo "admin"; 
   sleep 1
   echo "admin123"; 
   sleep 1
   echo "quit") | nc -w 2 $OPENCANARY_HOST 21 2>/dev/null || true
  
  echo -e "${GREEN}  ✓ FTP tests complete${NC}"
}

test_opencanary_http() {
  echo -e "${YELLOW}[TEST 3/5]${NC} OpenCanary HTTP (Port 80)"
  
  # Simulate various HTTP requests
  curl -s -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
    http://$OPENCANARY_HOST:80/ > /dev/null 2>&1 || true
  
  curl -s http://$OPENCANARY_HOST:80/admin 2>/dev/null || true
  curl -s http://$OPENCANARY_HOST:80/config.php 2>/dev/null || true
  curl -s http://$OPENCANARY_HOST:80/.env 2>/dev/null || true
  
  echo -e "${GREEN}  ✓ HTTP tests complete${NC}"
}

test_opencanary_mysql() {
  echo -e "${YELLOW}[TEST 4/5]${NC} OpenCanary MySQL (Port 3306)"
  
  # Test MySQL connection
  (echo -e "SELECT 1;" | timeout 2 nc -w 2 $OPENCANARY_HOST 3306) 2>/dev/null || true
  
  echo -e "${GREEN}  ✓ MySQL tests complete${NC}"
}

test_opencanary_telnet() {
  echo -e "${YELLOW}[TEST 5/5]${NC} OpenCanary Telnet (Port 23)"
  
  # Test Telnet connection
  (echo "root"; sleep 1; echo "password"; sleep 1; echo "quit") | \
    timeout 3 nc -w 2 $OPENCANARY_HOST 23 2>/dev/null || true
  
  echo -e "${GREEN}  ✓ Telnet tests complete${NC}"
}

check_dependencies() {
  echo "Checking dependencies..."
  
  command -v curl >/dev/null 2>&1 || { echo "❌ curl required"; exit 1; }
  command -v nc >/dev/null 2>&1 || { echo "❌ netcat required"; exit 1; }
  command -v ssh >/dev/null 2>&1 || { echo "❌ openssh-client required"; exit 1; }
  
  if ! command -v sshpass >/dev/null 2>&1; then
    echo "⚠️  sshpass not found. Installing..."
    sudo apt install -y sshpass > /dev/null 2>&1 || true
  fi
  
  echo "✅ Dependencies OK"
}

main() {
  echo ""
  check_dependencies
  echo ""
  
  echo "Starting attack simulations..."
  echo ""
  
  test_cowrie_ssh
  echo ""
  test_opencanary_ftp
  echo ""
  test_opencanary_http
  echo ""
  test_opencanary_mysql
  echo ""
  test_opencanary_telnet
  echo ""
  
  echo "╔════════════════════════════════════════════════════════════════╗"
  echo "║  ✅ ALL TESTS COMPLETE                                        ║"
  echo "╚════════════════════════════════════════════════════════════════╝"
  echo ""
  echo "Next: Check honeypot logs"
  echo "  Cowrie: cat /home/cowrie/cowrie/var/log/cowrie/cowrie.log"
  echo "  OpenCanary: cat /var/tmp/opencanary.log"
  echo "  Dashboard: python3 ~/Desktop/honeypot-framework/scripts/check-services.sh"
  echo ""
}

main "$@"
