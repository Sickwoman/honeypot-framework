#!/bin/bash

################################################################################
# Honeypot Framework Deployment Script
# Starts all honeypot services: Cowrie, OpenCanary, and ELK Stack
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
  echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
  echo -e "${GREEN}[✓]${NC} $1"
}

log_warn() {
  echo -e "${YELLOW}[⚠]${NC} $1"
}

log_error() {
  echo -e "${RED}[✗]${NC} $1"
}

# Check if running as root
check_root() {
  if [[ $EUID -ne 0 ]]; then
    log_warn "This script should be run with sudo for some operations"
  fi
}

# Start Cowrie SSH honeypot
start_cowrie() {
  log_info "Starting Cowrie SSH honeypot..."
  
  if [ ! -d "/home/cowrie/cowrie" ]; then
    log_error "Cowrie not installed at /home/cowrie/cowrie"
    return 1
  fi
  
  cd /home/cowrie/cowrie
  
  # Check if already running
  if pgrep -f "cowrie" > /dev/null; then
    log_warn "Cowrie already running"
    return 0
  fi
  
  # Activate venv and start
  source cowrie-env/bin/activate
  ./bin/cowrie start
  
  sleep 2
  if pgrep -f "cowrie" > /dev/null; then
    log_success "Cowrie started on port 2222"
    return 0
  else
    log_error "Failed to start Cowrie"
    return 1
  fi
}

# Start OpenCanary multi-service honeypot
start_opencanary() {
  log_info "Starting OpenCanary multi-service honeypot..."
  
  # Check if already running
  if pgrep -f "opencanaryd" > /dev/null; then
    log_warn "OpenCanary already running"
    return 0
  fi
  
  opencanaryd --start
  
  sleep 2
  if pgrep -f "opencanaryd" > /dev/null; then
    log_success "OpenCanary started (FTP:21, HTTP:80, MySQL:3306, SSH:2223, Telnet:23)"
    return 0
  else
    log_error "Failed to start OpenCanary"
    return 1
  fi
}

# Start ELK Stack (Docker)
start_elk_stack() {
  log_info "Starting ELK Stack (Elasticsearch, Logstash, Kibana)..."
  
  if [ ! -d "$HOME/elk-stack" ]; then
    log_error "ELK Stack directory not found at $HOME/elk-stack"
    return 1
  fi
  
  cd $HOME/elk-stack
  
  # Check if Docker is installed
  if ! command -v docker-compose &> /dev/null; then
    log_error "Docker Compose not installed"
    return 1
  fi
  
  # Check if containers already running
  if docker-compose ps | grep -q "Up"; then
    log_warn "ELK Stack containers already running"
    return 0
  fi
  
  docker-compose up -d
  
  sleep 10
  
  # Verify containers
  if docker-compose ps | grep -q "elasticsearch.*Up"; then
    log_success "ELK Stack started"
    log_info "  • Elasticsearch: http://localhost:9200"
    log_info "  • Kibana: http://localhost:5601"
    log_info "  • Logstash: port 5000"
    return 0
  else
    log_error "Failed to start ELK Stack"
    return 1
  fi
}

# Display honeypot dashboard
show_dashboard() {
  log_info "Fetching attack summary..."
  
  if [ -f "$HOME/elk-stack/honeypot_dashboard.py" ]; then
    python3 $HOME/elk-stack/honeypot_dashboard.py
  else
    log_warn "Dashboard script not found"
  fi
}

# Main deployment flow
main() {
  echo ""
  echo "╔════════════════════════════════════════════════════════════════╗"
  echo "║  🍯 HONEYPOT FRAMEWORK DEPLOYMENT SCRIPT                       ║"
  echo "║  Phase 1: Local Lab (Cowrie + OpenCanary + ELK)               ║"
  echo "╚════════════════════════════════════════════════════════════════╝"
  echo ""
  
  check_root
  
  # Track deployment status
  COWRIE_OK=false
  OPENCANARY_OK=false
  ELK_OK=false
  
  # Start services
  log_info "========== DEPLOYMENT STARTED =========="
  echo ""
  
  if start_cowrie; then
    COWRIE_OK=true
  fi
  
  echo ""
  
  if start_opencanary; then
    OPENCANARY_OK=true
  fi
  
  echo ""
  
  if start_elk_stack; then
    ELK_OK=true
  fi
  
  # Summary
  echo ""
  echo "╔════════════════════════════════════════════════════════════════╗"
  echo "║  📊 DEPLOYMENT SUMMARY                                        ║"
  echo "╚════════════════════════════════════════════════════════════════╝"
  echo ""
  
  if [ "$COWRIE_OK" = true ]; then
    log_success "Cowrie SSH honeypot"
  else
    log_error "Cowrie SSH honeypot"
  fi
  
  if [ "$OPENCANARY_OK" = true ]; then
    log_success "OpenCanary multi-service"
  else
    log_error "OpenCanary multi-service"
  fi
  
  if [ "$ELK_OK" = true ]; then
    log_success "ELK Stack (Elasticsearch, Logstash, Kibana)"
  else
    log_error "ELK Stack"
  fi
  
  echo ""
  
  # Display dashboard
  show_dashboard
  
  echo ""
  echo "For detailed logs:"
  echo "  • Cowrie: tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.log"
  echo "  • OpenCanary: tail -f /var/tmp/opencanary.log"
  echo "  • ELK: cd ~/elk-stack && docker-compose logs -f"
  echo ""
}

# Run main function
main "$@"
