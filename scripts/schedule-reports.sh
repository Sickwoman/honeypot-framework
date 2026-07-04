#!/bin/bash

################################################################################
# Automated Report Scheduler
# Schedules daily, weekly, and monthly reports
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

REPORT_DIR="/home/moksh/honeypot-reports"
SCRIPTS_DIR="~/Desktop/honeypot-framework/scripts"
LOG_FILE="/var/log/honeypot-reports.log"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  📅 REPORT SCHEDULER                                          ║"
echo "║  Manages automated report generation and distribution         ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Create directories
mkdir -p $REPORT_DIR/daily $REPORT_DIR/weekly $REPORT_DIR/monthly
mkdir -p $(dirname $LOG_FILE)
touch $LOG_FILE

log_message() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> $LOG_FILE
}

# Function to generate daily report
generate_daily_report() {
  echo -e "${YELLOW}Generating daily report...${NC}"
  log_message "Starting daily report generation"
  
  REPORT_FILE="$REPORT_DIR/daily/report-$(date +%Y-%m-%d).pdf"
  
  python3 $SCRIPTS_DIR/generate-pdf-report.py \
    --days 1 \
    --output $REPORT_FILE
  
  if [ -f "$REPORT_FILE" ]; then
    SIZE=$(du -h $REPORT_FILE | cut -f1)
    echo -e "${GREEN}✓ Daily report created: $REPORT_FILE ($SIZE)${NC}"
    log_message "Daily report created: $REPORT_FILE ($SIZE)"
    return 0
  else
    echo -e "${RED}✗ Daily report creation failed${NC}"
    log_message "Daily report creation failed"
    return 1
  fi
}

# Function to generate weekly report
generate_weekly_report() {
  echo -e "${YELLOW}Generating weekly report...${NC}"
  log_message "Starting weekly report generation"
  
  WEEK=$(date +%Y-W%V)
  REPORT_FILE="$REPORT_DIR/weekly/report-$WEEK.pdf"
  
  python3 $SCRIPTS_DIR/generate-pdf-report.py \
    --days 7 \
    --output $REPORT_FILE
  
  if [ -f "$REPORT_FILE" ]; then
    SIZE=$(du -h $REPORT_FILE | cut -f1)
    echo -e "${GREEN}✓ Weekly report created: $REPORT_FILE ($SIZE)${NC}"
    log_message "Weekly report created: $REPORT_FILE ($SIZE)"
    return 0
  else
    echo -e "${RED}✗ Weekly report creation failed${NC}"
    log_message "Weekly report creation failed"
    return 1
  fi
}

# Function to generate monthly report
generate_monthly_report() {
  echo -e "${YELLOW}Generating monthly report...${NC}"
  log_message "Starting monthly report generation"
  
  MONTH=$(date +%Y-%m)
  REPORT_FILE="$REPORT_DIR/monthly/report-$MONTH.pdf"
  
  python3 $SCRIPTS_DIR/generate-pdf-report.py \
    --days 30 \
    --output $REPORT_FILE
  
  if [ -f "$REPORT_FILE" ]; then
    SIZE=$(du -h $REPORT_FILE | cut -f1)
    echo -e "${GREEN}✓ Monthly report created: $REPORT_FILE ($SIZE)${NC}"
    log_message "Monthly report created: $REPORT_FILE ($SIZE)"
    return 0
  else
    echo -e "${RED}✗ Monthly report creation failed${NC}"
    log_message "Monthly report creation failed"
    return 1
  fi
}

# Function to setup cron jobs
setup_cron_jobs() {
  echo -e "${YELLOW}Setting up cron jobs...${NC}"
  
  CRON_JOBS=$(cat <<'CRON'
# Honeypot Backup Schedule
0 2 * * * /home/moksh/Desktop/honeypot-framework/scripts/automated-backup.sh backup >> /var/log/honeypot-backup.log 2>&1

# Daily Report - 9 AM
0 9 * * * /home/moksh/Desktop/honeypot-framework/scripts/schedule-reports.sh daily >> /var/log/honeypot-reports.log 2>&1

# Weekly Report - Monday 8 AM
0 8 * * 1 /home/moksh/Desktop/honeypot-framework/scripts/schedule-reports.sh weekly >> /var/log/honeypot-reports.log 2>&1

# Monthly Report - 1st day at 7 AM
0 7 1 * * /home/moksh/Desktop/honeypot-framework/scripts/schedule-reports.sh monthly >> /var/log/honeypot-reports.log 2>&1

# Health Check - Every hour
0 * * * * /home/moksh/Desktop/honeypot-framework/scripts/check-services.sh >> /var/log/honeypot-health.log 2>&1

# Cleanup old logs - Daily at 3 AM
0 3 * * * find /home/moksh/honeypot-reports -mtime +90 -delete
CRON

  echo "$CRON_JOBS"
  echo ""
  echo -e "${YELLOW}To install cron jobs:${NC}"
  echo "  crontab -e"
  echo "  # Then paste the above jobs"
  echo ""
  echo -e "${YELLOW}To verify installed jobs:${NC}"
  echo "  crontab -l"
}

# Function to show report status
report_status() {
  echo -e "${YELLOW}Report Status:${NC}"
  echo ""
  
  echo "Report Directory: $REPORT_DIR"
  echo ""
  
  echo "Daily Reports:"
  ls -lh $REPORT_DIR/daily/*.pdf 2>/dev/null | tail -5 | awk '{print "  " $9, "(" $5 ")"}' || echo "  None"
  
  echo ""
  echo "Weekly Reports:"
  ls -lh $REPORT_DIR/weekly/*.pdf 2>/dev/null | tail -5 | awk '{print "  " $9, "(" $5 ")"}' || echo "  None"
  
  echo ""
  echo "Monthly Reports:"
  ls -lh $REPORT_DIR/monthly/*.pdf 2>/dev/null | tail -5 | awk '{print "  " $9, "(" $5 ")"}' || echo "  None"
  
  echo ""
  TOTAL_SIZE=$(du -sh $REPORT_DIR 2>/dev/null | cut -f1)
  echo "Total reports size: $TOTAL_SIZE"
}

# Function to show logs
show_logs() {
  echo -e "${YELLOW}Recent Report Logs:${NC}"
  tail -20 $LOG_FILE
}

# Menu
case "${1:-help}" in
  daily)
    generate_daily_report
    ;;
  weekly)
    generate_weekly_report
    ;;
  monthly)
    generate_monthly_report
    ;;
  all)
    generate_daily_report
    echo ""
    generate_weekly_report
    echo ""
    generate_monthly_report
    ;;
  status)
    report_status
    ;;
  setup-cron)
    setup_cron_jobs
    ;;
  logs)
    show_logs
    ;;
  *)
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 daily         - Generate daily report"
    echo "  $0 weekly        - Generate weekly report"
    echo "  $0 monthly       - Generate monthly report"
    echo "  $0 all           - Generate all reports"
    echo "  $0 status        - Show report status"
    echo "  $0 setup-cron    - Display cron job setup"
    echo "  $0 logs          - Show report logs"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 daily"
    echo "  $0 status"
    echo "  $0 setup-cron | crontab"
    ;;
esac

