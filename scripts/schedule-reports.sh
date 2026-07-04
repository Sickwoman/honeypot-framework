#!/bin/bash
case "$1" in
  daily)
    python3 scripts/generate-pdf-report.py --days 1 --output honeypot-reports/daily-$(date +%Y-%m-%d).pdf
    ;;
  *)
    echo "Usage: $0 daily|weekly|monthly"
    ;;
esac
