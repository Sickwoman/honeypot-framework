#!/bin/bash

################################################################################
# Compliance Setup Script
# Initializes compliance reporting infrastructure
################################################################################

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
COMPLIANCE_DIR="$PROJECT_ROOT/compliance_reports"
CONFIG_DIR="$PROJECT_ROOT/config"

echo "🔒 Honeypot Compliance Framework Setup"
echo "======================================"

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check prerequisites
echo -e "\n${YELLOW}[*] Checking prerequisites...${NC}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 is required${NC}"
    exit 1
fi

# Check pip
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}[!] pip3 is required${NC}"
    exit 1
fi

# Create compliance directories
echo -e "\n${YELLOW}[*] Creating compliance directories...${NC}"
mkdir -p "$COMPLIANCE_DIR"/{SOC2,PCI-DSS,HIPAA}
echo -e "${GREEN}[✓] Compliance directories created${NC}"

# Install Python dependencies
echo -e "\n${YELLOW}[*] Installing Python dependencies...${NC}"
pip3 install --quiet requests reportlab 2>/dev/null || {
    echo -e "${YELLOW}[*] Some packages already installed${NC}"
}
echo -e "${GREEN}[✓] Dependencies installed${NC}"

# Create compliance config file
echo -e "\n${YELLOW}[*] Creating compliance configuration...${NC}"

cat > "$CONFIG_DIR/compliance-config.yml" << 'EOF'
# Compliance Configuration

elasticsearch:
  # Credentials come from the environment (ELASTICSEARCH_USERNAME /
  # ELASTICSEARCH_PASSWORD) -- never store a password in this file.
  url: "${ELASTICSEARCH_URL:-https://localhost:9200}"
  username: "${ELASTICSEARCH_USERNAME:-elastic}"
  password: "${ELASTICSEARCH_PASSWORD}"
  verify_ssl: true
  timeout: 30

compliance_standards:
  - SOC2
  - PCI-DSS
  - HIPAA

reporting:
  output_formats:
    - json
    - csv
    - pdf
  retention_days: 2555  # 7 years
  output_directory: "compliance_reports"

compliance_checks:
  # SOC2 Controls
  soc2:
    - CC1  # Organization and Governance
    - CC2  # Communication
    - CC3  # Responsibility Assignment
    - CC4  # Competence
    - CC5  # Accountability
    - CC6  # Logical and Physical Access
    - CC7  # Change Management
    - CC8  # Detection and Prevention
    - CC9  # Remediation
    - A1   # Availability
    - A2   # Performance and Capacity
    - C1   # Confidentiality
    - I1   # System Integrity
    - P1   # Privacy Controls

  # PCI-DSS Requirements
  pci_dss:
    - REQ1   # Network Segmentation
    - REQ2   # Default Configuration
    - REQ3   # Data Protection
    - REQ4   # Encryption in Transit
    - REQ5   # Malware Protection
    - REQ6   # Secure Development
    - REQ7   # Access Restriction
    - REQ8   # User Identification
    - REQ9   # Physical Access
    - REQ10  # Logging and Monitoring
    - REQ11  # Regular Testing
    - REQ12  # Incident Response

  # HIPAA Controls
  hipaa:
    - 164.308(a)(1)  # Security Management Process
    - 164.308(a)(2)  # Assigned Security Responsibility
    - 164.308(a)(3)  # Workforce Security
    - 164.308(a)(4)  # Information Access Management
    - 164.308(a)(5)  # Security Awareness and Training
    - 164.308(a)(6)  # Security Incident Procedures
    - 164.308(a)(7)  # Contingency Planning
    - 164.308(a)(8)  # Evaluation
    - 164.310(a)     # Facility Access Controls
    - 164.310(b)     # Workstation Use
    - 164.310(c)     # Workstation Security
    - 164.310(d)     # Device and Media Controls
    - 164.312(a)(1)  # Access Control
    - 164.312(a)(2)  # Encryption and Decryption
    - 164.312(b)     # Audit Controls
    - 164.312(c)     # Integrity
    - 164.312(d)     # Transmission Security

evidence_retention:
  audit_logs: "6 years"
  incident_logs: "2 years"
  change_logs: "1 year"
  access_logs: "90 days"

alerts:
  enabled: true
  channels:
    - email
    - slack
  thresholds:
    critical_findings: 1
    high_findings: 5
    medium_findings: 10

audit_schedule:
  daily_compliance_check: "02:00"
  weekly_evidence_review: "Monday 09:00"
  monthly_audit_summary: "1st Monday 10:00"
  quarterly_full_assessment: "Q1,Q2,Q3,Q4"
  annual_external_audit: "Q4"
EOF

echo -e "${GREEN}[✓] Compliance configuration created${NC}"

# Create cron job for automated compliance reports
echo -e "\n${YELLOW}[*] Setting up automated compliance reports...${NC}"

CRON_CMD="0 2 * * * cd $PROJECT_ROOT && python3 scripts/compliance-reporter.py --standard ALL >> $COMPLIANCE_DIR/compliance.log 2>&1"

# Check if cron job already exists
if ! crontab -l 2>/dev/null | grep -q "compliance-reporter.py"; then
    (crontab -l 2>/dev/null; echo "$CRON_CMD") | crontab - 2>/dev/null || {
        echo -e "${YELLOW}[*] Note: Could not set up cron job automatically${NC}"
        echo -e "${YELLOW}[*] Add this line to your crontab to enable automated reports:${NC}"
        echo -e "${YELLOW}    $CRON_CMD${NC}"
    }
else
    echo -e "${GREEN}[✓] Cron job already configured${NC}"
fi

# Create compliance monitoring script
echo -e "\n${YELLOW}[*] Creating compliance monitoring script...${NC}"

cat > "$SCRIPT_DIR/compliance-monitor.sh" << 'EOF'
#!/bin/bash

# Compliance monitoring dashboard
# Run this script to see compliance status

echo "════════════════════════════════════════════"
echo "  Honeypot Compliance Status Dashboard"
echo "════════════════════════════════════════════"
echo ""

# Check Elasticsearch connectivity
echo "📊 Elasticsearch Status:"
if curl -s -u "elastic:$ELASTICSEARCH_PASSWORD" https://localhost:9200/_cluster/health 2>/dev/null | grep -q '"status"'; then
    echo "  ✓ Connected"
else
    echo "  ✗ Not connected"
fi

# Check recent compliance reports
echo ""
echo "📋 Recent Compliance Reports:"
REPORT_DIR="compliance_reports"
if [ -d "$REPORT_DIR" ]; then
    find "$REPORT_DIR" -name "evidence.json" -type f | sort -r | head -3 | while read file; do
        timestamp=$(echo "$file" | grep -oE '[0-9]{8}_[0-9]{6}')
        standard=$(echo "$file" | sed 's/.*\///;s/_\/.*//')
        echo "  ✓ $standard - $timestamp"
    done
else
    echo "  No reports generated yet"
fi

# Check for compliance failures
echo ""
echo "⚠️  Compliance Issues:"
FAILURES=$(find "$REPORT_DIR" -name "evidence.json" -type f -exec grep -l '"status": "fail"' {} \; | wc -l)
if [ "$FAILURES" -eq 0 ]; then
    echo "  ✓ No failures detected"
else
    echo "  ⚠️  $FAILURES reports with failures found"
fi

echo ""
echo "════════════════════════════════════════════"
EOF

chmod +x "$SCRIPT_DIR/compliance-monitor.sh"
echo -e "${GREEN}[✓] Compliance monitoring script created${NC}"

# Create requirements.txt for compliance
echo -e "\n${YELLOW}[*] Creating Python requirements file...${NC}"

cat > "$PROJECT_ROOT/compliance-requirements.txt" << 'EOF'
# Compliance Reporter Requirements
requests>=2.28.0
reportlab>=4.0.0
pyyaml>=6.0
EOF

echo -e "${GREEN}[✓] Requirements file created${NC}"

# Create README for compliance
echo -e "\n${YELLOW}[*] Creating compliance README...${NC}"

cat > "$PROJECT_ROOT/COMPLIANCE-SETUP.md" << 'EOF'
# Compliance Reporting Setup

## Quick Start

1. **Run setup script:**
   ```bash
   bash scripts/setup-compliance.sh
   ```

2. **Generate compliance reports:**
   ```bash
   python3 scripts/compliance-reporter.py --standard SOC2
   python3 scripts/compliance-reporter.py --standard PCI-DSS
   python3 scripts/compliance-reporter.py --standard HIPAA
   python3 scripts/compliance-reporter.py --standard ALL
   ```

3. **View compliance status:**
   ```bash
   bash scripts/compliance-monitor.sh
   ```

## Documentation

- [COMPLIANCE.md](docs/COMPLIANCE.md) - What the reporter collects, and its limits

## Automated Reports

Reports are generated daily at 2:00 AM and stored in:
```
compliance_reports/
├── SOC2/
├── PCI-DSS/
└── HIPAA/
```

Each report includes:
- `evidence.json` - Detailed evidence trail
- `evidence.csv` - Evidence in CSV format
- `report.pdf` - Formatted PDF report

## Configuration

Edit `config/compliance-config.yml` to customize:
- Elasticsearch connection
- Which standards to audit
- Report output formats
- Retention policies
- Alert thresholds

## Troubleshooting

```bash
# Test Elasticsearch connection
curl -u "elastic:$ELASTICSEARCH_PASSWORD" https://localhost:9200/_cluster/health

# View recent reports
ls -ltr compliance_reports/SOC2/*/

# Check for errors
cat compliance_reports/compliance.log
```

## Next Steps

1. Review [COMPLIANCE.md](docs/COMPLIANCE.md)
2. Choose which standards apply to your organization
3. Review applicable framework document (SOC2, PCI-DSS, or HIPAA)
4. Complete compliance checklist
5. Schedule compliance assessments

For questions, contact your Security Officer.
EOF

echo -e "${GREEN}[✓] Compliance README created${NC}"

# Summary
echo ""
echo -e "${GREEN}════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Compliance Framework Setup Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════${NC}"

echo ""
echo "📚 Next Steps:"
echo ""
echo "1. Review compliance documentation:"
echo "   - docs/COMPLIANCE.md"
echo ""
echo "2. Customize compliance configuration:"
echo "   - nano config/compliance-config.yml"
echo ""
echo "3. Generate your first report:"
echo "   - python3 scripts/compliance-reporter.py --standard SOC2"
echo ""
echo "4. Monitor compliance status:"
echo "   - bash scripts/compliance-monitor.sh"
echo ""
echo "5. Verify Elasticsearch connectivity:"
echo '   - curl -u "elastic:$ELASTICSEARCH_PASSWORD" https://localhost:9200/_cluster/health'
echo ""
echo "✅ Automated daily reports scheduled for 2:00 AM"
echo ""
