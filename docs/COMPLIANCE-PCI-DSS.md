# PCI-DSS Compliance Framework

## Overview
PCI-DSS (Payment Card Industry Data Security Standard) is a set of security standards designed to ensure that all companies that accept, process, store, or transmit credit card information maintain a secure environment.

**Important:** Honeypots intentionally attract attacks and should NEVER handle real payment card data. This framework ensures honeypot systems are segmented and cannot access production systems.

## PCI-DSS Requirements

### Requirement 1: Install and Maintain Firewall Configuration
Establish firewall configuration standards to protect cardholder data environment (CDE).

- [ ] Define firewall rules and architecture
- [ ] Document network diagram
- [ ] Restrict connections between untrusted networks and CDE
- [ ] Implement stateful firewall rules
- [ ] Prohibit direct public access to honeypot
- [ ] Review firewall rules quarterly

**Honeypot Specific:**
- [ ] Verify honeypot is in isolated VPC
- [ ] Confirm no access to payment systems
- [ ] Test network segmentation
- [ ] Document firewall rules blocking honeypot→production traffic

**Verification:**
```bash
# Check network isolation
aws ec2 describe-security-groups --filters Name=vpc-id,Values=vpc-xxxxx

# Test connectivity to production
ping -c 1 production-database.internal || echo "✓ Isolated"

# Review firewall logs
grep "denied\|dropped" /var/log/firewall.log | tail -20
```

### Requirement 2: Do Not Use Vendor-Supplied Defaults
Remove or change all vendor-supplied default passwords and security parameters.

- [ ] Change all default passwords
- [ ] Remove unnecessary accounts
- [ ] Disable unnecessary services
- [ ] Document changes made
- [ ] Test password reset procedures
- [ ] Maintain secure configuration standards

**Honeypot Specific:**
- [ ] Verify Cowrie SSH honeypot has custom passwords
- [ ] Confirm database credentials are unique
- [ ] Check Elasticsearch is password-protected
- [ ] Verify Kibana authentication enabled

**Verification:**
```bash
# Check for default credentials in config
grep -r "default\|admin\|password" config/ honeypots/ | grep -v "\.git"

# Verify Elasticsearch authentication
curl -u elastic:changeme https://localhost:9200/_security/user 2>/dev/null | grep -q '"username"' && echo "✓ Auth enabled"
```

### Requirement 3: Protect Stored Cardholder Data
Render stored cardholder data unreadable anywhere it is stored.

- [ ] Do not store cardholder data in honeypot
- [ ] Verify no PAN (Primary Account Number) in logs
- [ ] Implement data minimization
- [ ] Redact sensitive patterns in logs
- [ ] Document data retention policies

**Honeypot Specific:**
- [ ] Log sanitization to remove credit card patterns
- [ ] No storage of actual payment data
- [ ] Document data handling procedures
- [ ] Implement log redaction rules

**Verification:**
```bash
# Scan logs for credit card patterns
grep -rE '[0-9]{13,19}' logs/ | wc -l

# Check logstash redaction rules
grep -A 5 "mutate" logstash.conf | grep -i "gsub\|redact"
```

### Requirement 4: Encrypt Transmission of Cardholder Data
Protect cardholder data with encryption during transmission over public networks.

- [ ] Identify all transmission methods
- [ ] Use strong encryption (TLS 1.2+)
- [ ] Implement certificate management
- [ ] Monitor certificate expiration
- [ ] Test encryption regularly

**Honeypot Specific:**
- [ ] Verify Elasticsearch uses TLS
- [ ] Confirm Kibana uses HTTPS
- [ ] Check Logstash→Elasticsearch encryption
- [ ] Test certificate validity

**Verification:**
```bash
# Check certificate validity
openssl s_client -connect localhost:9200 -showcerts </dev/null | grep -A 5 "Issuer"

# Verify TLS version
curl -v https://localhost:9200 2>&1 | grep "TLSv"

# Check Logstash output configuration
grep -A 10 "output {" logstash.conf | grep -E "ssl|certificate"
```

### Requirement 5: Protect Systems Against Malware
Maintain antivirus or anti-malware protection on all systems.

- [ ] Deploy antivirus/anti-malware
- [ ] Enable automatic updates
- [ ] Perform regular scans
- [ ] Monitor detection logs
- [ ] Investigate detections immediately
- [ ] Document procedures

**Honeypot Specific:**
- [ ] Install ClamAV or similar
- [ ] Configure real-time scanning
- [ ] Monitor honeypot for actual infections (separate from simulated attacks)
- [ ] Archive infected samples

**Verification:**
```bash
# Check antivirus status
systemctl status clamav-daemon

# Run full system scan
clamscan -r /home /var --exclude-dir=/proc

# Check last scan results
grep "FOUND\|Scanned" /var/log/clamav/scan.log | tail -10
```

### Requirement 6: Develop and Maintain Secure Systems and Applications
Maintain secure development and change management processes.

- [ ] Use secure development practices
- [ ] Implement code review
- [ ] Perform security testing
- [ ] Use secure libraries and frameworks
- [ ] Implement patch management
- [ ] Maintain change logs

**Honeypot Specific:**
- [ ] Use official Cowrie releases
- [ ] Apply security patches promptly
- [ ] Review custom modifications
- [ ] Test changes in isolated environment
- [ ] Document all changes

**Verification:**
```bash
# Check Cowrie version
cowrie --version

# List recent patches
apt-get changelog cowrie 2>/dev/null | head -20

# Review custom changes
git log --oneline honeypots/cowrie/ | head -10
```

### Requirement 7: Restrict Access to Cardholder Data
Implement access controls to limit access to cardholder data.

- [ ] Limit access by business need
- [ ] Implement role-based access control
- [ ] Use unique user IDs
- [ ] Restrict default access deny
- [ ] Document access requirements
- [ ] Review access quarterly

**Honeypot Specific:**
- [ ] Restrict Elasticsearch access to authorized analysts
- [ ] Implement role-based access in Kibana
- [ ] Log all access to honeypot data
- [ ] Audit access regularly

**Verification:**
```bash
# List Elasticsearch users with roles
curl -s -u elastic:changeme https://localhost:9200/_security/user | jq '.[] | {username, roles}'

# Check Kibana spaces and permissions
curl -s https://localhost:5601/api/spaces | jq '.[] | {id, name}'

# Review access logs
grep "user_id\|authentication" honeypot-*.log | tail -20
```

### Requirement 8: Identify and Authenticate Access
Assign unique ID to each user and maintain strong authentication.

- [ ] Assign unique user IDs
- [ ] Enforce strong passwords
- [ ] Implement multi-factor authentication
- [ ] Manage user lifecycle
- [ ] Disable unused accounts
- [ ] Monitor user creation/deletion

**Honeypot Specific:**
- [ ] Create unique accounts for each analyst
- [ ] Enforce strong passwords
- [ ] Implement MFA for administrative access
- [ ] Disable accounts for separated personnel
- [ ] Log authentication events

**Verification:**
```bash
# List active users
cat /etc/passwd | grep -v "^#\|/nologin\|/false" | cut -d: -f1

# Check password policy
cat /etc/login.defs | grep PASS

# Review authentication attempts
grep "Failed password\|Accepted" /var/log/auth.log | tail -20
```

### Requirement 9: Restrict Physical Access to Cardholder Data
Limit physical access to facilities and systems.

- [ ] Implement physical access controls
- [ ] Maintain visitor log
- [ ] Secure sensitive areas
- [ ] Implement badge/key systems
- [ ] Review access logs monthly

**Cloud Honeypot Specific:**
- [ ] Use AWS security groups to restrict network access
- [ ] Enable CloudTrail to log all API calls
- [ ] Implement IAM policies with least privilege
- [ ] Monitor root account usage
- [ ] Enable MFA on AWS console

**Verification:**
```bash
# Check AWS security groups
aws ec2 describe-security-groups --filters Name=tag:Environment,Values=honeypot

# Review CloudTrail events
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=root

# Check IAM policies
aws iam list-users | jq '.Users[] | {UserName, CreateDate}'
```

### Requirement 10: Track and Monitor Access to Honeypot Data
Implement comprehensive logging and monitoring.

- [ ] Log all access to network resources
- [ ] Log administrative actions
- [ ] Log failed access attempts
- [ ] Log user identity in logs
- [ ] Protect log files from modification
- [ ] Review logs regularly
- [ ] Retain logs for minimum 1 year

**Honeypot Specific:**
- [ ] Enable Elasticsearch audit logging
- [ ] Configure Kibana activity logs
- [ ] Monitor Logstash pipeline activity
- [ ] Log Docker container events
- [ ] Implement centralized log aggregation
- [ ] Set up alerts for suspicious activities

**Verification:**
```bash
# Check Elasticsearch audit logging
curl -s -u elastic:changeme https://localhost:9200/.audit-*/_count | jq '.count'

# View recent audit events
curl -s -u elastic:changeme https://localhost:9200/.audit-*/_search | jq '.hits.hits[] | ._source'

# Check Kibana audit logs
tail -50 /var/lib/kibana/audit.log

# Monitor honeypot events
docker-compose logs --follow cowrie
```

### Requirement 11: Test Security Systems Regularly
Implement policies and procedures to maintain security.

- [ ] Run vulnerability scans quarterly
- [ ] Perform penetration testing annually
- [ ] Monitor changes to system
- [ ] Maintain audit logs
- [ ] Document testing procedures
- [ ] Address findings immediately

**Honeypot Specific:**
- [ ] Test honeypot detection capabilities
- [ ] Verify logging accuracy
- [ ] Test incident response procedures
- [ ] Validate network segmentation
- [ ] Perform disaster recovery tests

**Verification:**
```bash
# Run vulnerability scan
nessus-scan --target localhost --policy honeypot

# Check system file integrity
aide --check

# Verify honeypot is capturing attacks
grep "connection\|attempt" honeypot-logs/*.log | wc -l
```

### Requirement 12: Maintain Incident Response Policy
Develop and implement incident response procedures.

- [ ] Document incident response plan
- [ ] Define incident severity levels
- [ ] Establish escalation procedures
- [ ] Test response procedures
- [ ] Maintain incident logs
- [ ] Conduct post-incident reviews
- [ ] Update procedures based on findings

**Honeypot Specific:**
- [ ] Document honeypot-specific incidents
- [ ] Alert on unusual patterns
- [ ] Escalate serious threats
- [ ] Archive incident evidence
- [ ] Conduct threat intelligence analysis

**Verification:**
```bash
# View incident alerts
grep "CRITICAL\|ALERT" honeypot-*.log | tail -20

# Check incident response logs
tail -50 /var/log/incident-response.log

# Review archived incidents
ls -la /archive/incidents/ | tail -10
```

## Implementation Checklist

### Network Architecture
- [ ] Honeypot in isolated VPC/subnet
- [ ] No direct internet access to production
- [ ] VPN required for administrative access
- [ ] Firewall rules documented
- [ ] Network diagram current

### Data Protection
- [ ] All data encrypted in transit (TLS 1.2+)
- [ ] All data encrypted at rest (AES-256)
- [ ] Key management procedures documented
- [ ] Certificates valid and monitored
- [ ] Password hashing (bcrypt/scrypt)

### Access Control
- [ ] Unique user accounts
- [ ] Role-based access control
- [ ] Multi-factor authentication
- [ ] Access review procedures
- [ ] Unused accounts disabled

### Monitoring and Logging
- [ ] Centralized log aggregation
- [ ] Real-time alerting
- [ ] Audit logs immutable
- [ ] Retention policy: 1+ year
- [ ] Regular log reviews

### Incident Response
- [ ] Response plan documented
- [ ] Contact list maintained
- [ ] Testing schedule established
- [ ] Forensics procedures defined
- [ ] Post-incident reviews conducted

## Compliance Status

> **This project has not been audited.** Nothing below is an attestation of
> compliance. These documents map the framework's controls onto the
> PCI-DSS control vocabulary as a self-assessment exercise -- useful as a
> checklist and for learning how the controls map to real infrastructure, but
> a genuine PCI-DSS position requires an independent assessor, organizational
> policies and evidence retention that live outside this repository.
>
> Run `python3 scripts/compliance-reporter.py --standard PCI-DSS` to collect
> the evidence this repo *can* produce (log coverage, access-control config,
> retention settings), then judge each control yourself against the checklist
> above.

## Automated Compliance Verification

```bash
# Generate PCI-DSS compliance report
python3 scripts/compliance-reporter.py --standard PCI-DSS

# Generate all compliance reports
python3 scripts/compliance-reporter.py --standard ALL
```

## References

- [PCI-DSS Official Document](https://www.pcisecuritystandards.org/)
- [PCI-DSS Best Practices](https://www.pcisecuritystandards.org/merchants/training-resources)
- [AWS PCI-DSS Compliance](https://aws.amazon.com/compliance/pci-dss-level-1-compliance/)

## Contact

For PCI-DSS compliance questions, contact the Security and Compliance Team.
