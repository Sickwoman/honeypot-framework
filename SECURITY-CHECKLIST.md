# Security Hardening Checklist

## Pre-Deployment Security

### SSL/TLS Configuration
- [ ] Generate SSL/TLS certificates
- [ ] Store private keys securely
- [ ] Set certificate expiration reminder
- [ ] Test HTTPS connectivity

### Authentication & Authorization
- [ ] Change all default passwords
- [ ] Create strong passwords (16+ characters)
- [ ] Set up RBAC (Role-Based Access Control)
- [ ] Create service-specific credentials
- [ ] Document user accounts and roles

### API Keys & Secrets
- [ ] Generate API keys for services
- [ ] Store API keys securely (environment variables)
- [ ] Set API key expiration (90 days)
- [ ] Never commit secrets to Git
- [ ] Rotate keys regularly

### Elasticsearch Security
- [ ] Enable X-Pack security
- [ ] Configure SSL/TLS for HTTP
- [ ] Configure SSL/TLS for node-to-node
- [ ] Enable audit logging
- [ ] Review audit logs weekly

### Kibana Security
- [ ] Enable authentication
- [ ] Configure HTTPS
- [ ] Set session timeout
- [ ] Disable console editing (production)
- [ ] Implement access controls

### Logstash Security
- [ ] Use SSL/TLS to Elasticsearch
- [ ] Sanitize sensitive data in pipelines
- [ ] Use API keys (not passwords)
- [ ] Redact passwords before indexing
- [ ] Monitor pipeline errors

## Local Lab Security

### Local Services
- [ ] Enable firewall
- [ ] Restrict SSH access
- [ ] Disable unnecessary services
- [ ] Keep system updated
- [ ] Run services as non-root

### Data Protection
- [ ] Enable full disk encryption
- [ ] Restrict file permissions
- [ ] Backup encryption keys
- [ ] Implement regular backups
- [ ] Test backup restoration

## AWS Deployment Security

### IAM Security
- [ ] Create least-privilege IAM policies
- [ ] Enable MFA for root account
- [ ] Use IAM roles (not access keys)
- [ ] Rotate access keys every 90 days
- [ ] Monitor IAM activity

### Network Security
- [ ] Create VPC with private subnets
- [ ] Configure security groups
- [ ] Enable NACLs (Network ACLs)
- [ ] Use VPC endpoints for AWS services
- [ ] Enable VPC Flow Logs

### Storage Security
- [ ] Enable S3 encryption
- [ ] Block S3 public access
- [ ] Enable S3 versioning
- [ ] Enable S3 MFA delete
- [ ] Set S3 lifecycle policies

### Logging & Monitoring
- [ ] Enable CloudTrail logging
- [ ] Enable S3 access logging
- [ ] Enable VPC Flow Logs
- [ ] Configure CloudWatch alarms
- [ ] Review logs weekly

### Compliance
- [ ] Document security controls
- [ ] Conduct vulnerability scans
- [ ] Perform penetration testing
- [ ] Review HIPAA/PCI-DSS requirements
- [ ] Maintain audit trail

## Ongoing Security

### Weekly Tasks
- [ ] Review audit logs
- [ ] Check for failed logins
- [ ] Verify backup integrity
- [ ] Monitor for anomalies

### Monthly Tasks
- [ ] Rotate API keys
- [ ] Review user access
- [ ] Update systems
- [ ] Review security logs
- [ ] Test incident response

### Quarterly Tasks
- [ ] Conduct security review
- [ ] Update security policies
- [ ] Perform vulnerability scan
- [ ] Review access controls
- [ ] Disaster recovery drill

### Annual Tasks
- [ ] Full security audit
- [ ] Penetration testing
- [ ] Security training
- [ ] Policy review
- [ ] Risk assessment

## Password Requirements

All passwords must meet these criteria:
- [ ] Minimum 16 characters
- [ ] Mix of uppercase and lowercase
- [ ] Include numbers (0-9)
- [ ] Include special characters (!@#$%^&*)
- [ ] Not contain dictionary words
- [ ] Not reuse last 12 passwords
- [ ] Expire every 90 days

## Incident Response

### If Breach Detected
- [ ] Isolate affected systems immediately
- [ ] Preserve logs and evidence
- [ ] Notify security team
- [ ] Document timeline of events
- [ ] Conduct investigation
- [ ] Implement remediation
- [ ] Notify affected parties
- [ ] Post-incident review

### If Credentials Compromised
- [ ] Revoke compromised credentials immediately
- [ ] Reset related passwords
- [ ] Rotate API keys
- [ ] Review access logs for unauthorized activity
- [ ] Monitor for lateral movement
- [ ] Document incident
- [ ] Review security controls

## Compliance Standards

### NIST Cybersecurity Framework
- [ ] Identify assets and risks
- [ ] Protect through access controls
- [ ] Detect unauthorized activity
- [ ] Respond to incidents
- [ ] Recover and maintain resilience

### CIS Controls
- [ ] Inventory and control hardware
- [ ] Inventory and control software
- [ ] Continuous vulnerability assessment
- [ ] Controlled access to network resources
- [ ] Secure configurations
- [ ] Secure account management
- [ ] User security training

## Documentation

- [ ] Security policies written
- [ ] Procedures documented
- [ ] Incident response plan created
- [ ] Access control matrix maintained
- [ ] Configuration baselines documented
- [ ] Security training materials prepared

## Sign-Off

- Security Review Date: _______________
- Reviewer Name: _______________
- Signature: _______________
- Next Review Date: _______________

