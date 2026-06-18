# Security Hardening Guide

## Overview

This guide covers security enhancements for the honeypot framework including SSL/TLS, authentication, and API key management.

---

## 1. SSL/TLS Configuration

### Local Development Certificates

Certificates have been generated in `certs/` directory:
- `honeypot-cert.pem` - Self-signed certificate
- `honeypot-key.pem` - Private key
- `kibana-cert.pem` - Kibana certificate
- `elasticsearch-cert.pem` - Elasticsearch certificate

### Updating Certificates

```bash
# Generate new certificate (365 days valid)
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/honeypot-key.pem \
  -out certs/honeypot-cert.pem \
  -days 365 -nodes \
  -subj "/CN=your-domain.com"

# View certificate details
openssl x509 -in certs/honeypot-cert.pem -text -noout

# Check expiration date
openssl x509 -in certs/honeypot-cert.pem -noout -dates
```

### Production Certificates

For production, use certificates from a trusted CA:

```bash
# Option 1: Let's Encrypt (Recommended)
sudo apt install certbot
sudo certbot certonly --standalone -d your-domain.com

# Certificates will be in: /etc/letsencrypt/live/your-domain.com/

# Option 2: AWS Certificate Manager
# Go to AWS Console → Certificate Manager
# Create certificate for your domain
```

---

## 2. Authentication & Authorization

### Elasticsearch Built-in Users

Default users created with X-Pack enabled:

| User | Role | Purpose |
|------|------|---------|
| `elastic` | superuser | Administrative access |
| `kibana_system` | kibana_system | Kibana internal use |
| `logstash_system` | logstash_system | Logstash pipeline |

### Change Default Passwords

```bash
# Set elastic user password
curl -X POST "localhost:9200/_security/user/elastic/_password?pretty" \
  -H 'Content-Type: application/json' \
  -d'{ "password" : "new-secure-password" }'

# Set kibana_system password
curl -X POST "localhost:9200/_security/user/kibana_system/_password?pretty" \
  -H 'Content-Type: application/json' \
  -d'{ "password" : "kibana-secure-password" }'

# Set logstash_system password
curl -X POST "localhost:9200/_security/user/logstash_system/_password?pretty" \
  -H 'Content-Type: application/json' \
  -d'{ "password" : "logstash-secure-password" }'
```

### Create Custom Users

```bash
# Create read-only user for analysts
curl -X POST "localhost:9200/_security/user/analyst?pretty" \
  -H 'Content-Type: application/json' \
  -d'
  {
    "password" : "analyst-password",
    "roles" : ["viewer"],
    "full_name" : "Security Analyst"
  }
  '

# Create admin user
curl -X POST "localhost:9200/_security/user/admin?pretty" \
  -H 'Content-Type: application/json' \
  -d'
  {
    "password" : "admin-password",
    "roles" : ["superuser"],
    "full_name" : "System Administrator"
  }
  '
```

---

## 3. API Key Management

### Create API Keys

```bash
# Using the management script
./scripts/manage-api-keys.sh create logstash-ingest

# Or via curl
curl -X POST "localhost:9200/_security/api_key?pretty" \
  -H 'Content-Type: application/json' \
  -u elastic:changeme \
  -d'
  {
    "name": "logstash-ingest",
    "role_descriptors": {
      "honeypot-role": {
        "cluster": ["monitor"],
        "index": [
          {
            "names": ["honeypot-*"],
            "privileges": ["create", "index", "read"]
          }
        ]
      }
    },
    "expiration": "90d"
  }
  '
```

### List API Keys

```bash
./scripts/manage-api-keys.sh list

# Or via curl
curl -X GET "localhost:9200/_security/api_key?pretty" \
  -u elastic:changeme
```

### Delete API Keys

```bash
./scripts/manage-api-keys.sh delete <key-id>

# Or via curl
curl -X DELETE "localhost:9200/_security/api_key?pretty" \
  -H 'Content-Type: application/json' \
  -u elastic:changeme \
  -d'{"ids": ["<key-id>"]}'
```

### Using API Keys in Applications

```bash
# Encode API key (base64)
API_KEY="S1Z6T4bQTwqP7d4XgfcR5A:TIJ508GeQ5i2Z0C1qoKc5A"
ENCODED=$(echo -n "$API_KEY" | base64)

# Use in curl
curl -H "Authorization: ApiKey $ENCODED" \
  https://localhost:9200/honeypot-*/_search

# Use in Logstash
output {
  elasticsearch {
    hosts => ["https://elasticsearch:9200"]
    api_key => "$ENCODED"
    ssl => true
  }
}
```

---

## 4. HTTPS/SSL Configuration

### Elasticsearch HTTPS

```bash
# Update elasticsearch connection
curl --cacert certs/ca.crt \
  -u elastic:changeme \
  https://localhost:9200/_cluster/health

# Or without certificate verification (dev only)
curl -k -u elastic:changeme \
  https://localhost:9200/_cluster/health
```

### Kibana HTTPS

Access Kibana over HTTPS:
https://localhost:5601
Browser will show certificate warning (expected for self-signed certs).

### Logstash with SSL

```conf
output {
  elasticsearch {
    hosts => ["https://elasticsearch:9200"]
    ssl => true
    ssl_certificate_verification => true
    cacert => "/usr/share/logstash/config/certs/ca.crt"
    user => "logstash_system"
    password => "changeme"
  }
}
```

---

## 5. Role-Based Access Control (RBAC)

### Built-in Roles

| Role | Permissions |
|------|-------------|
| `superuser` | Full access to all resources |
| `viewer` | Read-only access to indices |
| `editor` | Create, read, update documents |
| `admin` | Administrative access |
| `kibana_system` | Kibana internal operations |

### Create Custom Roles

```bash
# Create analyst role (read-only)
curl -X POST "localhost:9200/_security/role/analyst?pretty" \
  -H 'Content-Type: application/json' \
  -u elastic:changeme \
  -d'
  {
    "cluster": ["monitor"],
    "index": [
      {
        "names": ["honeypot-*"],
        "privileges": ["read", "view_index_metadata"]
      }
    ]
  }
  '

# Create incident responder role
curl -X POST "localhost:9200/_security/role/incident-responder?pretty" \
  -H 'Content-Type: application/json' \
  -u elastic:changeme \
  -d'
  {
    "cluster": ["monitor"],
    "index": [
      {
        "names": ["honeypot-*"],
        "privileges": ["read", "write"]
      }
    ]
  }
  '
```

---

## 6. Audit Logging

### Enable Audit Logging

Audit logs track all access and modifications:

```bash
# View audit logs
tail -f /var/log/elasticsearch/honeypot-audit.log

# Query audit logs in Kibana
GET .security_audit-*/_search
{
  "query": {
    "match_all": {}
  },
  "sort": [{"@timestamp": {"order": "desc"}}]
}
```

### Audit Log Events

- `authentication_success` - User logged in
- `authentication_failure` - Failed login attempt
- `access_granted` - Permission granted
- `access_denied` - Permission denied
- `change_password` - User changed password

---

## 7. Security Best Practices

### ✅ DO:

- ✅ Change default passwords immediately
- ✅ Use strong passwords (16+ characters, mixed case, numbers, symbols)
- ✅ Rotate API keys every 90 days
- ✅ Use HTTPS for all connections
- ✅ Enable audit logging
- ✅ Monitor access logs for suspicious activity
- ✅ Use separate credentials for each service
- ✅ Implement network segmentation (VPC)
- ✅ Keep secrets in environment variables
- ✅ Use certificate pinning for critical connections

### ❌ DON'T:

- ❌ Use default credentials in production
- ❌ Commit credentials to Git
- ❌ Use self-signed certificates in production
- ❌ Share API keys across services
- ❌ Store passwords in plain text
- ❌ Allow public access to Elasticsearch
- ❌ Disable SSL/TLS
- ❌ Use weak passwords
- ❌ Ignore audit logs
- ❌ Reuse API keys

---

## 8. AWS Security (Phase 2)

### IAM Policies

Least-privilege IAM policies defined in Terraform:

```hcl
statement {
  sid    = "CreateLogGroupAndStream"
  effect = "Allow"
  actions = [
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:PutLogEvents"
  ]
  resources = ["arn:aws:logs:*:*:/aws/honeypot/*"]
}
```

### VPC Security Groups

```bash
# Honeypot security group
# Inbound: Ports 21, 80, 2222, 2223, 23 (from anywhere)
# Inbound: Port 22 (SSH, from admin IP only)
# Outbound: Blocked (except CloudWatch)

# Management security group
# Inbound: Port 22 (from bastion only)
# Outbound: To honeypot group only
```

### S3 Encryption

```bash
# Enable server-side encryption
aws s3api put-bucket-encryption \
  --bucket honeypot-logs \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket honeypot-logs \
  --versioning-configuration Status=Enabled

# Block public access
aws s3api put-public-access-block \
  --bucket honeypot-logs \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

---

## 9. Incident Response

### Compromised API Key

```bash
# Immediately invalidate the key
./scripts/manage-api-keys.sh delete <compromised-key-id>

# Rotate user password
curl -X POST "localhost:9200/_security/user/elastic/_password?pretty" \
  -u elastic:old-password \
  -H 'Content-Type: application/json' \
  -d'{ "password" : "new-password" }'

# Review audit logs for unauthorized access
tail -1000 /var/log/elasticsearch/honeypot-audit.log | grep "access_granted"
```

### Unauthorized Access Detected

```bash
# 1. Check who accessed what
GET .security_audit-*/_search
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-24h"
      }
    }
  }
}

# 2. Disable user account
curl -X PUT "localhost:9200/_security/user/suspicious-user/_disable?pretty" \
  -u elastic:changeme

# 3. Force logout all sessions
curl -X POST "localhost:9200/_security/_saml/logout" \
  -u elastic:changeme

# 4. Review and rotate credentials
```

---

## Testing Security

### Verify HTTPS

```bash
# Check certificate
openssl s_client -connect localhost:9200

# Test HTTPS connection
curl -k --cert certs/honeypot-cert.pem \
  --key certs/honeypot-key.pem \
  https://localhost:9200/_cluster/health
```

### Test Authentication

```bash
# Should fail without credentials
curl -X GET "localhost:9200/_security/user" 2>&1 | grep -i "unauthorized"

# Should succeed with credentials
curl -u elastic:changeme \
  -X GET "localhost:9200/_security/user"
```

### Test API Key

```bash
# Generate test API key
./scripts/manage-api-keys.sh create test-key

# Use the key
curl -H "Authorization: ApiKey $(echo -n 'key:secret' | base64)" \
  https://localhost:9200/honeypot-*/_search
```

