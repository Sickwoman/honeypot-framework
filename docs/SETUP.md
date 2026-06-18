# Installation & Setup Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Local Lab Setup](#local-lab-setup)
3. [Docker Setup](#docker-setup)
4. [AWS Deployment](#aws-deployment)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements
- **OS**: Ubuntu 22.04+ or Kali Linux
- **RAM**: 4GB minimum (8GB recommended)
- **Disk**: 20GB free space
- **CPU**: 2 cores minimum

### Required Software
```bash
# Install dependencies
sudo apt update
sudo apt install -y \
  python3 python3-pip \
  git curl wget \
  docker.io docker-compose \
  terraform awscli \
  netcat-openbsd sshpass
```

### Optional Tools
```bash
# For advanced features
sudo apt install -y \
  geoip-bin geoip-database \
  jq \
  net-tools
```

---

## Local Lab Setup

### Step 1: Clone Repository

```bash
cd ~/Desktop
git clone https://github.com/Sickwoman/honeypot-framework.git
cd honeypot-framework
```

### Step 2: Deploy Honeypots

```bash
# Make scripts executable
chmod +x scripts/*.sh

# Deploy all services
./scripts/deploy.sh

# Wait 30 seconds for startup
sleep 30

# Verify services running
./scripts/check-services.sh
```

### Step 3: Configure Cowrie

```bash
# SSH into Cowrie to verify
ssh -p 2222 root@localhost

# Any password will work (it's a honeypot)
# Test commands:
whoami
ls -la
cat /etc/passwd
exit
```

### Step 4: Test OpenCanary

```bash
# Test FTP
ftp localhost 21
# Login: admin / admin123

# Test HTTP
curl http://localhost:80/

# Test MySQL
mysql -h localhost -u admin -p admin123

# Test SSH (alternate port)
ssh -p 2223 root@localhost
```

### Step 5: Access Kibana Dashboard

```bash
# Open in browser
open http://localhost:5601

# Or use curl
curl http://localhost:5601
```

---

## Docker Setup

### Option A: Using Docker Compose

```bash
cd ~/elk-stack

# Start all containers
docker-compose up -d

# View logs
docker-compose logs -f

# Stop containers
docker-compose down

# Restart specific service
docker-compose restart logstash
```

### Option B: Manual Docker Commands

```bash
# Start Elasticsearch
docker run -d \
  --name elasticsearch \
  -e "discovery.type=single-node" \
  -p 9200:9200 \
  docker.elastic.co/elasticsearch/elasticsearch:7.14.0

# Start Kibana
docker run -d \
  --name kibana \
  -p 5601:5601 \
  -e "ELASTICSEARCH_HOSTS=http://elasticsearch:9200" \
  docker.elastic.co/kibana/kibana:7.14.0
```

---

## AWS Deployment

### Step 1: Create AWS Account

1. Go to https://aws.amazon.com/free
2. Sign up with email
3. Verify email and phone
4. Add payment method
5. Wait 24 hours for full activation

### Step 2: Create IAM User

```bash
# Log into AWS Console
# Go to IAM → Users → Create user

# Username: honeypot-terraform
# Permissions: Attach these policies
#   - AmazonEC2FullAccess
#   - AmazonVPCFullAccess
#   - AmazonS3FullAccess
#   - CloudWatchFullAccess
#   - AmazonDynamoDBFullAccess

# Create access key
# Copy Access Key ID and Secret Access Key
```

### Step 3: Configure AWS CLI

```bash
# Configure credentials
aws configure

# When prompted enter:
# AWS Access Key ID: [your key]
# AWS Secret Access Key: [your secret]
# Default region: us-east-1
# Default output format: json

# Verify credentials
aws sts get-caller-identity
```

### Step 4: Create EC2 Key Pair

```bash
# Create key pair for us-east-1
aws ec2 create-key-pair \
  --key-name honeypot-framework-us-east \
  --region us-east-1 \
  --query 'KeyMaterial' \
  --output text > ~/.ssh/honeypot-framework-us-east.pem

# Set permissions
chmod 400 ~/.ssh/honeypot-framework-us-east.pem

# Repeat for other regions
aws ec2 create-key-pair \
  --key-name honeypot-framework-eu-west \
  --region eu-west-1 \
  --query 'KeyMaterial' \
  --output text > ~/.ssh/honeypot-framework-eu-west.pem

aws ec2 create-key-pair \
  --key-name honeypot-framework-ap-south \
  --region ap-south-1 \
  --query 'KeyMaterial' \
  --output text > ~/.ssh/honeypot-framework-ap-south.pem
```

### Step 5: Deploy Terraform

```bash
cd ~/Desktop/honeypot-framework/terraform/environments/aws-us-east

# Review what will be created
terraform plan -var-file=terraform.tfvars

# Deploy infrastructure
terraform apply -var-file=terraform.tfvars

# When prompted, type: yes

# Wait 5-10 minutes for deployment
```

### Step 6: Verify Deployment

```bash
# Get instance IPs
terraform output honeypot_instances

# SSH into instance
ssh -i ~/.ssh/honeypot-framework-us-east.pem \
  ubuntu@<instance-ip>

# Check honeypot status
sudo systemctl status cowrie opencanary

# View CloudWatch logs
aws logs describe-log-groups --region us-east-1
```

---

## Verification

### Local Lab Verification

```bash
# 1. Check all services running
sudo systemctl status cowrie opencanary elk-stack

# 2. Verify ports listening
sudo ss -tlnp | grep -E "(2222|21|80|3306|2223|23|9200|5601)"

# 3. Check honeypot logs
tail -20 /home/cowrie/cowrie/var/log/cowrie/cowrie.log
tail -20 /var/tmp/opencanary.log

# 4. Query Elasticsearch
curl http://localhost:9200/_cat/indices

# 5. Access Kibana
open http://localhost:5601
```

### AWS Deployment Verification

```bash
# 1. Check instances running
aws ec2 describe-instances --region us-east-1

# 2. Check security groups
aws ec2 describe-security-groups --region us-east-1

# 3. Check CloudWatch log groups
aws logs describe-log-groups --region us-east-1

# 4. Check S3 bucket created
aws s3 ls | grep honeypot

# 5. SSH and verify honeypots
ssh -i ~/.ssh/honeypot-framework-us-east.pem ubuntu@<ip>
sudo systemctl status cowrie opencanary
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u cowrie.service -n 50

# Restart service
sudo systemctl restart cowrie.service

# Check if port is in use
sudo lsof -i :2222

# Kill process using port
sudo kill -9 <pid>
```

### Elasticsearch Connection Error

```bash
# Check if running
docker ps | grep elasticsearch

# Check logs
docker logs elasticsearch-container-name

# Restart container
docker-compose restart elasticsearch
```

### Terraform Apply Fails

```bash
# Validate syntax
terraform validate

# Check format
terraform fmt -recursive

# Verbose output
terraform apply -var-file=terraform.tfvars -lock=false
```

### Cannot SSH into AWS Instance

```bash
# Verify key permissions
ls -la ~/.ssh/honeypot-framework-us-east.pem
# Should show: -r--------

# Check security group allows SSH
aws ec2 describe-security-groups --region us-east-1

# Verify instance is running
aws ec2 describe-instances --region us-east-1

# Check network connectivity
ping <instance-ip>
```

### High AWS Costs

```bash
# Check running instances
aws ec2 describe-instances --region us-east-1

# Check CloudWatch logs retention
aws logs describe-log-groups --region us-east-1

# Stop instances to save costs
aws ec2 stop-instances --instance-ids i-xxxxx --region us-east-1

# Terminate if no longer needed
aws ec2 terminate-instances --instance-ids i-xxxxx --region us-east-1
```

---

## Next Steps

1. ✅ Complete setup
2. 📊 Generate test attacks: `./scripts/simulate-attacks.sh`
3. 📈 View dashboards in Kibana
4. 🔍 Analyze logs with queries
5. 🚀 Deploy multi-region (Phase 3)
6. 🧠 Integrate threat intelligence (Phase 4)

---

## Getting Help

- 📖 [Architecture Documentation](architecture.md)
- 🐛 [Report Issues](https://github.com/Sickwoman/honeypot-framework/issues)
- 💬 [Discussions](https://github.com/Sickwoman/honeypot-framework/discussions)

