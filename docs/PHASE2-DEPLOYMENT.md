# Phase 2 — AWS Single-Region Deployment Guide

## Overview
This guide walks through deploying the honeypot framework to AWS us-east-1 region.

## Prerequisites

### 1. AWS Account Setup
- [ ] AWS account created and activated
- [ ] Billing information verified
- [ ] Free tier account confirmed

### 2. AWS Credentials
```bash
# Install AWS CLI
sudo apt install awscli -y

# Configure credentials
aws configure

# When prompted, enter:
# AWS Access Key ID: [from IAM user]
# AWS Secret Access Key: [from IAM user]
# Default region: us-east-1
# Default output format: json

# Verify credentials work
aws sts get-caller-identity
```

### 3. Create EC2 Key Pair
```bash
# Create key pair for us-east-1
aws ec2 create-key-pair \
  --key-name honeypot-framework-us-east \
  --region us-east-1 \
  --query 'KeyMaterial' \
  --output text > ~/.ssh/honeypot-framework-us-east.pem

# Set proper permissions
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

## Deployment Steps

### Step 1: Plan the Deployment
```bash
cd ~/Desktop/honeypot-framework/terraform/environments/aws-us-east

# Review what will be created
terraform plan -var-file=terraform.tfvars
```

### Step 2: Deploy Infrastructure
```bash
# Create all resources (VPC, Security Groups, EC2, CloudWatch, S3)
terraform apply -var-file=terraform.tfvars

# When prompted, type: yes
```

### Step 3: Verify Deployment
```bash
# Get instance IPs
terraform output honeypot_instances

# SSH into instance
ssh -i ~/.ssh/honeypot-framework-us-east.pem ubuntu@<instance-ip>

# Check honeypot status
sudo systemctl status cowrie
sudo systemctl status opencanary
```

### Step 4: View Logs
```bash
# Check CloudWatch logs
aws logs describe-log-groups --region us-east-1

# View Cowrie logs
aws logs tail /aws/honeypot/aws-us-east/cowrie --follow

# View OpenCanary logs
aws logs tail /aws/honeypot/aws-us-east/opencanary --follow
```

## Cost Estimation (Free Tier)

| Service | Monthly Limit | Cost |
|---------|--------------|------|
| EC2 (t3.micro) | 750 hours | Free |
| CloudWatch Logs | 5 GB | Free |
| S3 Storage | 5 GB | Free |
| Data Transfer | 1 GB out | Free |

**Total:** ~$0/month if within limits

## Security Best Practices

1. **Restrict SSH Access**
```bash
   # Update allowed_ssh_cidr to your IP only
   # Get your IP: curl https://checkip.amazonaws.com
   allowed_ssh_cidr = "203.0.113.42/32"
```

2. **Enable VPC Flow Logs**
```bash
   # Monitor honeypot network activity
```

3. **Set Up CloudWatch Alarms**
   - Already configured in terraform/modules/aws-cloudwatch/main.tf
   - Alerts on high login attempts and port scans

4. **Rotate SSH Keys Regularly**
```bash
   # Create new key pair monthly
   aws ec2 create-key-pair --key-name honeypot-framework-us-east-v2
```

## Cleanup (Delete All Resources)

```bash
cd ~/Desktop/honeypot-framework/terraform/environments/aws-us-east

# WARNING: This deletes everything
terraform destroy -var-file=terraform.tfvars

# When prompted, type: yes
```

## Troubleshooting

### EC2 instance fails to start
- Check user_data.sh logs: `/var/log/cloud-init-output.log`
- Verify IAM role has CloudWatch permissions

### Honeypots not capturing traffic
- Check security group allows inbound on ports 21, 80, 2222, 2223, 23
- Verify honeypot services are running

### Cannot SSH into instance
- Verify key pair name matches terraform.tfvars
- Check security group allows SSH on port 22
- Verify allowed_ssh_cidr includes your IP

## Next Steps

1. **Multi-Region Deployment:** Deploy to eu-west-1 and ap-south-1
2. **Centralized Logging:** Aggregate logs from all regions
3. **Threat Intelligence:** Enrich logs with GeoIP and threat feeds
4. **Automation:** Set up GitHub Actions to deploy on push

## References

- [AWS Terraform Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/)
- [EC2 Security Groups](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html)
