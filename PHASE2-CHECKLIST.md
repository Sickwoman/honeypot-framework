# Phase 2 Pre-Deployment Checklist

## ✅ Code Quality Fixes Applied

- [x] Created user_data.sh for EC2 instance initialization
- [x] Updated terraform.tfvars with documentation and key pair requirements
- [x] Fixed S3 bucket naming to include region (globally unique)
- [x] Updated EC2 module with least-privilege IAM policies
- [x] Uncommented EC2 module with clear deployment instructions
- [x] Added .terraform.lock.hcl to version control
- [x] Created Phase 2 deployment guide

## 🔐 AWS Account Setup

- [ ] AWS account created and activated
- [ ] Billing information verified
- [ ] Free tier eligibility confirmed

## 👤 AWS Credentials

- [ ] IAM user created (honeypot-terraform)
- [ ] Access Key ID obtained
- [ ] Secret Access Key obtained
- [ ] AWS CLI installed
- [ ] `aws configure` completed
- [ ] `aws sts get-caller-identity` returns account info

## 🔑 EC2 Key Pairs Created

- [ ] honeypot-framework-us-east (us-east-1)
- [ ] honeypot-framework-eu-west (eu-west-1)
- [ ] honeypot-framework-ap-south (ap-south-1)
- [ ] All .pem files stored in ~/.ssh/ with 400 permissions

## 📝 Terraform Configuration Ready

- [ ] terraform.tfvars updated with your IP for allowed_ssh_cidr
- [ ] key_pair_name matches AWS key pair names
- [ ] All terraform files validated
- [ ] terraform plan reviewed without errors

## 🚀 Ready to Deploy

Once all checkboxes are complete, deploy with:

```bash
cd ~/Desktop/honeypot-framework/terraform/environments/aws-us-east
terraform apply -var-file=terraform.tfvars
```

## 📋 Post-Deployment

After terraform apply completes:

1. [ ] Note the instance IPs from output
2. [ ] SSH into instance to verify connectivity
3. [ ] Check CloudWatch logs for honeypot activity
4. [ ] Verify S3 bucket created
5. [ ] Test honeypot ports (21, 80, 2222, 2223, 23)

## 🔄 Next Phases

- [ ] Phase 3: Multi-region deployment (eu-west-1, ap-south-1)
- [ ] Phase 4: Threat intelligence enrichment
- [ ] Phase 5: Auto-rotation and multi-cloud

