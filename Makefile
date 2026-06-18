.PHONY: help install deploy start stop restart logs test backup restore clean validate

# Variables
PROJECT_NAME := honeypot-framework
PYTHON := python3
PIP := pip3
TERRAFORM_DIR := terraform/environments/aws-us-east

help:
	@echo "🍯 $(PROJECT_NAME) - Makefile Commands"
	@echo ""
	@echo "Local Lab Commands:"
	@echo "  make install      - Install all dependencies"
	@echo "  make deploy       - Start all local honeypot services"
	@echo "  make start        - Start honeypot services"
	@echo "  make stop         - Stop honeypot services"
	@echo "  make restart      - Restart all services"
	@echo "  make logs         - View service logs"
	@echo "  make status       - Check service status"
	@echo "  make health       - Run health check"
	@echo ""
	@echo "Testing Commands:"
	@echo "  make test         - Run attack simulations"
	@echo "  make estimate     - Estimate AWS costs"
	@echo ""
	@echo "Backup & Restore:"
	@echo "  make backup       - Backup all data"
	@echo "  make restore      - Restore from backup"
	@echo ""
	@echo "AWS Deployment:"
	@echo "  make terraform-init    - Initialize Terraform"
	@echo "  make terraform-plan    - Plan AWS deployment"
	@echo "  make terraform-apply   - Deploy to AWS"
	@echo "  make terraform-destroy - Destroy AWS resources"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean        - Clean temporary files"
	@echo "  make clean-all    - Remove all data and containers"
	@echo ""

install:
	@echo "📦 Installing dependencies..."
	sudo apt update
	sudo apt install -y python3 python3-pip git curl wget
	sudo apt install -y docker.io docker-compose
	sudo apt install -y terraform awscli
	sudo apt install -y netcat-openbsd sshpass
	@echo "✅ Dependencies installed"

deploy:
	@echo "🚀 Deploying honeypot framework..."
	chmod +x scripts/deploy.sh
	./scripts/deploy.sh

start:
	@echo "▶️  Starting services..."
	sudo systemctl start cowrie.service
	sudo systemctl start opencanary.service
	sudo systemctl start elk-stack.service
	@echo "✅ Services started"

stop:
	@echo "⏹️  Stopping services..."
	sudo systemctl stop cowrie.service
	sudo systemctl stop opencanary.service
	sudo systemctl stop elk-stack.service
	@echo "✅ Services stopped"

restart:
	@echo "🔄 Restarting services..."
	sudo systemctl restart cowrie.service
	sudo systemctl restart opencanary.service
	sudo systemctl restart elk-stack.service
	@echo "✅ Services restarted"

status:
	@echo "📊 Service Status:"
	@sudo systemctl status cowrie.service --no-pager | head -5
	@echo ""
	@sudo systemctl status opencanary.service --no-pager | head -5
	@echo ""
	@sudo systemctl status elk-stack.service --no-pager | head -5

logs:
	@echo "📋 Service Logs:"
	@echo ""
	@echo "=== Cowrie Logs ==="
	@sudo journalctl -u cowrie.service -n 10 --no-pager
	@echo ""
	@echo "=== OpenCanary Logs ==="
	@sudo journalctl -u opencanary.service -n 10 --no-pager
	@echo ""
	@echo "=== ELK Stack Logs ==="
	@sudo journalctl -u elk-stack.service -n 10 --no-pager

health:
	@echo "🏥 Running health check..."
	chmod +x scripts/check-services.sh
	./scripts/check-services.sh

test:
	@echo "🎯 Running attack simulations..."
	chmod +x scripts/simulate-attacks.sh
	./scripts/simulate-attacks.sh

estimate:
	@echo "💰 Estimating AWS costs..."
	$(PYTHON) scripts/estimate-aws-costs.py

backup:
	@echo "💾 Creating backup..."
	chmod +x scripts/backup-honeypot.sh
	./scripts/backup-honeypot.sh

restore:
	@echo "🔄 Restoring from backup..."
	chmod +x scripts/restore-honeypot.sh
	@read -p "Enter backup file path: " BACKUP_FILE; \
	./scripts/restore-honeypot.sh $$BACKUP_FILE

terraform-init:
	@echo "🔧 Initializing Terraform..."
	cd $(TERRAFORM_DIR) && terraform init

terraform-plan:
	@echo "📋 Planning AWS deployment..."
	cd $(TERRAFORM_DIR) && terraform plan -var-file=terraform.tfvars

terraform-apply:
	@echo "🚀 Deploying to AWS..."
	cd $(TERRAFORM_DIR) && terraform apply -var-file=terraform.tfvars

terraform-destroy:
	@echo "⚠️  WARNING: This will delete all AWS resources!"
	@read -p "Continue? (yes/no): " CONFIRM; \
	if [ "$$CONFIRM" = "yes" ]; then \
		cd $(TERRAFORM_DIR) && terraform destroy -var-file=terraform.tfvars; \
	fi

validate:
	@echo "✅ Validating Terraform..."
	cd terraform/environments/local && terraform validate
	cd ~/Desktop/honeypot-framework/terraform/environments/aws-us-east && terraform validate
	@echo "✅ All configurations valid"

clean:
	@echo "🧹 Cleaning temporary files..."
	find . -type d -name ".terraform" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name ".terraform.lock.hcl" -delete
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ Cleanup complete"

clean-all: clean
	@echo "🗑️  WARNING: Removing all data and containers!"
	@read -p "Continue? (yes/no): " CONFIRM; \
	if [ "$$CONFIRM" = "yes" ]; then \
		docker-compose -f ~/elk-stack/docker-compose.yml down -v; \
		sudo systemctl stop cowrie opencanary elk-stack; \
		rm -rf ~/honeypot-backups/*; \
		@echo "✅ All data removed"; \
	fi

.DEFAULT_GOAL := help
