#!/bin/bash
set -e

echo "Starting honeypot initialization on $(date)"

# Update system
apt-get update
apt-get install -y python3 python3-pip git curl wget

# Install Cowrie SSH honeypot
echo "Installing Cowrie..."
useradd -m -s /bin/bash cowrie || true
su - cowrie << 'COWRIE_INSTALL'
git clone https://github.com/cowrie/cowrie.git || true
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install -q -r requirements.txt
cp etc/cowrie.cfg.dist etc/cowrie.cfg
sed -i 's/hostname = .*/hostname = webserver01/' etc/cowrie.cfg
./bin/cowrie start
COWRIE_INSTALL

echo "Cowrie started"

# Install OpenCanary multi-service honeypot
echo "Installing OpenCanary..."
pip3 install opencanary --break-system-packages
opencanaryd --copyconfig || true
opencanaryd --start

echo "OpenCanary started"

# Install CloudWatch agent for centralized logging
echo "Installing CloudWatch agent..."
wget -q https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i -E ./amazon-cloudwatch-agent.deb

echo "Honeypot initialization complete on $(date)"
