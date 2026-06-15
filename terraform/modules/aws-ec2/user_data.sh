#!/bin/bash
set -e

echo "Starting honeypot initialization..."

# Update system
apt-get update
apt-get install -y python3 python3-pip git curl wget

# Install Cowrie
useradd -m -s /bin/bash cowrie || true
su - cowrie << 'COWRIE_SETUP'
git clone https://github.com/cowrie/cowrie.git || true
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install -q -r requirements.txt
cp etc/cowrie.cfg.dist etc/cowrie.cfg
sed -i 's/hostname = .*/hostname = webserver01/' etc/cowrie.cfg
COWRIE_SETUP

# Install OpenCanary
pip3 install opencanary --break-system-packages
opencanaryd --copyconfig || true

# Install CloudWatch agent
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i -E ./amazon-cloudwatch-agent.deb

echo "Honeypot initialization complete"
