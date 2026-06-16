# Systemd Services Documentation

## Overview

Three systemd services manage the honeypot framework:
- **cowrie.service** — SSH honeypot (port 2222)
- **opencanary.service** — Multi-service honeypot (ports 21, 80, 3306, 2223, 23)
- **elk-stack.service** — Log visualization (Docker Compose)

All services auto-start on boot and auto-restart on failure.

## Service Management

### Start Services
```bash
sudo systemctl start cowrie.service
sudo systemctl start opencanary.service
sudo systemctl start elk-stack.service

# Or start all at once
sudo systemctl start cowrie opencanary elk-stack
```

### Stop Services
```bash
sudo systemctl stop cowrie.service
sudo systemctl stop opencanary.service
sudo systemctl stop elk-stack.service
```

### Check Status
```bash
sudo systemctl status cowrie.service
sudo systemctl status opencanary.service
sudo systemctl status elk-stack.service

# Or check all
sudo systemctl status cowrie opencanary elk-stack
```

### View Logs
```bash
# Real-time logs
sudo journalctl -u cowrie.service -f
sudo journalctl -u opencanary.service -f
sudo journalctl -u elk-stack.service -f

# Last N entries
sudo journalctl -u cowrie.service -n 50
sudo journalctl -u opencanary.service -n 50
sudo journalctl -u elk-stack.service -n 50

# Logs since last boot
sudo journalctl -u cowrie.service -b
sudo journalctl -u opencanary.service -b
sudo journalctl -u elk-stack.service -b
```

### Enable/Disable Auto-start
```bash
# Enable (start on boot)
sudo systemctl enable cowrie.service

# Disable (don't start on boot)
sudo systemctl disable cowrie.service

# Check if enabled
sudo systemctl is-enabled cowrie.service
```

### Restart Services
```bash
sudo systemctl restart cowrie.service
sudo systemctl restart opencanary.service
sudo systemctl restart elk-stack.service
```

### Reload Configuration (without restart)
```bash
sudo systemctl reload cowrie.service
sudo systemctl reload opencanary.service
```

## Service Files Location
