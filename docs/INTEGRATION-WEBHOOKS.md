# Integration & Webhooks Guide

## Overview

Integrate honeypot alerts and reports with Slack, Discord, Email, and custom webhooks.

---

## 1. Slack Integration

### Get Slack Webhook URL

1. Go to: https://api.slack.com/apps
2. Create New App → From scratch
3. Name: "Honeypot Framework"
4. Choose workspace
5. Go to "Incoming Webhooks"
6. Click "Add New Webhook to Workspace"
7. Select channel (e.g., #security-alerts)
8. Copy Webhook URL

### Set Environment Variable

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

### Send Messages

```bash
# Simple message
python3 scripts/slack-notifier.py --message "Test message" --webhook "$SLACK_WEBHOOK_URL"

# Alert
python3 scripts/slack-notifier.py --alert "High Risk IP Detected" --severity critical

# High-risk IP alert
python3 scripts/slack-notifier.py --high-risk-ip "192.168.1.1,85" --webhook "$SLACK_WEBHOOK_URL"

# Service down alert
python3 scripts/slack-notifier.py --service-down "Cowrie SSH" --webhook "$SLACK_WEBHOOK_URL"
```

---

## 2. Discord Integration

### Get Discord Webhook URL

1. Open Discord server
2. Go to Channel Settings → Integrations → Webhooks
3. Click "New Webhook"
4. Name: "Honeypot Framework"
5. Copy Webhook URL

### Set Environment Variable

```bash
export DISCORD_WEBHOOK_URL="https://discordapp.com/api/webhooks/YOUR/WEBHOOK/URL"
```

### Send Messages

```bash
# Simple message
python3 scripts/discord-notifier.py --message "Test message" --webhook "$DISCORD_WEBHOOK_URL"

# Alert
python3 scripts/discord-notifier.py --alert "Attack Detected" --severity warning

# High-risk IP alert
python3 scripts/discord-notifier.py --high-risk-ip "192.168.1.1,85" --webhook "$DISCORD_WEBHOOK_URL"

# Service down alert
python3 scripts/discord-notifier.py --service-down "OpenCanary" --webhook "$DISCORD_WEBHOOK_URL"
```

---

## 3. Email Integration

### Gmail Setup

1. Enable 2-Factor Authentication in Gmail
2. Go to: https://myaccount.google.com/apppasswords
3. Generate app password for "Mail" and "Windows Computer"
4. Copy the 16-character password

### Set Environment Variables

```bash
export EMAIL_SENDER="your-email@gmail.com"
export EMAIL_PASSWORD="your-app-password"
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT="587"
```

### Send Emails

```bash
# Send alert
python3 scripts/email-notifier.py \
  --recipient "security-team@example.com" \
  --alert "High Risk IP Detected" \
  --severity critical

# Send daily report
python3 scripts/email-notifier.py \
  --recipient "security-team@example.com" \
  --daily-report

# Send high-risk IP alert
python3 scripts/email-notifier.py \
  --recipient "security-team@example.com" \
  --high-risk-ip "192.168.1.1,85"
```

---

## 4. Automated Alert Scheduling

### Add to Cron Jobs

```bash
# Daily report to Slack (9:00 AM)
0 9 * * * python3 ~/Desktop/honeypot-framework/scripts/slack-notifier.py \
  --message "Daily Report Generated" --webhook "$SLACK_WEBHOOK_URL"

# Hourly health check to Discord (on the hour)
0 * * * * python3 ~/Desktop/honeypot-framework/scripts/discord-notifier.py \
  --message "Health Check: All systems operational" --webhook "$DISCORD_WEBHOOK_URL"

# High-risk IP alerts to Email (every 30 minutes)
*/30 * * * * python3 ~/Desktop/honeypot-framework/scripts/email-notifier.py \
  --recipient "security-team@example.com" --daily-report
```

---

## 5. Custom Webhook Integration

### Create Custom Webhook Handler

```bash
cat > scripts/custom-webhook.sh << 'EOFWEBHOOK'
#!/bin/bash

WEBHOOK_URL=$1
EVENT_TYPE=$2
EVENT_DATA=$3

curl -X POST $WEBHOOK_URL \
  -H 'Content-Type: application/json' \
  -d "{
    \"event_type\": \"$EVENT_TYPE\",
    \"timestamp\": \"$(date -Iseconds)\",
    \"data\": $EVENT_DATA
  }"

EOFWEBHOOK

chmod +x scripts/custom-webhook.sh
```

### Send Custom Webhook

```bash
./scripts/custom-webhook.sh \
  "https://your-server.com/webhook" \
  "attack_detected" \
  '{"ip":"192.168.1.1","severity":"high"}'
```

---

## 6. Integration Testing

### Test Slack

```bash
python3 scripts/slack-notifier.py \
  --alert "Test Alert" \
  --severity info \
  --webhook "$SLACK_WEBHOOK_URL"
```

### Test Discord

```bash
python3 scripts/discord-notifier.py \
  --message "Test from Honeypot Framework" \
  --webhook "$DISCORD_WEBHOOK_URL"
```

### Test Email

```bash
python3 scripts/email-notifier.py \
  --recipient "your-email@gmail.com" \
  --alert "Test Alert" \
  --severity info
```

---

## 7. Real-World Scenarios

### Alert on High-Risk IP

```bash
# When AbuseIPDB reports HIGH risk IP
python3 scripts/slack-notifier.py \
  --high-risk-ip "203.0.113.42,92" \
  --webhook "$SLACK_WEBHOOK_URL"

# And send to email
python3 scripts/email-notifier.py \
  --recipient "security-team@example.com" \
  --high-risk-ip "203.0.113.42,92"
```

### Alert on Service Down

```bash
# When health check fails
python3 scripts/discord-notifier.py \
  --service-down "Cowrie SSH Honeypot" \
  --webhook "$DISCORD_WEBHOOK_URL"
```

### Send Daily Report

```bash
# Combine with analytics script
python3 scripts/slack-notifier.py \
  --message "Daily honeypot report available" \
  --webhook "$SLACK_WEBHOOK_URL"
```

---

## 8. Troubleshooting

### Webhook not working

```bash
# Test webhook URL manually
curl -X POST "$SLACK_WEBHOOK_URL" \
  -H 'Content-Type: application/json' \
  -d '{"text":"Test message"}'

# Check response (should be empty or "ok")
```

### Email not sending

```bash
# Verify credentials
echo $EMAIL_SENDER
echo $EMAIL_PASSWORD

# Test SMTP connection
python3 -c "
import smtplib
server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login('$EMAIL_SENDER', '$EMAIL_PASSWORD')
print('Connection successful')
server.quit()
"
```

### Missing dependencies

```bash
pip3 install requests --break-system-packages
```

---

## 9. Environment Setup

### Add to ~/.bashrc or ~/.zshrc

```bash
# Slack
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Discord
export DISCORD_WEBHOOK_URL="https://discordapp.com/api/webhooks/YOUR/WEBHOOK/URL"

# Email
export EMAIL_SENDER="your-email@gmail.com"
export EMAIL_PASSWORD="your-app-password"
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT="587"
```

Then reload:
```bash
source ~/.bashrc
# or
source ~/.zshrc
```

---

## 10. Quick Reference

| Service | Setup | Command |
|---------|-------|---------|
| Slack | Get webhook | `slack-notifier.py` |
| Discord | Get webhook | `discord-notifier.py` |
| Email | Gmail app password | `email-notifier.py` |
| Custom | Your endpoint | `custom-webhook.sh` |

