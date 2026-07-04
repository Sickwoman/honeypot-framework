#!/usr/bin/env python3

################################################################################
# Discord Notification Service
# Sends honeypot alerts and reports to Discord
################################################################################

import requests
import json
import sys
import argparse
from datetime import datetime

class DiscordNotifier:
    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url or self.get_webhook_from_env()
        if not self.webhook_url:
            print("❌ Error: Discord webhook URL not provided")
            sys.exit(1)
    
    @staticmethod
    def get_webhook_from_env():
        """Get webhook URL from environment variable"""
        import os
        return os.getenv('DISCORD_WEBHOOK_URL')
    
    def send_message(self, content):
        """Send simple text message"""
        payload = {
            'content': content
        }
        
        response = requests.post(self.webhook_url, json=payload)
        return response.status_code == 204
    
    def send_embed(self, title, description, color=3447003, fields=None):
        """Send embedded message"""
        embed = {
            'title': title,
            'description': description,
            'color': color,
            'timestamp': datetime.now().isoformat()
        }
        
        if fields:
            embed['fields'] = fields
        
        payload = {
            'embeds': [embed]
        }
        
        response = requests.post(self.webhook_url, json=payload)
        return response.status_code == 204
    
    def send_alert(self, title, message, severity='info'):
        """Send alert with color coding"""
        color_map = {
            'info': 3447003,        # Blue
            'warning': 15105570,    # Orange
            'critical': 15158332    # Red
        }
        
        return self.send_embed(
            f'🚨 {title}',
            message,
            color=color_map.get(severity, 3447003)
        )
    
    def send_report(self, report_data):
        """Send analytics report"""
        fields = [
            {
                'name': 'Total Events',
                'value': f"{report_data.get('total_events', 0):,}",
                'inline': True
            },
            {
                'name': 'Top IP',
                'value': report_data.get('top_ip', 'N/A'),
                'inline': True
            },
            {
                'name': 'Credentials Captured',
                'value': str(report_data.get('credentials', 0)),
                'inline': True
            },
            {
                'name': 'High Risk IPs',
                'value': str(report_data.get('high_risk_ips', 0)),
                'inline': True
            }
        ]
        
        return self.send_embed(
            '📊 Honeypot Daily Report',
            'Daily attack statistics and analysis',
            color=32768,
            fields=fields
        )
    
    def send_high_risk_ip_alert(self, ip, threat_level, confidence_score):
        """Alert for high-risk IP detected"""
        fields = [
            {
                'name': 'IP Address',
                'value': ip,
                'inline': True
            },
            {
                'name': 'Threat Level',
                'value': threat_level,
                'inline': True
            },
            {
                'name': 'Confidence Score',
                'value': f'{confidence_score}/100',
                'inline': True
            },
            {
                'name': 'Action',
                'value': 'Review and block if necessary',
                'inline': False
            }
        ]
        
        return self.send_embed(
            '🔴 HIGH RISK IP DETECTED',
            f'Malicious IP activity detected',
            color=15158332,
            fields=fields
        )
    
    def send_service_down_alert(self, service_name):
        """Alert when service is down"""
        fields = [
            {
                'name': 'Service',
                'value': service_name,
                'inline': True
            },
            {
                'name': 'Status',
                'value': '🔴 DOWN',
                'inline': True
            },
            {
                'name': 'Action Required',
                'value': 'Restart service or investigate',
                'inline': False
            }
        ]
        
        return self.send_embed(
            f'⛔ SERVICE DOWN: {service_name}',
            'A honeypot service has stopped responding',
            color=15158332,
            fields=fields
        )
    
    def send_attack_summary(self, summary_data):
        """Send attack summary"""
        fields = [
            {
                'name': 'Period',
                'value': summary_data.get('period', 'Last 24 hours'),
                'inline': True
            },
            {
                'name': 'Total Attacks',
                'value': str(summary_data.get('attacks', 0)),
                'inline': True
            },
            {
                'name': 'Unique IPs',
                'value': str(summary_data.get('unique_ips', 0)),
                'inline': True
            },
            {
                'name': 'Most Targeted Service',
                'value': summary_data.get('top_service', 'SSH'),
                'inline': True
            }
        ]
        
        return self.send_embed(
            '📈 Attack Summary',
            'Honeypot activity report',
            color=65535,
            fields=fields
        )

def main():
    parser = argparse.ArgumentParser(description='Discord Notification Service')
    parser.add_argument('--message', help='Send simple message')
    parser.add_argument('--alert', help='Send alert')
    parser.add_argument('--severity', default='info', choices=['info', 'warning', 'critical'])
    parser.add_argument('--high-risk-ip', help='Send high-risk IP alert')
    parser.add_argument('--service-down', help='Send service down alert')
    parser.add_argument('--webhook', help='Discord webhook URL')
    
    args = parser.parse_args()
    
    notifier = DiscordNotifier(args.webhook)
    
    if args.message:
        success = notifier.send_message(args.message)
        print("✅ Message sent" if success else "❌ Failed to send message")
    
    elif args.alert:
        success = notifier.send_alert(args.alert, args.alert, args.severity)
        print("✅ Alert sent" if success else "❌ Failed to send alert")
    
    elif args.high_risk_ip:
        ip, score = args.high_risk_ip.split(',')
        success = notifier.send_high_risk_ip_alert(ip, 'HIGH', int(score))
        print("✅ IP alert sent" if success else "❌ Failed to send IP alert")
    
    elif args.service_down:
        success = notifier.send_service_down_alert(args.service_down)
        print("✅ Service alert sent" if success else "❌ Failed to send service alert")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

