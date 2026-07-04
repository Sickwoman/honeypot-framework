#!/usr/bin/env python3

################################################################################
# Slack Notification Service
# Sends honeypot alerts and reports to Slack
################################################################################

import requests
import json
import sys
import argparse
from datetime import datetime

class SlackNotifier:
    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url or self.get_webhook_from_env()
        if not self.webhook_url:
            print("❌ Error: Slack webhook URL not provided")
            sys.exit(1)
    
    @staticmethod
    def get_webhook_from_env():
        """Get webhook URL from environment variable"""
        import os
        return os.getenv('SLACK_WEBHOOK_URL')
    
    def send_message(self, text, color='#36a64f'):
        """Send simple text message"""
        payload = {
            'text': text
        }
        
        response = requests.post(self.webhook_url, json=payload)
        return response.status_code == 200
    
    def send_alert(self, title, message, severity='info'):
        """Send alert with formatting"""
        color_map = {
            'info': '#36a64f',      # Green
            'warning': '#ff9900',    # Orange
            'critical': '#ff0000'    # Red
        }
        
        payload = {
            'attachments': [
                {
                    'fallback': title,
                    'color': color_map.get(severity, '#36a64f'),
                    'title': f'🚨 {title}',
                    'text': message,
                    'ts': int(datetime.now().timestamp())
                }
            ]
        }
        
        response = requests.post(self.webhook_url, json=payload)
        return response.status_code == 200
    
    def send_report(self, report_data):
        """Send analytics report"""
        payload = {
            'attachments': [
                {
                    'fallback': 'Honeypot Daily Report',
                    'color': '#1f77b4',
                    'title': '📊 Honeypot Daily Report',
                    'fields': [
                        {
                            'title': 'Total Events',
                            'value': f"{report_data.get('total_events', 0):,}",
                            'short': True
                        },
                        {
                            'title': 'Top IP',
                            'value': report_data.get('top_ip', 'N/A'),
                            'short': True
                        },
                        {
                            'title': 'Credentials Captured',
                            'value': str(report_data.get('credentials', 0)),
                            'short': True
                        },
                        {
                            'title': 'High Risk IPs',
                            'value': str(report_data.get('high_risk_ips', 0)),
                            'short': True
                        }
                    ],
                    'ts': int(datetime.now().timestamp())
                }
            ]
        }
        
        response = requests.post(self.webhook_url, json=payload)
        return response.status_code == 200
    
    def send_high_risk_ip_alert(self, ip, threat_level, confidence_score):
        """Alert for high-risk IP detected"""
        payload = {
            'attachments': [
                {
                    'fallback': f'High Risk IP Detected: {ip}',
                    'color': '#ff0000',
                    'title': f'🔴 HIGH RISK IP DETECTED',
                    'fields': [
                        {
                            'title': 'IP Address',
                            'value': ip,
                            'short': True
                        },
                        {
                            'title': 'Threat Level',
                            'value': threat_level,
                            'short': True
                        },
                        {
                            'title': 'Confidence Score',
                            'value': f'{confidence_score}/100',
                            'short': True
                        },
                        {
                            'title': 'Action Required',
                            'value': 'Review and potentially block this IP',
                            'short': False
                        }
                    ],
                    'ts': int(datetime.now().timestamp())
                }
            ]
        }
        
        response = requests.post(self.webhook_url, json=payload)
        return response.status_code == 200
    
    def send_service_down_alert(self, service_name):
        """Alert when service is down"""
        payload = {
            'attachments': [
                {
                    'fallback': f'Service Down: {service_name}',
                    'color': '#ff0000',
                    'title': f'⛔ SERVICE DOWN: {service_name}',
                    'text': f'The {service_name} honeypot service is not responding',
                    'fields': [
                        {
                            'title': 'Service',
                            'value': service_name,
                            'short': True
                        },
                        {
                            'title': 'Time',
                            'value': datetime.now().isoformat(),
                            'short': True
                        },
                        {
                            'title': 'Action',
                            'value': 'Restart service or investigate',
                            'short': False
                        }
                    ]
                }
            ]
        }
        
        response = requests.post(self.webhook_url, json=payload)
        return response.status_code == 200

def main():
    parser = argparse.ArgumentParser(description='Slack Notification Service')
    parser.add_argument('--message', help='Send simple message')
    parser.add_argument('--alert', help='Send alert')
    parser.add_argument('--severity', default='info', choices=['info', 'warning', 'critical'])
    parser.add_argument('--high-risk-ip', help='Send high-risk IP alert with score')
    parser.add_argument('--service-down', help='Send service down alert')
    parser.add_argument('--webhook', help='Slack webhook URL')
    
    args = parser.parse_args()
    
    notifier = SlackNotifier(args.webhook)
    
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

