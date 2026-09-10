#!/usr/bin/env python3

################################################################################
# Email Notification Service
# Sends honeypot alerts and reports via email
################################################################################

import argparse
import os
import smtplib
import sys
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class EmailNotifier:
    def __init__(self, smtp_server=None, smtp_port=587, sender=None, password=None):
        self.smtp_server = smtp_server or os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = smtp_port or int(os.getenv('SMTP_PORT', '587'))
        self.sender = sender or os.getenv('EMAIL_SENDER')
        self.password = password or os.getenv('EMAIL_PASSWORD')
        
        if not all([self.sender, self.password]):
            print("❌ Error: Email credentials not provided")
            print("Set: EMAIL_SENDER, EMAIL_PASSWORD, SMTP_SERVER, SMTP_PORT")
            sys.exit(1)
    
    def send_email(self, recipient, subject, html_content):
        """Send email with HTML content"""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.sender
            msg['To'] = recipient
            msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')
            
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender, self.password)
                server.sendmail(self.sender, recipient, msg.as_string())
            
            return True
        except Exception as e:
            print(f"❌ Error sending email: {e}")
            return False
    
    def send_alert(self, recipient, title, message, severity='info'):
        """Send alert email"""
        color_map = {
            'info': '#36a64f',
            'warning': '#ff9900',
            'critical': '#ff0000'
        }
        
        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background-color: {color_map.get(severity, '#36a64f')}; 
                                color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px;">
                        <h2 style="margin: 0;">🚨 {title}</h2>
                    </div>
                    <div style="padding: 20px; background-color: #f5f5f5; border-radius: 5px;">
                        <p>{message}</p>
                        <p style="color: #666; font-size: 12px;">
                            Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                        </p>
                    </div>
                </div>
            </body>
        </html>
        """
        
        return self.send_email(recipient, f"🚨 Alert: {title}", html_content)
    
    def send_daily_report(self, recipient, report_data):
        """Send daily report email"""
        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background-color: #1f77b4; color: white; padding: 20px; 
                                border-radius: 5px; margin-bottom: 20px;">
                        <h2 style="margin: 0;">📊 Honeypot Daily Report</h2>
                        <p style="margin: 10px 0 0 0;">{datetime.now().strftime('%Y-%m-%d')}</p>
                    </div>
                    
                    <div style="padding: 20px; background-color: #f5f5f5; border-radius: 5px; margin-bottom: 20px;">
                        <h3>Summary</h3>
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr style="background-color: #e8e8e8;">
                                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Metric</strong></td>
                                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Value</strong></td>
                            </tr>
                            <tr>
                                <td style="padding: 10px; border: 1px solid #ddd;">Total Events</td>
                                <td style="padding: 10px; border: 1px solid #ddd;">{report_data.get('total_events', 0):,}</td>
                            </tr>
                            <tr style="background-color: #f9f9f9;">
                                <td style="padding: 10px; border: 1px solid #ddd;">Top Attacking IP</td>
                                <td style="padding: 10px; border: 1px solid #ddd;">{report_data.get('top_ip', 'N/A')}</td>
                            </tr>
                            <tr>
                                <td style="padding: 10px; border: 1px solid #ddd;">Credentials Captured</td>
                                <td style="padding: 10px; border: 1px solid #ddd;">{report_data.get('credentials', 0)}</td>
                            </tr>
                            <tr style="background-color: #f9f9f9;">
                                <td style="padding: 10px; border: 1px solid #ddd;">High Risk IPs</td>
                                <td style="padding: 10px; border: 1px solid #ddd;">{report_data.get('high_risk_ips', 0)}</td>
                            </tr>
                        </table>
                    </div>
                    
                    <div style="padding: 20px; background-color: #fffacd; border-radius: 5px; margin-bottom: 20px;">
                        <h3>Actions Recommended</h3>
                        <ul>
                            <li>Review top attacking IPs</li>
                            <li>Check for patterns in attacks</li>
                            <li>Update security rules if needed</li>
                            <li>Monitor threat intelligence scores</li>
                        </ul>
                    </div>
                    
                    <div style="text-align: center; color: #666; font-size: 12px; padding-top: 20px;">
                        <p>Honeypot Framework | Automated Report</p>
                    </div>
                </div>
            </body>
        </html>
        """
        
        return self.send_email(recipient, "📊 Honeypot Daily Report", html_content)
    
    def send_high_risk_ip_alert(self, recipient, ip, threat_level, confidence_score):
        """Send high-risk IP alert"""
        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background-color: #ff0000; color: white; padding: 20px; 
                                border-radius: 5px; margin-bottom: 20px;">
                        <h2 style="margin: 0;">🔴 HIGH RISK IP DETECTED</h2>
                    </div>
                    
                    <div style="padding: 20px; background-color: #ffe0e0; border-radius: 5px; margin-bottom: 20px;">
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr>
                                <td style="padding: 10px;"><strong>IP Address:</strong></td>
                                <td style="padding: 10px; color: #ff0000; font-weight: bold;">{ip}</td>
                            </tr>
                            <tr>
                                <td style="padding: 10px;"><strong>Threat Level:</strong></td>
                                <td style="padding: 10px;">{threat_level}</td>
                            </tr>
                            <tr>
                                <td style="padding: 10px;"><strong>Confidence Score:</strong></td>
                                <td style="padding: 10px;">{confidence_score}/100</td>
                            </tr>
                            <tr>
                                <td style="padding: 10px;"><strong>Detected:</strong></td>
                                <td style="padding: 10px;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
                            </tr>
                        </table>
                    </div>
                    
                    <div style="padding: 20px; background-color: #fff0f0; border-radius: 5px;">
                        <h3>⚠️ Recommended Actions:</h3>
                        <ul>
                            <li>Review attack patterns from this IP</li>
                            <li>Consider blocking this IP</li>
                            <li>Check threat intelligence databases</li>
                            <li>Implement geo-blocking if applicable</li>
                        </ul>
                    </div>
                </div>
            </body>
        </html>
        """
        
        return self.send_email(recipient, f"🔴 HIGH RISK IP: {ip}", html_content)

def main():
    parser = argparse.ArgumentParser(description='Email Notification Service')
    parser.add_argument('--recipient', required=True, help='Email recipient')
    parser.add_argument('--alert', help='Send alert')
    parser.add_argument('--daily-report', action='store_true', help='Send daily report')
    parser.add_argument('--high-risk-ip', help='Send high-risk IP alert')
    parser.add_argument('--severity', default='info', choices=['info', 'warning', 'critical'])
    
    args = parser.parse_args()
    
    notifier = EmailNotifier()
    
    if args.alert:
        success = notifier.send_alert(args.recipient, args.alert, args.alert, args.severity)
        print("✅ Alert sent" if success else "❌ Failed to send alert")
    
    elif args.daily_report:
        report_data = {
            'total_events': 103,
            'top_ip': '192.168.1.1',
            'credentials': 5,
            'high_risk_ips': 3
        }
        success = notifier.send_daily_report(args.recipient, report_data)
        print("✅ Report sent" if success else "❌ Failed to send report")
    
    elif args.high_risk_ip:
        ip, score = args.high_risk_ip.split(',')
        success = notifier.send_high_risk_ip_alert(args.recipient, ip, 'HIGH', int(score))
        print("✅ IP alert sent" if success else "❌ Failed to send IP alert")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

