#!/usr/bin/env python3

################################################################################
# Automated Reports Generation Script
# Generates daily/weekly/monthly attack reports
################################################################################

import requests
import json
from datetime import datetime, timedelta
from jinja2 import Template
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

class ReportGenerator:
    def __init__(self, es_url="https://localhost:9200", 
                 username="elastic", password="changeme"):
        self.es_url = es_url
        self.username = username
        self.password = password
        self.verify_ssl = False
        
    def get_attack_statistics(self, period="24h"):
        """Get attack statistics for given period"""
        try:
            response = requests.get(
                f"{self.es_url}/honeypot-*/_search",
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                json={
                    "query": {
                        "range": {
                            "@timestamp": {"gte": f"now-{period}"}
                        }
                    },
                    "aggs": {
                        "total_attacks": {"value_count": {"field": "_id"}},
                        "top_ips": {
                            "terms": {"field": "src_ip", "size": 10}
                        },
                        "by_service": {
                            "terms": {"field": "service", "size": 10}
                        },
                        "by_country": {
                            "terms": {"field": "geoip.country_name", "size": 10}
                        },
                        "failed_logins": {
                            "filter": {
                                "term": {"event_type": "login_attempt"}
                            }
                        }
                    },
                    "size": 0
                }
            )
            return response.json()
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return None
    
    def generate_html_report(self, stats, period="24h"):
        """Generate HTML report"""
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Honeypot Attack Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
                .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .section { background-color: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .metric { display: inline-block; width: 45%; margin: 10px; padding: 15px; background-color: #ecf0f1; border-radius: 5px; }
                .metric-value { font-size: 32px; font-weight: bold; color: #e74c3c; }
                .metric-label { color: #7f8c8d; font-size: 14px; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #34495e; color: white; }
                tr:hover { background-color: #f5f5f5; }
                .alert { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 10px 0; }
                .success { background-color: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin: 10px 0; }
                .danger { background-color: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin: 10px 0; }
                .footer { text-align: center; color: #7f8c8d; font-size: 12px; margin-top: 40px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🍯 Honeypot Attack Report</h1>
                <p>Period: {{ period }} | Generated: {{ date }}</p>
            </div>
            
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <div class="metric">
                    <div class="metric-value">{{ total_attacks }}</div>
                    <div class="metric-label">Total Attacks</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{{ unique_ips }}</div>
                    <div class="metric-label">Unique IPs</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{{ top_country }}</div>
                    <div class="metric-label">Top Attack Country</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{{ failed_logins }}</div>
                    <div class="metric-label">Failed Login Attempts</div>
                </div>
            </div>
            
            <div class="section">
                <h2>🎯 Top Attacking IPs</h2>
                <table>
                    <tr>
                        <th>IP Address</th>
                        <th>Attack Count</th>
                        <th>Country</th>
                    </tr>
                    {% for ip in top_ips %}
                    <tr>
                        <td>{{ ip.ip }}</td>
                        <td>{{ ip.count }}</td>
                        <td>{{ ip.country }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            
            <div class="section">
                <h2>📡 Attacks by Service</h2>
                <table>
                    <tr>
                        <th>Service</th>
                        <th>Attack Count</th>
                        <th>Percentage</th>
                    </tr>
                    {% for service in services %}
                    <tr>
                        <td>{{ service.name }}</td>
                        <td>{{ service.count }}</td>
                        <td>{{ service.percentage }}%</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            
            <div class="section">
                <h2>⚠️ Security Alerts</h2>
                {% if high_risk_ips %}
                <div class="danger">
                    <strong>🚨 High Risk IPs Detected</strong>
                    {% for ip in high_risk_ips %}
                    <div>{{ ip }} - {{ ip_risk[ip] }} incidents</div>
                    {% endfor %}
                </div>
                {% endif %}
                
                {% if malware_attempts %}
                <div class="alert">
                    <strong>⚠️ Malware Download Attempts</strong>
                    <div>{{ malware_attempts }} attempts detected</div>
                </div>
                {% endif %}
                
                <div class="success">
                    <strong>✅ All honeypots operational</strong>
                    <div>No service outages detected</div>
                </div>
            </div>
            
            <div class="section">
                <h2>📈 Recommendations</h2>
                <ul>
                    <li>Monitor top attacking IPs for patterns</li>
                    <li>Review failed login attempts for brute force attacks</li>
                    <li>Investigate any new services being targeted</li>
                    <li>Check geographic distribution for anomalies</li>
                    <li>Maintain honeypot infrastructure updates</li>
                </ul>
            </div>
            
            <div class="footer">
                <p>This report was automatically generated by Honeypot Framework</p>
                <p>For more information, visit: https://github.com/Sickwoman/honeypot-framework</p>
            </div>
        </body>
        </html>
        """
        
        template = Template(html_template)
        html = template.render(
            period=period,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_attacks=stats.get('total_attacks', 0),
            unique_ips=len(stats.get('top_ips', [])),
            top_country=stats.get('top_country', 'N/A'),
            failed_logins=stats.get('failed_logins', 0),
            top_ips=stats.get('top_ips', []),
            services=stats.get('services', []),
            high_risk_ips=stats.get('high_risk_ips', []),
            malware_attempts=stats.get('malware_attempts', 0),
            ip_risk=stats.get('ip_risk', {})
        )
        return html
    
    def generate_json_report(self, stats, period="24h"):
        """Generate JSON report"""
        report = {
            "generated": datetime.now().isoformat(),
            "period": period,
            "statistics": stats
        }
        return json.dumps(report, indent=2)
    
    def save_report(self, content, filename, format="html"):
        """Save report to file"""
        filepath = f"/tmp/honeypot-report-{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
        
        with open(filepath, 'w') as f:
            f.write(content)
        
        print(f"✅ Report saved: {filepath}")
        return filepath
    
    def send_email_report(self, html_content, recipient, subject="Honeypot Attack Report"):
        """Send report via email"""
        try:
            sender = os.getenv('REPORT_EMAIL_FROM', 'honeypot@example.com')
            password = os.getenv('REPORT_EMAIL_PASSWORD', '')
            smtp_server = os.getenv('REPORT_SMTP_SERVER', 'smtp.gmail.com')
            smtp_port = int(os.getenv('REPORT_SMTP_PORT', '587'))
            
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = sender
            message['To'] = recipient
            
            part = MIMEText(html_content, 'html')
            message.attach(part)
            
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender, password)
                server.send_message(message)
            
            print(f"✅ Email sent to {recipient}")
            return True
        except Exception as e:
            print(f"❌ Error sending email: {e}")
            return False
    
    def generate_daily_report(self):
        """Generate daily report"""
        print("📊 Generating daily report...")
        stats = self.get_attack_statistics("24h")
        
        if stats:
            html = self.generate_html_report(stats, "24 hours")
            json_report = self.generate_json_report(stats, "24h")
            
            self.save_report(html, "daily-report", "html")
            self.save_report(json_report, "daily-report", "json")
            
            # Send email if configured
            recipient = os.getenv('REPORT_EMAIL_TO')
            if recipient:
                self.send_email_report(html, recipient, "Daily Honeypot Attack Report")
    
    def generate_weekly_report(self):
        """Generate weekly report"""
        print("📊 Generating weekly report...")
        stats = self.get_attack_statistics("7d")
        
        if stats:
            html = self.generate_html_report(stats, "7 days")
            json_report = self.generate_json_report(stats, "7d")
            
            self.save_report(html, "weekly-report", "html")
            self.save_report(json_report, "weekly-report", "json")
            
            recipient = os.getenv('REPORT_EMAIL_TO')
            if recipient:
                self.send_email_report(html, recipient, "Weekly Honeypot Attack Report")
    
    def generate_monthly_report(self):
        """Generate monthly report"""
        print("📊 Generating monthly report...")
        stats = self.get_attack_statistics("30d")
        
        if stats:
            html = self.generate_html_report(stats, "30 days")
            json_report = self.generate_json_report(stats, "30d")
            
            self.save_report(html, "monthly-report", "html")
            self.save_report(json_report, "monthly-report", "json")
            
            recipient = os.getenv('REPORT_EMAIL_TO')
            if recipient:
                self.send_email_report(html, recipient, "Monthly Honeypot Attack Report")

def main():
    import sys
    
    generator = ReportGenerator()
    
    if len(sys.argv) < 2:
        print("Usage: generate-reports.py [daily|weekly|monthly|all]")
        sys.exit(1)
    
    report_type = sys.argv[1]
    
    if report_type == "daily":
        generator.generate_daily_report()
    elif report_type == "weekly":
        generator.generate_weekly_report()
    elif report_type == "monthly":
        generator.generate_monthly_report()
    elif report_type == "all":
        generator.generate_daily_report()
        generator.generate_weekly_report()
        generator.generate_monthly_report()
    else:
        print("Invalid report type. Use: daily, weekly, monthly, or all")
        sys.exit(1)

if __name__ == "__main__":
    main()

