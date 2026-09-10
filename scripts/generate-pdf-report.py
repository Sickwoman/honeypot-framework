#!/usr/bin/env python3

################################################################################
# PDF Report Generator
# Generates professional PDF reports from analytics data
################################################################################

import json
from datetime import datetime, timedelta
import argparse

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
except ImportError:
    print("❌ reportlab not installed. Install with: pip3 install reportlab")
    exit(1)

import es_client

class PDFReportGenerator:
    def __init__(self, es_host=None, username=None, password=None):
        self.es = es_client.build_client(
            es_host,
            basic_auth=(username or es_client.username(),
                        password or es_client.password()),
        )
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
    
    def setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f77b4'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#1f77b4'),
            spaceAfter=12,
            spaceBefore=12
        )
    
    def get_analytics_data(self, days=1):
        """Fetch analytics data from Elasticsearch"""
        data = {
            'total_events': 0,
            'credentials_captured': 0,
            'top_ips': [],
            'services': {},
            'threat_stats': {}
        }
        
        try:
            # Total events
            response = self.es.search(
                index="honeypot-*",
                body={
                    "query": {
                        "range": {"@timestamp": {"gte": f"now-{days}d"}}
                    }
                },
                size=0
            )
            data['total_events'] = response['hits']['total']['value']
            
            # Top IPs
            response = self.es.search(
                index="honeypot-*",
                body={
                    "query": {
                        "range": {"@timestamp": {"gte": f"now-{days}d"}}
                    },
                    "size": 0,
                    "aggs": {
                        "top_ips": {
                            "terms": {
                                "field": "src_ip",
                                "size": 10,
                                "order": {"_count": "desc"}
                            }
                        }
                    }
                }
            )
            
            for bucket in response['aggregations']['top_ips']['buckets']:
                data['top_ips'].append({
                    'ip': bucket['key'],
                    'count': bucket['doc_count']
                })
            
            # Services
            response = self.es.search(
                index="honeypot-*",
                body={
                    "query": {
                        "range": {"@timestamp": {"gte": f"now-{days}d"}}
                    },
                    "size": 0,
                    "aggs": {
                        "services": {
                            "terms": {
                                "field": "service",
                                "size": 20
                            }
                        }
                    }
                }
            )
            
            for bucket in response['aggregations']['services']['buckets']:
                data['services'][bucket['key']] = bucket['doc_count']
            
            # Credentials
            response = self.es.search(
                index="honeypot-*",
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
                                {"exists": {"field": "logdata.PASSWORD"}}
                            ]
                        }
                    }
                },
                size=0
            )
            data['credentials_captured'] = response['hits']['total']['value']
            
            return data
        except Exception as e:
            print(f"❌ Error fetching data: {e}")
            return data
    
    def build_title_page(self, story, days):
        """Build title page"""
        story.append(Spacer(1, 1.5*inch))
        
        title = Paragraph("🍯 HONEYPOT SECURITY REPORT", self.title_style)
        story.append(title)
        
        story.append(Spacer(1, 0.3*inch))
        
        date_text = Paragraph(
            f"<b>Report Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>" +
            f"<b>Analysis Period:</b> Last {days} day(s)<br/>" +
            f"<b>Status:</b> <font color='green'>Active Monitoring</font>",
            self.styles['Normal']
        )
        story.append(date_text)
        
        story.append(PageBreak())
    
    def build_executive_summary(self, story, data, days):
        """Build executive summary"""
        story.append(Paragraph("Executive Summary", self.heading_style))
        
        summary_text = (
            f"During the {days}-day analysis period, the honeypot captured "
            f"<b>{data['total_events']:,}</b> attack events from malicious sources. "
            f"The system identified <b>{len(data['top_ips'])}</b> unique attacking IPs "
            f"and captured <b>{data['credentials_captured']}</b> credential attempts. "
            f"Attacks were distributed across <b>{len(data['services'])}</b> different services."
        )
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
    
    def build_statistics_section(self, story, data):
        """Build statistics section"""
        story.append(Paragraph("Key Statistics", self.heading_style))
        
        stats_data = [
            ['Metric', 'Value'],
            ['Total Attack Events', f"{data['total_events']:,}"],
            ['Unique Attacking IPs', f"{len(data['top_ips'])}"],
            ['Credentials Captured', f"{data['credentials_captured']}"],
            ['Services Targeted', f"{len(data['services'])}"]
        ]
        
        stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f77b4')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(stats_table)
        story.append(Spacer(1, 0.2*inch))
    
    def build_top_ips_section(self, story, data):
        """Build top IPs section"""
        story.append(Paragraph("Top 10 Attacking IPs", self.heading_style))
        
        ip_data = [['Rank', 'IP Address', 'Event Count']]
        for i, ip_info in enumerate(data['top_ips'][:10], 1):
            ip_data.append([str(i), ip_info['ip'], str(ip_info['count'])])
        
        ip_table = Table(ip_data, colWidths=[0.8*inch, 2.5*inch, 1.5*inch])
        ip_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f77b4')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(ip_table)
        story.append(Spacer(1, 0.2*inch))
    
    def build_services_section(self, story, data):
        """Build services targeted section"""
        story.append(Paragraph("Attacks by Service", self.heading_style))
        
        service_data = [['Service', 'Event Count', 'Percentage']]
        total = sum(data['services'].values())
        
        for service, count in sorted(data['services'].items(), 
                                     key=lambda x: x[1], reverse=True)[:10]:
            percentage = (count / total * 100) if total > 0 else 0
            service_data.append([service, str(count), f"{percentage:.1f}%"])
        
        service_table = Table(service_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        service_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f77b4')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(service_table)
        story.append(Spacer(1, 0.2*inch))
    
    def build_recommendations(self, story):
        """Build recommendations section"""
        story.append(Paragraph("Recommendations", self.heading_style))
        
        recommendations = [
            "1. Review top attacking IPs and implement IP-based filtering",
            "2. Strengthen SSH credentials and implement rate limiting",
            "3. Monitor for distributed attacks across multiple IPs",
            "4. Integrate threat intelligence for IP reputation scoring",
            "5. Set up automated alerts for HIGH-risk threat levels",
            "6. Regularly review and update security group rules",
            "7. Archive old logs to S3 for long-term analysis"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
        
        story.append(Spacer(1, 0.2*inch))
    
    def generate_pdf(self, filename, days=1):
        """Generate complete PDF report"""
        doc = SimpleDocTemplate(filename, pagesize=letter)
        story = []
        
        # Fetch data
        data = self.get_analytics_data(days)
        
        # Build report
        self.build_title_page(story, days)
        self.build_executive_summary(story, data, days)
        self.build_statistics_section(story, data)
        self.build_top_ips_section(story, data)
        self.build_services_section(story, data)
        self.build_recommendations(story)
        
        # Build footer
        story.append(Spacer(1, 0.3*inch))
        footer_text = Paragraph(
            f"<i>This report was automatically generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>",
            self.styles['Normal']
        )
        story.append(footer_text)
        
        # Generate PDF
        doc.build(story)
        print(f"✅ PDF report generated: {filename}")

def main():
    parser = argparse.ArgumentParser(description='PDF Report Generator')
    parser.add_argument('--output', default='honeypot-report.pdf', help='Output PDF filename')
    parser.add_argument('--days', type=int, default=1, help='Number of days to analyze')
    
    args = parser.parse_args()
    
    generator = PDFReportGenerator()
    generator.generate_pdf(args.output, args.days)

if __name__ == "__main__":
    main()

