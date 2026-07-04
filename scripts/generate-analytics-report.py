#!/usr/bin/env python3

################################################################################
# Advanced Analytics Report Generator
# Generates comprehensive attack analysis and statistics
################################################################################

import json
import requests
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
import argparse

class AnalyticsReportGenerator:
    def __init__(self, es_host="https://localhost:9200", 
                 username="elastic", password="changeme"):
        self.es = Elasticsearch(
            [es_host],
            basic_auth=(username, password),
            verify_certs=False
        )
        self.verify_ssl = False
    
    def get_document_count(self, days=1):
        """Get total documents in last N days"""
        try:
            response = self.es.search(
                index="honeypot-*",
                body={
                    "query": {
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{days}d"
                            }
                        }
                    }
                },
                size=0
            )
            return response['hits']['total']['value']
        except Exception as e:
            print(f"❌ Error: {e}")
            return 0
    
    def get_top_ips(self, limit=10, days=1):
        """Get top attacking IPs"""
        try:
            response = self.es.search(
                index="honeypot-*",
                body={
                    "query": {
                        "range": {
                            "@timestamp": {"gte": f"now-{days}d"}
                        }
                    },
                    "size": 0,
                    "aggs": {
                        "top_ips": {
                            "terms": {
                                "field": "src_ip",
                                "size": limit,
                                "order": {"_count": "desc"}
                            }
                        }
                    }
                }
            )
            
            ips = []
            for bucket in response['aggregations']['top_ips']['buckets']:
                ips.append({
                    'ip': bucket['key'],
                    'count': bucket['doc_count']
                })
            return ips
        except Exception as e:
            print(f"❌ Error: {e}")
            return []
    
    def get_service_distribution(self, days=1):
        """Get attack distribution by service"""
        try:
            response = self.es.search(
                index="honeypot-*",
                body={
                    "query": {
                        "range": {
                            "@timestamp": {"gte": f"now-{days}d"}
                        }
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
            
            services = {}
            for bucket in response['aggregations']['services']['buckets']:
                services[bucket['key']] = bucket['doc_count']
            return services
        except Exception as e:
            print(f"❌ Error: {e}")
            return {}
    
    def get_hourly_trend(self, days=1):
        """Get attack trend by hour"""
        try:
            response = self.es.search(
                index="honeypot-*",
                body={
                    "query": {
                        "range": {
                            "@timestamp": {"gte": f"now-{days}d"}
                        }
                    },
                    "size": 0,
                    "aggs": {
                        "timeline": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "calendar_interval": "1h"
                            }
                        }
                    }
                }
            )
            
            timeline = []
            for bucket in response['aggregations']['timeline']['buckets']:
                timeline.append({
                    'timestamp': bucket['key_as_string'],
                    'count': bucket['doc_count']
                })
            return timeline
        except Exception as e:
            print(f"❌ Error: {e}")
            return []
    
    def get_threat_intelligence_stats(self, days=1):
        """Get threat intelligence statistics"""
        try:
            response = self.es.search(
                index="honeypot-*",
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
                                {"exists": {"field": "threat_intel"}}
                            ]
                        }
                    },
                    "size": 0,
                    "aggs": {
                        "threat_levels": {
                            "terms": {
                                "field": "threat_intel.threat_level",
                                "size": 10
                            }
                        },
                        "avg_confidence": {
                            "avg": {
                                "field": "threat_intel.confidence_score"
                            }
                        }
                    }
                }
            )
            
            stats = {
                'threat_levels': {},
                'avg_confidence': response['aggregations']['avg_confidence']['value']
            }
            
            for bucket in response['aggregations']['threat_levels']['buckets']:
                stats['threat_levels'][bucket['key']] = bucket['doc_count']
            
            return stats
        except Exception as e:
            print(f"❌ Error: {e}")
            return {}
    
    def get_credentials_captured(self, days=1):
        """Get number of credentials captured"""
        try:
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
            return response['hits']['total']['value']
        except Exception as e:
            return 0
    
    def generate_text_report(self, days=1):
        """Generate formatted text report"""
        print("\n" + "="*70)
        print(f" 📊 HONEYPOT ANALYTICS REPORT".center(70))
        print(f" {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(70))
        print("="*70)
        
        print(f"\n📈 SUMMARY (Last {days} day(s)):")
        
        # Total events
        total = self.get_document_count(days)
        print(f"  Total Events: {total:,}")
        
        # Credentials
        creds = self.get_credentials_captured(days)
        print(f"  Credentials Captured: {creds}")
        
        # Top IPs
        print(f"\n🔴 TOP 10 ATTACKING IPs:")
        top_ips = self.get_top_ips(10, days)
        for i, ip_data in enumerate(top_ips, 1):
            print(f"  {i:2d}. {ip_data['ip']:15s} - {ip_data['count']:5d} events")
        
        # Service distribution
        print(f"\n🔧 ATTACKS BY SERVICE:")
        services = self.get_service_distribution(days)
        for service, count in sorted(services.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            bar = "█" * int(percentage / 5)
            print(f"  {service:15s} {count:5d} ({percentage:5.1f}%) {bar}")
        
        # Threat intelligence
        print(f"\n⚠️  THREAT INTELLIGENCE:")
        threat_stats = self.get_threat_intelligence_stats(days)
        if threat_stats.get('threat_levels'):
            for level, count in threat_stats['threat_levels'].items():
                print(f"  {level:8s}: {count:5d}")
        if threat_stats.get('avg_confidence'):
            print(f"  Avg Confidence Score: {threat_stats['avg_confidence']:.2f}/100")
        
        # Hourly trend
        print(f"\n📅 HOURLY TREND (Last {days} day(s)):")
        timeline = self.get_hourly_trend(days)
        if timeline:
            max_count = max([t['count'] for t in timeline])
            for entry in timeline[-12:]:  # Last 12 hours
                hour = entry['timestamp'].split('T')[1].split(':')[0]
                bar = "█" * int((entry['count'] / max_count * 30) if max_count > 0 else 0)
                print(f"  {hour}:00 {entry['count']:5d} {bar}")
        
        print("\n" + "="*70 + "\n")
    
    def generate_json_report(self, days=1):
        """Generate JSON report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'period_days': days,
            'summary': {
                'total_events': self.get_document_count(days),
                'credentials_captured': self.get_credentials_captured(days)
            },
            'top_ips': self.get_top_ips(10, days),
            'service_distribution': self.get_service_distribution(days),
            'threat_intelligence': self.get_threat_intelligence_stats(days),
            'hourly_trend': self.get_hourly_trend(days)
        }
        return report

def main():
    parser = argparse.ArgumentParser(description='Analytics Report Generator')
    parser.add_argument('--days', type=int, default=1, help='Number of days to analyze')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--file', help='Save report to file')
    
    args = parser.parse_args()
    
    generator = AnalyticsReportGenerator()
    
    if args.json:
        report = generator.generate_json_report(args.days)
        
        if args.file:
            with open(args.file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"✅ Report saved to {args.file}")
        else:
            print(json.dumps(report, indent=2))
    else:
        generator.generate_text_report(args.days)
        
        if args.file:
            with open(args.file, 'w') as f:
                # Redirect print to file
                import sys
                old_stdout = sys.stdout
                sys.stdout = f
                generator.generate_text_report(args.days)
                sys.stdout = old_stdout
            print(f"✅ Report saved to {args.file}")

if __name__ == "__main__":
    main()

