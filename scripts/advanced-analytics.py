#!/usr/bin/env python3

################################################################################
# Advanced Analytics & Data Export
# Analyze attack trends and export data
################################################################################

import requests
import json
import csv
from datetime import datetime, timedelta
import pandas as pd
import os

class AdvancedAnalytics:
    def __init__(self, es_url="https://localhost:9200",
                 username="elastic", password="changeme"):
        self.es_url = es_url
        self.username = username
        self.password = password
        self.verify_ssl = False
    
    def get_attack_trends(self, period="7d", interval="1d"):
        """Analyze attack trends over time"""
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
                        "trend": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "calendar_interval": interval,
                                "min_doc_count": 0
                            }
                        }
                    },
                    "size": 0
                }
            )
            
            data = response.json()
            trends = []
            
            for bucket in data['aggregations']['trend']['buckets']:
                trends.append({
                    'timestamp': bucket['key_as_string'],
                    'count': bucket['doc_count']
                })
            
            return trends
        except Exception as e:
            print(f"Error analyzing trends: {e}")
            return None
    
    def get_geographic_analysis(self):
        """Analyze attacks by geographic location"""
        try:
            response = requests.get(
                f"{self.es_url}/honeypot-*/_search",
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                json={
                    "aggs": {
                        "by_country": {
                            "terms": {
                                "field": "geoip.country_name",
                                "size": 50
                            }
                        }
                    },
                    "size": 0
                }
            )
            
            data = response.json()
            locations = []
            
            for bucket in data['aggregations']['by_country']['buckets']:
                locations.append({
                    'country': bucket['key'],
                    'attacks': bucket['doc_count']
                })
            
            return sorted(locations, key=lambda x: x['attacks'], reverse=True)
        except Exception as e:
            print(f"Error analyzing geography: {e}")
            return None
    
    def get_top_attackers(self, limit=50):
        """Get top attacking IPs"""
        try:
            response = requests.get(
                f"{self.es_url}/honeypot-*/_search",
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                json={
                    "aggs": {
                        "top_ips": {
                            "terms": {
                                "field": "src_ip",
                                "size": limit
                            }
                        }
                    },
                    "size": 0
                }
            )
            
            data = response.json()
            attackers = []
            
            for bucket in data['aggregations']['top_ips']['buckets']:
                attackers.append({
                    'ip': bucket['key'],
                    'attacks': bucket['doc_count']
                })
            
            return attackers
        except Exception as e:
            print(f"Error getting top attackers: {e}")
            return None
    
    def export_to_csv(self, data, filename):
        """Export data to CSV"""
        try:
            if not data:
                print("No data to export")
                return False
            
            filepath = f"/tmp/{filename}-{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            
            with open(filepath, 'w', newline='') as f:
                if isinstance(data, list) and len(data) > 0:
                    writer = csv.DictWriter(f, fieldnames=data[0].keys())
                    writer.writeheader()
                    writer.writerows(data)
            
            print(f"✅ Data exported to: {filepath}")
            return filepath
        except Exception as e:
            print(f"Error exporting to CSV: {e}")
            return None
    
    def export_to_json(self, data, filename):
        """Export data to JSON"""
        try:
            filepath = f"/tmp/{filename}-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"✅ Data exported to: {filepath}")
            return filepath
        except Exception as e:
            print(f"Error exporting to JSON: {e}")
            return None
    
    def export_to_excel(self, data, filename):
        """Export data to Excel"""
        try:
            filepath = f"/tmp/{filename}-{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            
            df = pd.DataFrame(data)
            df.to_excel(filepath, index=False)
            
            print(f"✅ Data exported to: {filepath}")
            return filepath
        except Exception as e:
            print(f"Error exporting to Excel: {e}")
            return None
    
    def generate_analytics_report(self):
        """Generate comprehensive analytics report"""
        print("📊 Generating analytics report...\n")
        
        # Get trends
        print("📈 Analyzing trends...")
        trends = self.get_attack_trends("7d", "1d")
        
        # Get geography
        print("🌍 Analyzing geographic distribution...")
        geography = self.get_geographic_analysis()
        
        # Get top attackers
        print("🎯 Identifying top attackers...")
        attackers = self.get_top_attackers(20)
        
        report = {
            "generated": datetime.now().isoformat(),
            "trends": trends,
            "geography": geography,
            "top_attackers": attackers
        }
        
        # Export in multiple formats
        self.export_to_json(report, "analytics-report")
        self.export_to_csv(attackers, "top-attackers")
        
        if geography:
            self.export_to_csv(geography, "geographic-distribution")
        
        print("\n✅ Analytics report generated")
        return report

def main():
    import sys
    
    analytics = AdvancedAnalytics()
    
    if len(sys.argv) < 2:
        print("Usage: advanced-analytics.py [trends|geography|attackers|report|export]")
        sys.exit(1)
    
    action = sys.argv[1]
    
    if action == "trends":
        trends = analytics.get_attack_trends("7d", "1d")
        analytics.export_to_json(trends, "attack-trends")
        analytics.export_to_csv(trends, "attack-trends")
    
    elif action == "geography":
        geography = analytics.get_geographic_analysis()
        analytics.export_to_json(geography, "geographic-distribution")
        analytics.export_to_csv(geography, "geographic-distribution")
    
    elif action == "attackers":
        attackers = analytics.get_top_attackers(50)
        analytics.export_to_json(attackers, "top-attackers")
        analytics.export_to_csv(attackers, "top-attackers")
    
    elif action == "report":
        analytics.generate_analytics_report()
    
    elif action == "export":
        analytics.get_attack_trends()
        analytics.get_geographic_analysis()
        analytics.get_top_attackers()
    
    else:
        print("Invalid action")
        sys.exit(1)

if __name__ == "__main__":
    main()

