#!/usr/bin/env python3

################################################################################
# Machine Learning - Attack Classification & Threat Scoring
# Classify attacks and assign risk scores
################################################################################

import requests
import json
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.preprocessing import MinMaxScaler
import os

class ThreatClassifier:
    def __init__(self, es_url="https://localhost:9200",
                 username="elastic", password="changeme"):
        self.es_url = es_url
        self.username = username
        self.password = password
        self.verify_ssl = False
        self.scaler = MinMaxScaler()
    
    def fetch_detailed_attacks(self, period="7d"):
        """Fetch detailed attack information"""
        print("📊 Fetching detailed attack data...")
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
                        "by_ip": {
                            "terms": {
                                "field": "src_ip",
                                "size": 1000
                            },
                            "aggs": {
                                "events": {
                                    "top_hits": {
                                        "size": 100,
                                        "_source": ["event_type", "service", "dst_port", "@timestamp"]
                                    }
                                },
                                "failed_logins": {
                                    "filter": {
                                        "term": {"event_type": "login_attempt"}
                                    }
                                },
                                "malware_attempts": {
                                    "filter": {
                                        "match": {"logdata.CMD": "wget"}
                                    }
                                },
                                "port_scan_attempts": {
                                    "cardinality": {"field": "dst_port"}
                                }
                            }
                        }
                    },
                    "size": 0
                }
            )
            
            data = []
            for bucket in response.json()['aggregations']['by_ip']['buckets']:
                data.append({
                    'src_ip': bucket['key'],
                    'total_attacks': bucket['doc_count'],
                    'failed_logins': bucket['failed_logins']['doc_count'],
                    'malware_attempts': bucket['malware_attempts']['doc_count'],
                    'unique_ports': bucket['port_scan_attempts']['value']
                })
            
            return pd.DataFrame(data)
        except Exception as e:
            print(f"❌ Error fetching data: {e}")
            return None
    
    def calculate_threat_score(self, row):
        """Calculate threat score (0-100)"""
        score = 0
        
        # Attack frequency (0-30 points)
        if row['total_attacks'] > 100:
            score += 30
        elif row['total_attacks'] > 50:
            score += 20
        elif row['total_attacks'] > 10:
            score += 10
        
        # Failed logins (0-25 points) - Brute force indicator
        if row['failed_logins'] > 50:
            score += 25
        elif row['failed_logins'] > 20:
            score += 15
        elif row['failed_logins'] > 0:
            score += 5
        
        # Malware attempts (0-25 points) - Critical threat
        if row['malware_attempts'] > 0:
            score += 25
        
        # Port diversity (0-20 points) - Reconnaissance indicator
        if row['unique_ports'] > 10:
            score += 20
        elif row['unique_ports'] > 5:
            score += 10
        
        return min(100, score)
    
    def classify_attack_type(self, row):
        """Classify attack into categories"""
        
        # Malware attack (highest priority)
        if row['malware_attempts'] > 0:
            return "Malware Distribution"
        
        # Brute force attack
        if row['failed_logins'] > 50 and row['total_attacks'] > 100:
            return "Brute Force Attack"
        
        # Reconnaissance/Port scanning
        if row['unique_ports'] > 10 and row['total_attacks'] < 50:
            return "Port Scanning"
        
        # Targeted attack
        if row['total_attacks'] > 100 and row['unique_ports'] > 3:
            return "Targeted Attack"
        
        # Credential testing
        if row['failed_logins'] > 5 and row['total_attacks'] < 50:
            return "Credential Testing"
        
        # General probing
        if row['total_attacks'] < 10:
            return "General Probing"
        
        return "Unknown"
    
    def assign_threat_level(self, score):
        """Assign threat level based on score"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "INFO"
    
    def get_recommendations(self, attack_type, threat_level):
        """Get security recommendations"""
        recommendations = {
            "Malware Distribution": [
                "Block IP immediately",
                "Alert security team",
                "Submit URL to abuse databases",
                "Monitor for related attacks"
            ],
            "Brute Force Attack": [
                "Implement rate limiting",
                "Enable MFA",
                "Consider IP blocking",
                "Monitor failed login patterns"
            ],
            "Port Scanning": [
                "Monitor for exploitation attempts",
                "Ensure firewall is active",
                "Review open ports",
                "Track follow-up attacks"
            ],
            "Targeted Attack": [
                "Highest priority monitoring",
                "Increase logging verbosity",
                "Alert security team immediately",
                "Prepare incident response"
            ],
            "Credential Testing": [
                "Monitor for privilege escalation",
                "Enforce password policies",
                "Enable account lockout",
                "Review access logs"
            ]
        }
        
        return recommendations.get(attack_type, ["Monitor activity"])
    
    def generate_threat_report(self):
        """Generate comprehensive threat classification report"""
        print("\n" + "="*80)
        print("🎯 THREAT CLASSIFICATION & RISK SCORING REPORT")
        print("="*80 + "\n")
        
        # Fetch data
        df = self.fetch_detailed_attacks("7d")
        if df is None or len(df) == 0:
            print("❌ No data available")
            return
        
        print(f"📊 Analyzed {len(df)} unique attacking IPs\n")
        
        # Calculate threat scores
        df['threat_score'] = df.apply(self.calculate_threat_score, axis=1)
        df['attack_type'] = df.apply(self.classify_attack_type, axis=1)
        df['threat_level'] = df['threat_score'].apply(self.assign_threat_level)
        
        # Sort by threat score
        df = df.sort_values('threat_score', ascending=False)
        
        # Print threat summary
        print("⚠️  THREAT LEVEL DISTRIBUTION:")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = len(df[df['threat_level'] == level])
            if count > 0:
                print(f"  • {level}: {count}")
        
        print("\n🎯 TOP 10 THREATS BY RISK SCORE:")
        print("-" * 80)
        print(f"{'IP Address':<20} {'Type':<25} {'Score':<8} {'Level':<10} {'Attacks':<8}")
        print("-" * 80)
        
        for idx, row in df.head(10).iterrows():
            print(f"{row['src_ip']:<20} {row['attack_type']:<25} "
                  f"{row['threat_score']:<8.1f} {row['threat_level']:<10} "
                  f"{row['total_attacks']:<8}")
        
        print("\n📊 ATTACK TYPE DISTRIBUTION:")
        type_dist = df['attack_type'].value_counts()
        for attack_type, count in type_dist.items():
            print(f"  • {attack_type}: {count}")
        
        print("\n🔴 CRITICAL THREATS REQUIRING IMMEDIATE ACTION:")
        critical = df[df['threat_level'] == "CRITICAL"]
        if len(critical) > 0:
            for idx, row in critical.iterrows():
                print(f"\n  IP: {row['src_ip']}")
                print(f"  Type: {row['attack_type']}")
                print(f"  Risk Score: {row['threat_score']:.1f}/100")
                print(f"  Attacks: {row['total_attacks']}")
                print(f"  Recommendations:")
                for rec in self.get_recommendations(row['attack_type'], row['threat_level']):
                    print(f"    ✓ {rec}")
        else:
            print("  ✅ No critical threats detected")
        
        print("\n📈 THREAT STATISTICS:")
        print(f"  • Average Threat Score: {df['threat_score'].mean():.1f}")
        print(f"  • Highest Threat Score: {df['threat_score'].max():.1f}")
        print(f"  • Lowest Threat Score: {df['threat_score'].min():.1f}")
        print(f"  • Std Deviation: {df['threat_score'].std():.1f}")
        
        # Export results
        self.export_results(df)
        
        print("\n" + "="*80)
        print("✅ Threat Classification Report Complete")
        print("="*80 + "\n")
    
    def export_results(self, df):
        """Export classification results"""
        print("💾 Exporting results...")
        
        # Export to JSON
        results = {
            'timestamp': datetime.now().isoformat(),
            'threats': df.to_dict('records')
        }
        
        filepath = f"/tmp/threat-classification-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"✅ Results exported to: {filepath}")
        
        # Export to CSV
        df.to_csv(
            f"/tmp/threat-scores-{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            index=False
        )
        
        print(f"✅ Threat scores exported to CSV")

def main():
    import sys
    
    classifier = ThreatClassifier()
    
    if len(sys.argv) < 2:
        classifier.generate_threat_report()
    else:
        action = sys.argv[1]
        if action == "classify":
            classifier.generate_threat_report()
        else:
            print("Usage: ml-threat-classifier.py [classify]")

if __name__ == "__main__":
    main()

