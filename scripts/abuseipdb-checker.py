#!/usr/bin/env python3

################################################################################
# AbuseIPDB Integration Script
# Check IP reputation and enrich honeypot logs with threat intelligence
################################################################################

import argparse
import sys
import time
from datetime import datetime

import es_client
import requests


class AbuseIPDBChecker:
    def __init__(self, api_key=None):
        self.api_key = api_key or self.get_api_key()
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.cache = {}
        self.cache_ttl = 86400  # 24 hours
        self.es = None
        
    @staticmethod
    def get_api_key():
        """Get API key from environment or user input"""
        import os
        api_key = os.getenv('ABUSEIPDB_API_KEY')
        if not api_key:
            print("❌ Error: ABUSEIPDB_API_KEY environment variable not set")
            print("Get free API key at: https://www.abuseipdb.com/register")
            sys.exit(1)
        return api_key
    
    def check_ip(self, ip_address):
        """Check IP reputation on AbuseIPDB"""
        # Check cache first
        if ip_address in self.cache:
            cached_data, timestamp = self.cache[ip_address]
            if time.time() - timestamp < self.cache_ttl:
                return cached_data
        
        try:
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(
                f"{self.base_url}/check",
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Cache the result
                self.cache[ip_address] = (data, time.time())
                
                return data
            else:
                print(f"❌ Error: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Error checking IP {ip_address}: {e}")
            return None
    
    def get_threat_level(self, confidence_score):
        """Determine threat level based on confidence score"""
        if confidence_score >= 75:
            return "HIGH"
        elif confidence_score >= 50:
            return "MEDIUM"
        elif confidence_score >= 25:
            return "LOW"
        else:
            return "SAFE"
    
    def format_result(self, ip_address, data):
        """Format check result for display"""
        if not data or 'data' not in data:
            return None
        
        ip_data = data['data']
        
        result = {
            'ip': ip_address,
            'timestamp': datetime.now().isoformat(),
            'confidence_score': ip_data.get('abuseConfidenceScore', 0),
            'threat_level': self.get_threat_level(ip_data.get('abuseConfidenceScore', 0)),
            'total_reports': ip_data.get('totalReports', 0),
            'last_reported': ip_data.get('lastReportedAt', 'Never'),
            'is_whitelisted': ip_data.get('isWhitelisted', False),
            'is_blacklisted': ip_data.get('isBlacklisted', False),
            'usage_type': ip_data.get('usageType', 'Unknown'),
            'isp': ip_data.get('isp', 'Unknown'),
            'domain': ip_data.get('domain', 'Unknown'),
            'country': ip_data.get('countryCode', 'Unknown'),
            'reports': ip_data.get('reports', [])
        }
        
        return result
    
    def print_report(self, result):
        """Print formatted IP reputation report"""
        if not result:
            print("❌ No data to display")
            return
        
        # Color codes
        color_high = '\033[91m'    # Red
        color_medium = '\033[93m'  # Yellow
        color_low = '\033[92m'     # Green
        color_reset = '\033[0m'
        
        threat_color = {
            'HIGH': color_high,
            'MEDIUM': color_medium,
            'LOW': color_low,
            'SAFE': color_low
        }.get(result['threat_level'], color_reset)
        
        print("\n" + "="*70)
        print(f" 🔍 IP REPUTATION REPORT - {result['ip']}".center(70))
        print("="*70)
        
        print(f"\n{threat_color}Threat Level: {result['threat_level']}{color_reset}")
        print(f"Confidence Score: {result['confidence_score']}/100")
        print(f"Total Reports: {result['total_reports']}")
        print(f"Last Reported: {result['last_reported']}")
        
        print("\n📍 Location & Network:")
        print(f"  Country: {result['country']}")
        print(f"  ISP: {result['isp']}")
        print(f"  Domain: {result['domain']}")
        print(f"  Usage Type: {result['usage_type']}")
        
        print("\n🚨 Flags:")
        print(f"  Whitelisted: {'✓ Yes' if result['is_whitelisted'] else '✗ No'}")
        print(f"  Blacklisted: {'✓ Yes' if result['is_blacklisted'] else '✗ No'}")
        
        if result['reports']:
            print(f"\n📋 Recent Reports ({len(result['reports'])} total):")
            for i, report in enumerate(result['reports'][:5], 1):
                print(f"  {i}. {report['reportedAt']}")
                print(f"     Category: {report['category']}")
                print(f"     Comment: {report['comment'][:60]}...")
        
        print("\n" + "="*70 + "\n")
    
    def enrich_elasticsearch(self, ip_address):
        """Enrich Elasticsearch documents with threat intelligence"""
        try:
            self.es = es_client.build_client()
            
            result = self.check_ip(ip_address)
            formatted = self.format_result(ip_address, result)
            
            if formatted:
                # Add threat intel document
                self.es.index(
                    index="threat-intel",
                    doc_type="_doc",
                    body={
                        'ip': ip_address,
                        'threat_data': formatted,
                        '@timestamp': datetime.now().isoformat()
                    }
                )
                
                # Update honeypot events with threat info
                self.es.update_by_query(
                    index="honeypot-*",
                    body={
                        "query": {"match": {"src_ip": ip_address}},
                        "script": {
                            "source": "ctx._source.threat_intel = params.threat_data",
                            "params": {"threat_data": formatted}
                        }
                    }
                )
                
                print(f"✅ Enriched {ip_address} in Elasticsearch")
                return True
        except Exception as e:
            print(f"⚠️  Could not enrich Elasticsearch: {e}")
            return False
    
    def batch_check_ips(self, ip_list):
        """Check multiple IPs and generate report"""
        print(f"\n🔄 Checking {len(ip_list)} IPs...")
        results = []
        
        for i, ip in enumerate(ip_list, 1):
            print(f"  [{i}/{len(ip_list)}] Checking {ip}...", end='\r')
            data = self.check_ip(ip)
            result = self.format_result(ip, data)
            if result:
                results.append(result)
            time.sleep(1)  # Rate limiting (free tier: 50 req/day)
        
        print("\n✅ Batch check complete\n")
        return results
    
    def get_honeypot_ips(self):
        """Get attacking IPs from Elasticsearch"""
        try:
            self.es = es_client.build_client()
            
            response = self.es.search(
                index="honeypot-*",
                body={
                    "size": 0,
                    "aggs": {
                        "top_ips": {
                            "terms": {
                                "field": "src_ip",
                                "size": 20
                            }
                        }
                    }
                }
            )
            
            ips = [bucket['key'] for bucket in response['aggregations']['top_ips']['buckets']]
            return ips
        except Exception as e:
            print(f"⚠️  Could not fetch IPs from Elasticsearch: {e}")
            return []

def main():
    parser = argparse.ArgumentParser(description='AbuseIPDB IP Reputation Checker')
    parser.add_argument('--check', help='Check single IP')
    parser.add_argument('--batch', help='Batch check IPs from file')
    parser.add_argument('--honeypot', action='store_true', help='Check IPs from honeypot logs')
    parser.add_argument('--enrich', help='Check and enrich Elasticsearch with threat intel')
    parser.add_argument('--report', help='Generate report for IP')
    
    args = parser.parse_args()
    
    checker = AbuseIPDBChecker()
    
    print("\n\033[94m" + "="*70)
    print(" 🛡️  ABUSEIPDB IP REPUTATION CHECKER".center(70))
    print("="*70 + "\033[0m\n")
    
    if args.check:
        result = checker.check_ip(args.check)
        formatted = checker.format_result(args.check, result)
        checker.print_report(formatted)
    
    elif args.batch:
        with open(args.batch, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
        results = checker.batch_check_ips(ips)
        
        # Print summary
        high_risk = [r for r in results if r['threat_level'] == 'HIGH']
        print(f"Summary: {len(high_risk)} HIGH risk IPs found")
        for result in high_risk:
            checker.print_report(result)
    
    elif args.honeypot:
        ips = checker.get_honeypot_ips()
        if ips:
            print(f"Found {len(ips)} attacking IPs in honeypot")
            results = checker.batch_check_ips(ips)
            for result in results:
                if result['threat_level'] in ['HIGH', 'MEDIUM']:
                    checker.print_report(result)
    
    elif args.enrich:
        checker.enrich_elasticsearch(args.enrich)
        result = checker.check_ip(args.enrich)
        formatted = checker.format_result(args.enrich, result)
        checker.print_report(formatted)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

