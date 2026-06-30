#!/usr/bin/env python3

################################################################################
# Performance Monitoring Dashboard
# Real-time monitoring of Elasticsearch and Logstash performance
################################################################################

import requests
import json
import time
from datetime import datetime
from collections import deque
import os
import sys

class PerformanceMonitor:
    def __init__(self, es_url="https://localhost:9200", 
                 username="elastic", password="changeme"):
        self.es_url = es_url
        self.username = username
        self.password = password
        self.verify_ssl = False
        self.metrics_history = deque(maxlen=60)  # Last 60 samples
        
    def get_cluster_health(self):
        """Get Elasticsearch cluster health"""
        try:
            response = requests.get(
                f"{self.es_url}/_cluster/health",
                auth=(self.username, self.password),
                verify=self.verify_ssl
            )
            return response.json()
        except Exception as e:
            print(f"❌ Error getting cluster health: {e}")
            return None
    
    def get_nodes_stats(self):
        """Get node statistics"""
        try:
            response = requests.get(
                f"{self.es_url}/_nodes/stats",
                auth=(self.username, self.password),
                verify=self.verify_ssl
            )
            return response.json()
        except Exception as e:
            print(f"❌ Error getting node stats: {e}")
            return None
    
    def get_indices_stats(self):
        """Get index statistics"""
        try:
            response = requests.get(
                f"{self.es_url}/_stats",
                auth=(self.username, self.password),
                verify=self.verify_ssl
            )
            return response.json()
        except Exception as e:
            print(f"❌ Error getting indices stats: {e}")
            return None
    
    def get_index_count(self):
        """Get total document count"""
        try:
            response = requests.get(
                f"{self.es_url}/honeypot-*/_count",
                auth=(self.username, self.password),
                verify=self.verify_ssl
            )
            return response.json()['count']
        except Exception as e:
            return 0
    
    def calculate_metrics(self):
        """Calculate performance metrics"""
        health = self.get_cluster_health()
        nodes = self.get_nodes_stats()
        indices = self.get_indices_stats()
        
        if not all([health, nodes, indices]):
            return None
        
        # Extract metrics
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cluster_status': health.get('status', 'unknown'),
            'active_shards': health.get('active_shards', 0),
            'unassigned_shards': health.get('unassigned_shards', 0),
            'heap_used_percent': 0,
            'heap_max_bytes': 0,
            'docs_count': indices['_all']['primaries']['docs']['count'],
            'store_size_bytes': indices['_all']['primaries']['store']['size_in_bytes'],
            'search_time_ms': indices['_all']['total']['search']['query_time_in_millis'],
            'indexing_time_ms': indices['_all']['total']['indexing']['index_time_in_millis'],
        }
        
        # Get heap info from first node
        if 'nodes' in nodes:
            for node_id, node_data in nodes['nodes'].items():
                if 'jvm' in node_data:
                    metrics['heap_used_percent'] = node_data['jvm']['mem']['heap_used_percent']
                    metrics['heap_max_bytes'] = node_data['jvm']['mem']['heap_max_in_bytes']
                break
        
        self.metrics_history.append(metrics)
        return metrics
    
    def print_dashboard(self):
        """Print formatted performance dashboard"""
        metrics = self.calculate_metrics()
        
        if not metrics:
            print("❌ Failed to retrieve metrics")
            return
        
        # Clear screen
        os.system('clear' if os.name == 'posix' else 'cls')
        
        print("\033[94m" + "="*70 + "\033[0m")
        print("\033[94m ELASTICSEARCH PERFORMANCE DASHBOARD".center(70) + "\033[0m")
        print("\033[94m" + "="*70 + "\033[0m")
        print()
        
        # Cluster Health
        status_color = {
            'green': '\033[92m',   # Green
            'yellow': '\033[93m',  # Yellow
            'red': '\033[91m'      # Red
        }.get(metrics['cluster_status'], '\033[0m')
        
        print(f"\033[92m📊 CLUSTER HEALTH\033[0m")
        print(f"  Status: {status_color}{metrics['cluster_status'].upper()}\033[0m")
        print(f"  Active Shards: {metrics['active_shards']}")
        print(f"  Unassigned Shards: {metrics['unassigned_shards']}")
        print()
        
        # Memory Usage
        heap_percent = metrics['heap_used_percent']
        heap_color = '\033[92m' if heap_percent < 70 else '\033[93m' if heap_percent < 85 else '\033[91m'
        
        print(f"\033[92m💾 MEMORY USAGE\033[0m")
        print(f"  Heap Used: {heap_color}{heap_percent}%\033[0m")
        print(f"  Max Heap: {metrics['heap_max_bytes'] / (1024**3):.2f}GB")
        print()
        
        # Data Statistics
        docs_gb = metrics['store_size_bytes'] / (1024**3)
        print(f"\033[92m📈 DATA STATISTICS\033[0m")
        print(f"  Total Documents: {metrics['docs_count']:,}")
        print(f"  Storage Size: {docs_gb:.2f}GB")
        print()
        
        # Performance Metrics
        print(f"\033[92m⚡ PERFORMANCE\033[0m")
        print(f"  Search Time (total): {metrics['search_time_ms']:,}ms")
        print(f"  Indexing Time (total): {metrics['indexing_time_ms']:,}ms")
        
        # Calculate rates if we have history
        if len(self.metrics_history) > 1:
            prev = self.metrics_history[-2]
            curr = self.metrics_history[-1]
            
            docs_per_sec = (curr['docs_count'] - prev['docs_count']) / 1  # 1 second interval
            print(f"  Indexing Rate: {docs_per_sec:,.0f} docs/sec")
        
        print()
        
        # Recommendations
        print(f"\033[92m💡 RECOMMENDATIONS\033[0m")
        recommendations = []
        
        if heap_percent > 85:
            recommendations.append("⚠️  High heap usage - consider increasing JVM heap size")
        
        if metrics['unassigned_shards'] > 0:
            recommendations.append("⚠️  Unassigned shards detected - check cluster status")
        
        if metrics['cluster_status'] != 'green':
            recommendations.append("⚠️  Cluster not in green state - investigate issues")
        
        if not recommendations:
            recommendations.append("✅ Cluster performing optimally")
        
        for rec in recommendations:
            print(f"  {rec}")
        
        print()
        print(f"\033[94m{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m")
        print(f"\033[94m(Press Ctrl+C to stop)\033[0m")

def main():
    monitor = PerformanceMonitor()
    
    print("🚀 Starting performance monitoring...")
    print("Connecting to Elasticsearch...")
    
    try:
        while True:
            monitor.print_dashboard()
            time.sleep(5)  # Update every 5 seconds
    except KeyboardInterrupt:
        print("\n\n✅ Monitoring stopped")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

