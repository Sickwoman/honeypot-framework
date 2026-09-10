#!/usr/bin/env python3

################################################################################
# Honeypot Prometheus Metrics Exporter
# Exports honeypot metrics for Prometheus scraping
################################################################################

import sys
import time

from prometheus_client import Counter, Gauge, Histogram, start_http_server

# Create metrics
honeypot_events = Counter(
    'honeypot_events_total',
    'Total honeypot events',
    ['service', 'event_type']
)

attack_rate = Gauge(
    'honeypot_attack_rate',
    'Current attack rate (events/min)'
)

threat_level_high = Gauge(
    'honeypot_threat_level_high',
    'Number of HIGH threat level IPs'
)

threat_level_medium = Gauge(
    'honeypot_threat_level_medium',
    'Number of MEDIUM threat level IPs'
)

credentials_captured = Counter(
    'honeypot_credentials_total',
    'Total credentials captured'
)

unique_attacking_ips = Gauge(
    'honeypot_unique_ips',
    'Number of unique attacking IPs'
)

elasticsearch_health = Gauge(
    'elasticsearch_cluster_health_status',
    'Elasticsearch cluster health (1=green, 0.5=yellow, 0=red)'
)

elasticsearch_docs = Gauge(
    'elasticsearch_documents_total',
    'Total documents in Elasticsearch'
)

response_time = Histogram(
    'honeypot_query_duration_seconds',
    'Honeypot query duration'
)

import es_client


class MetricsCollector:
    def __init__(self, es_host=None, username=None, password=None):
        self.es = es_client.build_client(
            es_host,
            basic_auth=(username or es_client.username(),
                        password or es_client.password()),
        )
    
    def collect_metrics(self):
        """Collect and update all metrics"""
        try:
            # Cluster health
            health = self.es.cluster.health()
            status_map = {'green': 1, 'yellow': 0.5, 'red': 0}
            elasticsearch_health.set(status_map.get(health['status'], 0))
            
            # Total documents
            count = self.es.count(index='honeypot-*')
            elasticsearch_docs.set(count['count'])
            
            # Threat levels
            response = self.es.search(
                index='honeypot-*',
                body={
                    'size': 0,
                    'aggs': {
                        'threat_high': {
                            'filter': {
                                'term': {'threat_intel.threat_level': 'HIGH'}
                            }
                        },
                        'threat_medium': {
                            'filter': {
                                'term': {'threat_intel.threat_level': 'MEDIUM'}
                            }
                        }
                    }
                }
            )
            
            threat_level_high.set(
                response['aggregations']['threat_high']['doc_count']
            )
            threat_level_medium.set(
                response['aggregations']['threat_medium']['doc_count']
            )
            
            # Unique IPs
            response = self.es.search(
                index='honeypot-*',
                body={
                    'size': 0,
                    'aggs': {
                        'unique_ips': {
                            'cardinality': {
                                'field': 'src_ip'
                            }
                        }
                    }
                }
            )
            
            unique_attacking_ips.set(
                response['aggregations']['unique_ips']['value']
            )
            
            # Attack rate (last 5 minutes)
            response = self.es.search(
                index='honeypot-*',
                body={
                    'query': {
                        'range': {
                            '@timestamp': {'gte': 'now-5m'}
                        }
                    }
                },
                size=0
            )
            
            attack_count = response['hits']['total']['value']
            attack_rate.set(attack_count / 5)  # events per minute
            
            print(f"✅ Metrics collected - Events: {count['count']}, "
                  f"Attack Rate: {attack_rate._value:.2f} /min, "
                  f"HIGH Risk IPs: {threat_level_high._value}")
            
        except Exception as e:
            print(f"❌ Error collecting metrics: {e}")

def main():
    print("Starting Prometheus metrics exporter...")
    print("Listening on http://localhost:8000/metrics")
    
    # Start HTTP server
    start_http_server(8000)
    
    collector = MetricsCollector()
    
    # Collect metrics every 15 seconds
    while True:
        try:
            collector.collect_metrics()
            time.sleep(15)
        except KeyboardInterrupt:
            print("\n✅ Exporter stopped")
            sys.exit(0)
        except Exception as e:
            print(f"❌ Error: {e}")
            time.sleep(15)

if __name__ == '__main__':
    main()

