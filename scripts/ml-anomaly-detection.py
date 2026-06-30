#!/usr/bin/env python3

################################################################################
# Machine Learning - Anomaly Detection
# Detect unusual attack patterns using Isolation Forest & Autoencoders
################################################################################

import requests
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import json
import pickle
from datetime import datetime
import os

class AnomalyDetector:
    def __init__(self, es_url="https://localhost:9200",
                 username="elastic", password="changeme"):
        self.es_url = es_url
        self.username = username
        self.password = password
        self.verify_ssl = False
        self.scaler = StandardScaler()
        self.model = None
        self.model_path = "/tmp/anomaly_model.pkl"
    
    def fetch_attack_data(self, period="7d"):
        """Fetch attack data from Elasticsearch"""
        print("📊 Fetching attack data...")
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
                        "attacks_by_ip": {
                            "terms": {
                                "field": "src_ip",
                                "size": 1000
                            },
                            "aggs": {
                                "attack_count": {"value_count": {"field": "_id"}},
                                "services_targeted": {
                                    "cardinality": {"field": "service"}
                                },
                                "unique_ports": {
                                    "cardinality": {"field": "dst_port"}
                                }
                            }
                        }
                    },
                    "size": 0
                }
            )
            
            data = []
            for bucket in response.json()['aggregations']['attacks_by_ip']['buckets']:
                data.append({
                    'src_ip': bucket['key'],
                    'attack_count': bucket['doc_count'],
                    'services_targeted': bucket['services_targeted']['value'],
                    'unique_ports': bucket['unique_ports']['value']
                })
            
            return pd.DataFrame(data)
        except Exception as e:
            print(f"❌ Error fetching data: {e}")
            return None
    
    def prepare_features(self, df):
        """Prepare features for ML model"""
        print("🔧 Preparing features...")
        
        features = df[['attack_count', 'services_targeted', 'unique_ports']].copy()
        
        # Add derived features
        features['attack_service_ratio'] = features['attack_count'] / (features['services_targeted'] + 1)
        features['port_diversity'] = features['unique_ports'] / (features['attack_count'] + 1)
        features['service_port_ratio'] = features['services_targeted'] / (features['unique_ports'] + 1)
        
        return features
    
    def train_isolation_forest(self, features, contamination=0.1):
        """Train Isolation Forest model"""
        print("🤖 Training Isolation Forest...")
        
        # Scale features
        scaled_features = self.scaler.fit_transform(features)
        
        # Train model
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        
        predictions = self.model.fit_predict(scaled_features)
        anomaly_scores = self.model.score_samples(scaled_features)
        
        # Save model
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler
            }, f)
        
        print(f"✅ Model trained. Anomalies detected: {sum(predictions == -1)}")
        
        return predictions, anomaly_scores
    
    def train_clustering(self, features):
        """Train DBSCAN clustering for pattern detection"""
        print("🤖 Training DBSCAN clustering...")
        
        scaled_features = self.scaler.fit_transform(features)
        
        clusterer = DBSCAN(eps=0.5, min_samples=2)
        labels = clusterer.fit_predict(scaled_features)
        
        return labels
    
    def detect_attack_patterns(self, df):
        """Detect specific attack patterns"""
        print("🔍 Analyzing attack patterns...")
        
        patterns = {}
        
        # Brute force detection (high attack count, single service)
        brute_force = df[(df['attack_count'] > 50) & (df['services_targeted'] == 1)]
        patterns['brute_force'] = len(brute_force)
        
        # Reconnaissance detection (low attack count, many services)
        reconnaissance = df[(df['attack_count'] < 10) & (df['services_targeted'] > 3)]
        patterns['reconnaissance'] = len(reconnaissance)
        
        # Port scanning detection (many unique ports)
        port_scanning = df[df['unique_ports'] > 5]
        patterns['port_scanning'] = len(port_scanning)
        
        # Targeted attacks (high attack count, many services)
        targeted = df[(df['attack_count'] > 50) & (df['services_targeted'] > 2)]
        patterns['targeted'] = len(targeted)
        
        return patterns
    
    def classify_attacks(self, df):
        """Classify attacks into categories"""
        print("📂 Classifying attacks...")
        
        classifications = []
        
        for idx, row in df.iterrows():
            attack_type = "Unknown"
            
            if row['attack_count'] > 100 and row['services_targeted'] == 1:
                attack_type = "Brute Force"
            elif row['attack_count'] < 10 and row['services_targeted'] > 3:
                attack_type = "Reconnaissance"
            elif row['unique_ports'] > 5:
                attack_type = "Port Scanning"
            elif row['attack_count'] > 50 and row['services_targeted'] > 2:
                attack_type = "Targeted Attack"
            else:
                attack_type = "General Probing"
            
            classifications.append({
                'ip': row['src_ip'],
                'type': attack_type,
                'risk_score': min(100, (row['attack_count'] / 10) + 
                                  (row['services_targeted'] * 15))
            })
        
        return pd.DataFrame(classifications)
    
    def generate_ml_report(self):
        """Generate comprehensive ML analysis report"""
        print("\n" + "="*70)
        print("🤖 MACHINE LEARNING ANOMALY DETECTION REPORT")
        print("="*70 + "\n")
        
        # Fetch data
        df = self.fetch_attack_data("7d")
        if df is None or len(df) == 0:
            print("❌ No data available")
            return
        
        print(f"📊 Analyzed {len(df)} unique attacking IPs\n")
        
        # Prepare features
        features = self.prepare_features(df)
        
        # Train Isolation Forest
        predictions, anomaly_scores = self.train_isolation_forest(features)
        
        # Add predictions to dataframe
        df['is_anomaly'] = predictions
        df['anomaly_score'] = anomaly_scores
        
        # Detect patterns
        patterns = self.detect_attack_patterns(df)
        
        # Classify attacks
        classifications = self.classify_attacks(df)
        
        # Print results
        print("🎯 ATTACK PATTERNS DETECTED:")
        print(f"  • Brute Force Attempts: {patterns['brute_force']}")
        print(f"  • Reconnaissance: {patterns['reconnaissance']}")
        print(f"  • Port Scanning: {patterns['port_scanning']}")
        print(f"  • Targeted Attacks: {patterns['targeted']}\n")
        
        print("⚠️ ANOMALIES DETECTED:")
        anomalies = df[df['is_anomaly'] == -1]
        print(f"  Total: {len(anomalies)}\n")
        
        if len(anomalies) > 0:
            print("  Top Anomalous IPs:")
            for idx, row in anomalies.head(5).iterrows():
                print(f"    • {row['src_ip']} - Score: {row['anomaly_score']:.2f}")
        
        print("\n🏆 TOP RISK IPS:")
        top_risk = classifications.nlargest(10, 'risk_score')
        for idx, row in top_risk.iterrows():
            print(f"  • {row['ip']} ({row['type']}) - Risk: {row['risk_score']:.1f}")
        
        print("\n📈 ATTACK TYPE DISTRIBUTION:")
        type_dist = classifications['type'].value_counts()
        for attack_type, count in type_dist.items():
            print(f"  • {attack_type}: {count}")
        
        # Export results
        self.export_results(df, classifications, patterns)
        
        print("\n" + "="*70)
        print("✅ Report Complete")
        print("="*70 + "\n")
    
    def export_results(self, df, classifications, patterns):
        """Export ML results"""
        print("💾 Exporting results...")
        
        # Export to JSON
        results = {
            'timestamp': datetime.now().isoformat(),
            'anomalies': df[df['is_anomaly'] == -1].to_dict('records'),
            'classifications': classifications.to_dict('records'),
            'patterns': patterns
        }
        
        filepath = f"/tmp/ml-anomaly-report-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"✅ Results exported to: {filepath}")
        
        # Export to CSV
        classifications.to_csv(
            f"/tmp/attack-classifications-{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            index=False
        )
        
        print(f"✅ Classifications exported to CSV")

def main():
    import sys
    
    detector = AnomalyDetector()
    
    if len(sys.argv) < 2:
        detector.generate_ml_report()
    else:
        action = sys.argv[1]
        if action == "analyze":
            detector.generate_ml_report()
        elif action == "train":
            df = detector.fetch_attack_data("7d")
            if df is not None:
                features = detector.prepare_features(df)
                detector.train_isolation_forest(features)
        else:
            print("Usage: ml-anomaly-detection.py [analyze|train]")

if __name__ == "__main__":
    main()

