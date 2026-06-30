#!/usr/bin/env python3

################################################################################
# Machine Learning - Attack Trend Prediction
# Predict future attack patterns and trends
################################################################################

import requests
import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import PolynomialFeatures
import warnings
warnings.filterwarnings('ignore')

class TrendPredictor:
    def __init__(self, es_url="https://localhost:9200",
                 username="elastic", password="changeme"):
        self.es_url = es_url
        self.username = username
        self.password = password
        self.verify_ssl = False
    
    def fetch_time_series_data(self, period="30d", interval="1d"):
        """Fetch attack volume time series data"""
        print("📊 Fetching time series data...")
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
                        "over_time": {
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
            
            data = []
            for bucket in response.json()['aggregations']['over_time']['buckets']:
                data.append({
                    'timestamp': bucket['key_as_string'],
                    'count': bucket['doc_count']
                })
            
            return pd.DataFrame(data)
        except Exception as e:
            print(f"❌ Error fetching time series: {e}")
            return None
    
    def predict_next_period(self, df, periods=7):
        """Predict attack volume for next N periods"""
        print(f"🔮 Predicting next {periods} periods...")
        
        if len(df) < 3:
            print("❌ Not enough historical data")
            return None
        
        # Prepare data
        X = np.arange(len(df)).reshape(-1, 1)
        y = df['count'].values
        
        # Linear regression
        lr_model = LinearRegression()
        lr_model.fit(X, y)
        
        # Polynomial regression (degree 2) for better fit
        poly_features = PolynomialFeatures(degree=2)
        X_poly = poly_features.fit_transform(X)
        poly_model = LinearRegression()
        poly_model.fit(X_poly, y)
        
        # Predict future
        future_X = np.arange(len(df), len(df) + periods).reshape(-1, 1)
        future_X_poly = poly_features.transform(future_X)
        
        predictions_linear = lr_model.predict(future_X)
        predictions_poly = poly_model.predict(future_X_poly)
        
        # Use average of both models
        predictions = (predictions_linear + predictions_poly) / 2
        predictions = np.maximum(predictions, 0)  # No negative values
        
        return predictions.astype(int)
    
    def calculate_growth_rate(self, df):
        """Calculate attack growth rate"""
        if len(df) < 2:
            return 0
        
        recent = df['count'].tail(7).mean()
        previous = df['count'].iloc[:7].mean() if len(df) >= 14 else df['count'].mean()
        
        if previous == 0:
            return 0
        
        growth = ((recent - previous) / previous) * 100
        return growth
    
    def detect_attack_surge(self, df, threshold_std=2):
        """Detect unusual attack surges"""
        mean = df['count'].mean()
        std = df['count'].std()
        
        threshold = mean + (threshold_std * std)
        surges = df[df['count'] > threshold]
        
        return surges
    
    def forecast_peak_times(self, df):
        """Forecast when attacks are likely to peak"""
        # Find top 3 attack days
        top_days = df.nlargest(3, 'count')
        
        predictions = []
        for idx, row in top_days.iterrows():
            day_of_week = pd.to_datetime(row['timestamp']).day_name()
            predictions.append({
                'date': row['timestamp'],
                'day': day_of_week,
                'attacks': row['count']
            })
        
        return predictions
    
    def generate_prediction_report(self):
        """Generate trend prediction report"""
        print("\n" + "="*80)
        print("🔮 ATTACK TREND PREDICTION REPORT")
        print("="*80 + "\n")
        
        # Fetch historical data (30 days)
        df = self.fetch_time_series_data("30d", "1d")
        if df is None or len(df) == 0:
            print("❌ No data available")
            return
        
        print(f"📊 Analyzed {len(df)} days of attack data\n")
        
        # Calculate metrics
        avg_daily_attacks = df['count'].mean()
        max_daily_attacks = df['count'].max()
        min_daily_attacks = df['count'].min()
        growth_rate = self.calculate_growth_rate(df)
        
        print("📈 HISTORICAL METRICS (Last 30 days):")
        print(f"  • Average Daily Attacks: {avg_daily_attacks:.0f}")
        print(f"  • Maximum Daily Attacks: {max_daily_attacks:.0f}")
        print(f"  • Minimum Daily Attacks: {min_daily_attacks:.0f}")
        print(f"  • Growth Rate: {growth_rate:+.1f}%\n")
        
        # Predict next 7 days
        predictions = self.predict_next_period(df, periods=7)
        
        if predictions is not None:
            print("🔮 7-DAY FORECAST:")
            print("-" * 80)
            print(f"{'Day':<15} {'Predicted Attacks':<20} {'Trend':<15}")
            print("-" * 80)
            
            for i, pred in enumerate(predictions):
                day = (datetime.now() + timedelta(days=i+1)).strftime("%Y-%m-%d")
                if i > 0:
                    trend = "↑" if pred > predictions[i-1] else "↓" if pred < predictions[i-1] else "→"
                else:
                    trend = "→"
                print(f"{day:<15} {pred:<20} {trend:<15}")
            
            print("\n📊 7-DAY FORECAST STATISTICS:")
            print(f"  • Average Predicted Attacks: {predictions.mean():.0f}")
            print(f"  • Predicted Peak: {predictions.max():.0f}")
            print(f"  • Predicted Low: {predictions.min():.0f}")
        
        # Detect surges
        surges = self.detect_attack_surge(df)
        if len(surges) > 0:
            print(f"\n⚠️  ATTACK SURGES DETECTED ({len(surges)} days):")
            for idx, row in surges.iterrows():
                print(f"  • {row['timestamp']}: {row['count']:.0f} attacks")
        else:
            print("\n✅ No unusual attack surges detected")
        
        # Peak time forecast
        peak_days = self.forecast_peak_times(df)
        print("\n📅 LIKELY PEAK ATTACK TIMES:")
        for peak in peak_days:
            print(f"  • {peak['date'][:10]} ({peak['day']}): {peak['attacks']:.0f} attacks")
        
        # Generate insights
        print("\n💡 INSIGHTS & RECOMMENDATIONS:")
        
        if growth_rate > 20:
            print("  ⚠️  Attack volume increasing rapidly - heighten monitoring")
        elif growth_rate > 5:
            print("  ⚠️  Slow attack volume increase - monitor for escalation")
        elif growth_rate < -20:
            print("  ✅ Attack volume decreasing - security measures effective")
        
        if predictions is not None:
            avg_pred = predictions.mean()
            if avg_pred > avg_daily_attacks * 1.3:
                print("  ⚠️  Expect higher attack volumes next week")
            elif avg_pred < avg_daily_attacks * 0.7:
                print("  ✅ Attack volumes expected to decrease")
        
        if len(surges) > 0:
            print(f"  ⚠️  {len(surges)} unusual surge(s) detected - investigate causes")
        
        # Export results
        self.export_results(df, predictions)
        
        print("\n" + "="*80)
        print("✅ Trend Prediction Report Complete")
        print("="*80 + "\n")
    
    def export_results(self, df, predictions):
        """Export prediction results"""
        print("💾 Exporting results...")
        
        # Export to JSON
        results = {
            'timestamp': datetime.now().isoformat(),
            'historical_data': df.to_dict('records'),
            'predictions': predictions.tolist() if predictions is not None else None
        }
        
        filepath = f"/tmp/trend-prediction-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"✅ Results exported to: {filepath}")

def main():
    import sys
    
    predictor = TrendPredictor()
    
    if len(sys.argv) < 2:
        predictor.generate_prediction_report()
    else:
        action = sys.argv[1]
        if action == "predict":
            predictor.generate_prediction_report()
        else:
            print("Usage: ml-trend-prediction.py [predict]")

if __name__ == "__main__":
    main()

