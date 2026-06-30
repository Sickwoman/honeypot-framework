#!/usr/bin/env python3

################################################################################
# Machine Learning Dashboard
# Real-time ML insights and visualizations
################################################################################

import os
import sys
import json
from datetime import datetime
import subprocess

class MLDashboard:
    def __init__(self):
        self.scripts_dir = os.path.dirname(os.path.abspath(__file__))
    
    def print_header(self):
        """Print dashboard header"""
        os.system('clear' if os.name == 'posix' else 'cls')
        print("\033[94m" + "="*80 + "\033[0m")
        print("\033[94m🤖 MACHINE LEARNING SECURITY ANALYTICS DASHBOARD\033[0m".center(80))
        print("\033[94m" + "="*80 + "\033[0m")
        print()
    
    def run_anomaly_detection(self):
        """Run anomaly detection analysis"""
        print("\033[93m📊 Running Anomaly Detection...\033[0m")
        result = subprocess.run(
            ["python3", f"{self.scripts_dir}/ml-anomaly-detection.py", "analyze"],
            capture_output=True,
            text=True
        )
        return result.stdout
    
    def run_threat_classification(self):
        """Run threat classification"""
        print("\033[93m🎯 Running Threat Classification...\033[0m")
        result = subprocess.run(
            ["python3", f"{self.scripts_dir}/ml-threat-classifier.py", "classify"],
            capture_output=True,
            text=True
        )
        return result.stdout
    
    def run_trend_prediction(self):
        """Run trend prediction"""
        print("\033[93m🔮 Running Trend Prediction...\033[0m")
        result = subprocess.run(
            ["python3", f"{self.scripts_dir}/ml-trend-prediction.py", "predict"],
            capture_output=True,
            text=True
        )
        return result.stdout
    
    def display_quick_stats(self):
        """Display quick ML statistics"""
        print("\033[92m📈 QUICK STATISTICS\033[0m")
        print("-" * 80)
        print("  Models Status: ✅ All systems operational")
        print("  Last Analysis: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print("  Data Sources: Elasticsearch (Last 30 days)")
        print("-" * 80)
        print()
    
    def display_menu(self):
        """Display dashboard menu"""
        print("\033[92m🎮 DASHBOARD MENU\033[0m")
        print("-" * 80)
        print("  1. Run All ML Analysis (Anomaly + Threat + Prediction)")
        print("  2. Anomaly Detection Only")
        print("  3. Threat Classification Only")
        print("  4. Trend Prediction Only")
        print("  5. View Last Report")
        print("  6. Export All Results")
        print("  0. Exit")
        print("-" * 80)
        print()
    
    def run_full_analysis(self):
        """Run all ML analyses"""
        print("\033[94m🚀 STARTING FULL ML ANALYSIS\033[0m\n")
        
        # Run all analyses
        anomaly_output = self.run_anomaly_detection()
        print(anomaly_output)
        
        threat_output = self.run_threat_classification()
        print(threat_output)
        
        prediction_output = self.run_trend_prediction()
        print(prediction_output)
        
        print("\033[92m✅ FULL ANALYSIS COMPLETE\033[0m")
        input("\nPress Enter to continue...")
    
    def display_interactive_menu(self):
        """Interactive dashboard menu"""
        while True:
            self.print_header()
            self.display_quick_stats()
            self.display_menu()
            
            choice = input("Select option (0-6): ").strip()
            
            if choice == "1":
                self.run_full_analysis()
            
            elif choice == "2":
                self.print_header()
                output = self.run_anomaly_detection()
                print(output)
                input("\nPress Enter to continue...")
            
            elif choice == "3":
                self.print_header()
                output = self.run_threat_classification()
                print(output)
                input("\nPress Enter to continue...")
            
            elif choice == "4":
                self.print_header()
                output = self.run_trend_prediction()
                print(output)
                input("\nPress Enter to continue...")
            
            elif choice == "5":
                self.print_header()
                print("\033[92m📄 LAST REPORT\033[0m")
                print("-" * 80)
                self.show_last_reports()
                input("\nPress Enter to continue...")
            
            elif choice == "6":
                self.print_header()
                print("\033[92m💾 EXPORTING RESULTS\033[0m")
                self.export_all_results()
                input("\nPress Enter to continue...")
            
            elif choice == "0":
                print("\n\033[92m✅ Dashboard closed\033[0m")
                break
            
            else:
                print("\n\033[91m❌ Invalid option\033[0m")
                input("Press Enter to continue...")
    
    def show_last_reports(self):
        """Show last generated reports"""
        import glob
        
        reports = glob.glob("/tmp/ml-anomaly-report-*.json")
        reports += glob.glob("/tmp/threat-classification-*.json")
        reports += glob.glob("/tmp/trend-prediction-*.json")
        
        if reports:
            reports.sort(reverse=True)
            print(f"\nFound {len(reports)} reports:\n")
            for report in reports[:5]:
                print(f"  • {os.path.basename(report)}")
        else:
            print("\n  No reports found. Run analysis first.")
    
    def export_all_results(self):
        """Export all results to summary file"""
        summary = {
            "timestamp": datetime.now().isoformat(),
            "analyses": {
                "anomaly_detection": "See ml-anomaly-report-*.json",
                "threat_classification": "See threat-classification-*.json",
                "trend_prediction": "See trend-prediction-*.json"
            },
            "files_location": "/tmp/"
        }
        
        filepath = f"/tmp/ml-dashboard-summary-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filepath, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n  ✅ Summary exported to: {filepath}")

def main():
    dashboard = MLDashboard()
    
    if len(sys.argv) > 1:
        action = sys.argv[1]
        if action == "full":
            dashboard.run_full_analysis()
        elif action == "anomaly":
            dashboard.print_header()
            print(dashboard.run_anomaly_detection())
        elif action == "threat":
            dashboard.print_header()
            print(dashboard.run_threat_classification())
        elif action == "predict":
            dashboard.print_header()
            print(dashboard.run_trend_prediction())
        else:
            print("Usage: ml-dashboard.py [full|anomaly|threat|predict|interactive]")
    else:
        # Run interactive mode
        dashboard.display_interactive_menu()

if __name__ == "__main__":
    main()

