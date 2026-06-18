#!/usr/bin/env python3

################################################################################
# AWS Cost Estimator for Honeypot Framework
# Calculates monthly costs before deploying to AWS
################################################################################

import json
from datetime import datetime

class AWSCostEstimator:
    def __init__(self):
        self.costs = {}
        self.free_tier_limits = {
            'ec2_hours': 750,  # t3.micro
            'cloudwatch_logs_gb': 5,
            's3_storage_gb': 5,
            's3_transfer_out_gb': 1,
        }
        
    def calculate_ec2_costs(self, instances=1, hours_per_month=730, instance_type='t3.micro'):
        """Calculate EC2 costs"""
        # t3.micro: $0.0104/hour (us-east-1)
        hourly_rate = 0.0104
        free_hours = self.free_tier_limits['ec2_hours']
        
        if hours_per_month <= free_hours:
            cost = 0
            status = f"FREE (within {free_hours} hours/month limit)"
        else:
            billable_hours = hours_per_month - free_hours
            cost = billable_hours * hourly_rate * instances
            status = f"${cost:.2f} ({billable_hours} hours over limit)"
        
        self.costs['ec2'] = {
            'cost': cost,
            'status': status,
            'details': f"{instances}x {instance_type} @ {hours_per_month} hours/month"
        }
        return cost
    
    def calculate_cloudwatch_costs(self, log_gb_per_month=2):
        """Calculate CloudWatch Logs costs"""
        # $0.50 per GB ingested
        free_gb = self.free_tier_limits['cloudwatch_logs_gb']
        
        if log_gb_per_month <= free_gb:
            cost = 0
            status = f"FREE (within {free_gb} GB/month limit)"
        else:
            billable_gb = log_gb_per_month - free_gb
            cost = billable_gb * 0.50
            status = f"${cost:.2f} ({billable_gb} GB over limit)"
        
        self.costs['cloudwatch'] = {
            'cost': cost,
            'status': status,
            'details': f"{log_gb_per_month} GB logs/month"
        }
        return cost
    
    def calculate_s3_costs(self, storage_gb=1, transfer_out_gb=0.5):
        """Calculate S3 costs"""
        # Storage: $0.023/GB
        # Transfer: $0.09/GB
        free_storage = self.free_tier_limits['s3_storage_gb']
        free_transfer = self.free_tier_limits['s3_transfer_out_gb']
        
        storage_cost = max(0, (storage_gb - free_storage) * 0.023)
        transfer_cost = max(0, (transfer_out_gb - free_transfer) * 0.09)
        total_cost = storage_cost + transfer_cost
        
        storage_status = "FREE" if storage_gb <= free_storage else f"${storage_cost:.2f}"
        transfer_status = "FREE" if transfer_out_gb <= free_transfer else f"${transfer_cost:.2f}"
        
        self.costs['s3'] = {
            'cost': total_cost,
            'status': f"Storage: {storage_status} | Transfer: {transfer_status}",
            'details': f"{storage_gb} GB storage + {transfer_out_gb} GB transfer/month"
        }
        return total_cost
    
    def calculate_data_transfer_costs(self, gb_between_regions=0):
        """Calculate inter-region data transfer"""
        # $0.02/GB between regions
        cost = gb_between_regions * 0.02
        
        status = "FREE" if cost == 0 else f"${cost:.2f}"
        
        self.costs['data_transfer'] = {
            'cost': cost,
            'status': status,
            'details': f"{gb_between_regions} GB inter-region transfer/month"
        }
        return cost
    
    def calculate_total(self):
        """Calculate total monthly cost"""
        total = sum(service['cost'] for service in self.costs.values())
        return total
    
    def print_report(self):
        """Print formatted cost report"""
        print("\n" + "="*70)
        print(" 💰 AWS COST ESTIMATION FOR HONEYPOT FRAMEWORK".center(70))
        print("="*70)
        
        print("\n📊 SERVICE COSTS:\n")
        
        for service, details in self.costs.items():
            service_name = service.upper()
            cost = details['cost']
            status = details['status']
            config = details['details']
            
            print(f"  {service_name}")
            print(f"    Cost: {status}")
            print(f"    Config: {config}")
            print()
        
        total = self.calculate_total()
        print("="*70)
        print(f"  TOTAL MONTHLY COST: ${total:.2f}".center(70))
        print("="*70)
        
        print("\n✅ FREE TIER BREAKDOWN:\n")
        print(f"  • EC2: {self.free_tier_limits['ec2_hours']} hours/month (t3.micro)")
        print(f"  • CloudWatch: {self.free_tier_limits['cloudwatch_logs_gb']} GB logs/month")
        print(f"  • S3: {self.free_tier_limits['s3_storage_gb']} GB storage + {self.free_tier_limits['s3_transfer_out_gb']} GB transfer")
        print(f"  • Credits: $100 USD (185 days remaining)")
        
        print("\n💡 RECOMMENDATIONS:\n")
        
        if total == 0:
            print("  ✅ All costs within FREE TIER limits!")
            print("     You can run this for 12 months FREE")
        elif total < 5:
            print(f"  ✅ Costs (~${total:.2f}/month) easily covered by $100 credit")
            print(f"     ~{int(100/total)} months of free operation")
        else:
            print(f"  ⚠️  Monthly cost (~${total:.2f}) exceeds free tier")
            print("     Consider: Reducing log retention, consolidating regions")
        
        print("\n📈 COST OPTIMIZATION TIPS:\n")
        print("  1. Use t3.micro (free tier eligible)")
        print("  2. Limit CloudWatch log retention to 30 days")
        print("  3. Use S3 Glacier for long-term storage (cheaper)")
        print("  4. Deploy single region initially (us-east-1)")
        print("  5. Monitor actual usage via AWS Cost Explorer")
        
        print("\n" + "="*70 + "\n")
    
    def export_json(self, filename='cost-estimate.json'):
        """Export estimate to JSON file"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'services': self.costs,
            'total_monthly': self.calculate_total(),
            'free_tier_limits': self.free_tier_limits
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📄 Cost estimate exported to: {filename}")

def main():
    estimator = AWSCostEstimator()
    
    # Default honeypot framework configuration
    print("\n🔧 Calculating costs for:")
    print("  • 1x t3.micro EC2 instance (us-east-1)")
    print("  • CloudWatch Logs (honeypot events)")
    print("  • S3 bucket (log archival)")
    print("  • Single region deployment\n")
    
    # Calculate costs
    estimator.calculate_ec2_costs(instances=1, hours_per_month=730)
    estimator.calculate_cloudwatch_costs(log_gb_per_month=2)
    estimator.calculate_s3_costs(storage_gb=1, transfer_out_gb=0.5)
    estimator.calculate_data_transfer_costs(gb_between_regions=0)
    
    # Print report
    estimator.print_report()
    
    # Export to file
    estimator.export_json('/tmp/honeypot-cost-estimate.json')

if __name__ == "__main__":
    main()
