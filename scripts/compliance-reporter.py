#!/usr/bin/env python3

################################################################################
# Compliance Reporting System
# Generates SOC2, PCI-DSS, HIPAA compliance reports from honeypot logs
################################################################################

import csv
import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import es_client
import requests

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('compliance-audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ComplianceStandard(Enum):
    SOC2 = "SOC2"
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"


@dataclass
class ComplianceEvidence:
    """Represents a compliance control evidence item"""
    control_id: str
    standard: str
    control_name: str
    evidence_type: str
    description: str
    evidence_data: Dict[str, Any]
    timestamp: str
    status: str  # pass, fail, n/a
    severity: str  # critical, high, medium, low
    remediation: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ComplianceReporter:
    """Main compliance reporting engine"""
    
    def __init__(self, es_url: str = None,
                 username: str = None,
                 password: str = None,
                 verify_ssl=None):
        self.es_url = es_url or es_client.url()
        self.username = username or es_client.username()
        self.password = password or es_client.password()
        self.verify_ssl = es_client.verify() if verify_ssl is None else verify_ssl
        self.evidence_trail: List[ComplianceEvidence] = []
        
        logger.info(f"Initialized ComplianceReporter for {es_url}")
    
    def query_elasticsearch(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Query Elasticsearch for compliance evidence"""
        try:
            response = requests.get(
                f"{self.es_url}/honeypot-*/_search",
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                json=query,
                timeout=30
            )
            response.raise_for_status()
            results = response.json()
            return [hit["_source"] for hit in results.get("hits", {}).get("hits", [])]
        except Exception as e:
            logger.error(f"Elasticsearch query failed: {e}")
            return []
    
    # ==================== SOC2 COMPLIANCE CHECKS ====================
    
    def check_soc2_access_control(self) -> ComplianceEvidence:
        """SOC2 CC6: Logical and Physical Access Controls"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event_type": "authentication"}},
                        {"range": {"@timestamp": {"gte": "now-30d"}}}
                    ]
                }
            },
            "aggs": {
                "auth_events": {"value_count": {"field": "_id"}},
                "failed_logins": {
                    "filter": {"term": {"status": "failed"}}
                }
            },
            "size": 10000
        }
        
        results = self.query_elasticsearch(query)
        failed_count = len([r for r in results if r.get("status") == "failed"])
        passed = len(results) > 0 and failed_count < len(results) * 0.1
        
        evidence = ComplianceEvidence(
            control_id="CC6.1",
            standard="SOC2",
            control_name="Logical Access Controls",
            evidence_type="authentication_logs",
            description="Verify honeypot authentication logging and access restrictions",
            evidence_data={
                "total_auth_events": len(results),
                "failed_logins": failed_count,
                "period": "30 days",
                "compliance_rate": round((1 - failed_count/max(len(results), 1)) * 100, 2)
            },
            timestamp=datetime.now().isoformat(),
            status="pass" if passed else "fail",
            severity="high",
            remediation="Implement stronger authentication policies and monitor failed login attempts"
        )
        
        self.evidence_trail.append(evidence)
        return evidence
    
    def check_soc2_change_management(self) -> ComplianceEvidence:
        """SOC2 CC7: Change Management"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event_type": "configuration_change"}},
                        {"range": {"@timestamp": {"gte": "now-30d"}}}
                    ]
                }
            },
            "aggs": {
                "changes_count": {"value_count": {"field": "_id"}},
                "by_component": {
                    "terms": {"field": "component", "size": 20}
                }
            },
            "size": 5000
        }
        
        results = self.query_elasticsearch(query)
        
        evidence = ComplianceEvidence(
            control_id="CC7.1",
            standard="SOC2",
            control_name="Change Management",
            evidence_type="change_logs",
            description="Track all configuration changes to honeypot infrastructure",
            evidence_data={
                "total_changes": len(results),
                "period": "30 days",
                "changes_tracked": results[:10] if results else []
            },
            timestamp=datetime.now().isoformat(),
            status="pass" if len(results) > 0 else "fail",
            severity="high",
            remediation="Implement centralized change tracking and approval workflows"
        )
        
        self.evidence_trail.append(evidence)
        return evidence
    
    def check_soc2_availability(self) -> ComplianceEvidence:
        """SOC2 A1: Availability - System monitoring and uptime"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event_type": "health_check"}},
                        {"range": {"@timestamp": {"gte": "now-30d"}}}
                    ]
                }
            },
            "aggs": {
                "uptime_checks": {"value_count": {"field": "_id"}},
                "successful": {
                    "filter": {"term": {"status": "healthy"}}
                }
            },
            "size": 10000
        }
        
        results = self.query_elasticsearch(query)
        healthy = len([r for r in results if r.get("status") == "healthy"])
        uptime_percentage = round((healthy / max(len(results), 1)) * 100, 2)
        passed = uptime_percentage >= 99.5
        
        evidence = ComplianceEvidence(
            control_id="A1.1",
            standard="SOC2",
            control_name="System Availability",
            evidence_type="health_monitoring",
            description="Monitor and document honeypot system availability",
            evidence_data={
                "total_checks": len(results),
                "healthy_checks": healthy,
                "uptime_percentage": uptime_percentage,
                "period": "30 days"
            },
            timestamp=datetime.now().isoformat(),
            status="pass" if passed else "fail",
            severity="high"
        )
        
        self.evidence_trail.append(evidence)
        return evidence
    
    # ==================== PCI-DSS COMPLIANCE CHECKS ====================
    
    def check_pci_dss_network_segmentation(self) -> ComplianceEvidence:
        """PCI-DSS Requirement 1: Network Segmentation"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event_type": "network_access"}},
                        {"range": {"@timestamp": {"gte": "now-30d"}}}
                    ]
                }
            },
            "aggs": {
                "network_segments": {
                    "terms": {"field": "network_segment", "size": 20}
                },
                "cross_segment_traffic": {
                    "filter": {
                        "term": {"cross_segment": True}
                    }
                }
            },
            "size": 5000
        }
        
        results = self.query_elasticsearch(query)
        cross_segment = len([r for r in results if r.get("cross_segment")])
        passed = cross_segment == 0
        
        evidence = ComplianceEvidence(
            control_id="REQ1",
            standard="PCI-DSS",
            control_name="Network Segmentation",
            evidence_type="network_logs",
            description="Verify honeypot is isolated from payment systems",
            evidence_data={
                "total_network_events": len(results),
                "cross_segment_connections": cross_segment,
                "segments_identified": len(set(r.get("network_segment") for r in results)),
                "period": "30 days"
            },
            timestamp=datetime.now().isoformat(),
            status="pass" if passed else "fail",
            severity="critical",
            remediation="Ensure honeypot VPC/network is completely isolated from production systems"
        )
        
        self.evidence_trail.append(evidence)
        return evidence
    
    def check_pci_dss_encryption(self) -> ComplianceEvidence:
        """PCI-DSS Requirement 4: Encryption in Transit"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event_type": "network_connection"}},
                        {"range": {"@timestamp": {"gte": "now-30d"}}}
                    ]
                }
            },
            "aggs": {
                "encrypted_connections": {
                    "filter": {"term": {"encrypted": True}}
                },
                "protocols": {
                    "terms": {"field": "protocol", "size": 20}
                }
            },
            "size": 10000
        }
        
        results = self.query_elasticsearch(query)
        encrypted = len([r for r in results if r.get("encrypted")])
        encryption_rate = round((encrypted / max(len(results), 1)) * 100, 2)
        passed = encryption_rate >= 95
        
        evidence = ComplianceEvidence(
            control_id="REQ4",
            standard="PCI-DSS",
            control_name="Encryption in Transit",
            evidence_type="network_encryption",
            description="Verify honeypot uses encryption for sensitive data transmission",
            evidence_data={
                "total_connections": len(results),
                "encrypted_connections": encrypted,
                "encryption_rate": encryption_rate,
                "period": "30 days"
            },
            timestamp=datetime.now().isoformat(),
            status="pass" if passed else "fail",
            severity="critical",
            remediation="Enforce TLS/SSL for all internal and external communications"
        )
        
        self.evidence_trail.append(evidence)
        return evidence
    
    def check_pci_dss_logging(self) -> ComplianceEvidence:
        """PCI-DSS Requirement 10: Logging and Monitoring"""
        query = {
            "query": {
                "range": {"@timestamp": {"gte": "now-30d"}}
            },
            "aggs": {
                "log_volume": {"value_count": {"field": "_id"}},
                "log_retention": {
                    "min": {"field": "@timestamp"}
                }
            },
            "size": 1
        }
        
        results = self.query_elasticsearch(query)
        log_count = len(results)
        passed = log_count > 0
        
        evidence = ComplianceEvidence(
            control_id="REQ10",
            standard="PCI-DSS",
            control_name="Logging and Monitoring",
            evidence_type="audit_logs",
            description="Verify comprehensive logging of honeypot events",
            evidence_data={
                "logs_stored": log_count,
                "retention_period": "30+ days",
                "period": "30 days",
                "log_sources": ["authentication", "network", "system", "application"]
            },
            timestamp=datetime.now().isoformat(),
            status="pass" if passed else "fail",
            severity="high"
        )
        
        self.evidence_trail.append(evidence)
        return evidence
    
    # ==================== HIPAA COMPLIANCE CHECKS ====================
    
    def check_hipaa_access_controls(self) -> ComplianceEvidence:
        """HIPAA Security Rule 45 CFR 164.312(a)(2)(i)"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event_type": "access_control"}},
                        {"range": {"@timestamp": {"gte": "now-30d"}}}
                    ]
                }
            },
            "aggs": {
                "user_access": {
                    "terms": {"field": "user_id", "size": 100}
                },
                "unauthorized_attempts": {
                    "filter": {"term": {"authorized": False}}
                }
            },
            "size": 5000
        }
        
        results = self.query_elasticsearch(query)
        unauthorized = len([r for r in results if not r.get("authorized")])
        passed = unauthorized == 0
        
        evidence = ComplianceEvidence(
            control_id="164.312(a)(2)(i)",
            standard="HIPAA",
            control_name="Access Controls",
            evidence_type="access_logs",
            description="Verify unique user identification and access controls",
            evidence_data={
                "total_access_events": len(results),
                "unauthorized_attempts": unauthorized,
                "unique_users": len(set(r.get("user_id") for r in results)),
                "period": "30 days"
            },
            timestamp=datetime.now().isoformat(),
            status="pass" if passed else "fail",
            severity="critical",
            remediation="Implement multi-factor authentication and access reviews"
        )
        
        self.evidence_trail.append(evidence)
        return evidence
    
    def check_hipaa_audit_controls(self) -> ComplianceEvidence:
        """HIPAA Security Rule 45 CFR 164.312(b)"""
        query = {
            "query": {
                "range": {"@timestamp": {"gte": "now-6m"}}
            },
            "aggs": {
                "audit_records": {"value_count": {"field": "_id"}},
                "by_event_type": {
                    "terms": {"field": "event_type", "size": 50}
                }
            },
            "size": 1
        }
        
        results = self.query_elasticsearch(query)
        
        evidence = ComplianceEvidence(
            control_id="164.312(b)",
            standard="HIPAA",
            control_name="Audit Controls",
            evidence_type="audit_logs",
            description="Verify audit logging and review procedures",
            evidence_data={
                "audit_records_6m": len(results),
                "retention_period": "6 months",
                "review_frequency": "weekly"
            },
            timestamp=datetime.now().isoformat(),
            status="pass" if len(results) > 0 else "fail",
            severity="high"
        )
        
        self.evidence_trail.append(evidence)
        return evidence
    
    def check_hipaa_encryption(self) -> ComplianceEvidence:
        """HIPAA Security Rule 45 CFR 164.312(a)(2)(ii)"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event_type": "data_transmission"}},
                        {"range": {"@timestamp": {"gte": "now-30d"}}}
                    ]
                }
            },
            "aggs": {
                "encrypted_transmissions": {
                    "filter": {"term": {"encryption_status": "encrypted"}}
                },
                "encryption_algorithms": {
                    "terms": {"field": "encryption_algorithm", "size": 20}
                }
            },
            "size": 5000
        }
        
        results = self.query_elasticsearch(query)
        encrypted = len([r for r in results if r.get("encryption_status") == "encrypted"])
        encryption_rate = round((encrypted / max(len(results), 1)) * 100, 2)
        passed = encryption_rate >= 99.5
        
        evidence = ComplianceEvidence(
            control_id="164.312(a)(2)(ii)",
            standard="HIPAA",
            control_name="Encryption and Decryption",
            evidence_type="encryption_logs",
            description="Verify encryption of all data at rest and in transit",
            evidence_data={
                "total_transmissions": len(results),
                "encrypted_transmissions": encrypted,
                "encryption_rate": encryption_rate,
                "algorithms": list(set(r.get("encryption_algorithm") for r in results))
            },
            timestamp=datetime.now().isoformat(),
            status="pass" if passed else "fail",
            severity="critical"
        )
        
        self.evidence_trail.append(evidence)
        return evidence
    
    # ==================== REPORT GENERATION ====================
    
    def generate_evidence_csv(self, output_path: str) -> str:
        """Export evidence trail to CSV"""
        try:
            with open(output_path, 'w', newline='') as f:
                if not self.evidence_trail:
                    logger.warning("No evidence collected")
                    return output_path
                
                writer = csv.DictWriter(f, fieldnames=[
                    'control_id', 'standard', 'control_name', 'evidence_type',
                    'description', 'timestamp', 'status', 'severity', 'remediation'
                ])
                writer.writeheader()
                
                for evidence in self.evidence_trail:
                    row = asdict(evidence)
                    row.pop('evidence_data')  # Remove complex dict for CSV
                    writer.writerow(row)
            
            logger.info(f"Evidence exported to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to generate CSV: {e}")
            return ""
    
    def generate_evidence_json(self, output_path: str) -> str:
        """Export evidence trail to JSON"""
        try:
            data = {
                "report_generated": datetime.now().isoformat(),
                "total_controls_tested": len(self.evidence_trail),
                "passed_controls": len([e for e in self.evidence_trail if e.status == "pass"]),
                "failed_controls": len([e for e in self.evidence_trail if e.status == "fail"]),
                "evidence": [e.to_dict() for e in self.evidence_trail]
            }
            
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Evidence exported to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to generate JSON: {e}")
            return ""
    
    def generate_pdf_report(self, output_path: str, standard: str = "ALL") -> str:
        """Generate formatted PDF compliance report"""
        if not HAS_REPORTLAB:
            logger.error("reportlab not installed. Install with: pip install reportlab")
            return ""
        
        try:
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            elements = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1f77b4'),
                spaceAfter=30,
                alignment=1
            )
            elements.append(Paragraph(f"Compliance Report - {standard}", title_style))
            elements.append(Spacer(1, 0.3*inch))
            
            # Report info
            report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            info_style = ParagraphStyle('Info', parent=styles['Normal'], fontSize=10)
            elements.append(Paragraph(f"Report Generated: {report_date}", info_style))
            elements.append(Spacer(1, 0.2*inch))
            
            # Summary
            summary_data = [
                ['Metric', 'Value'],
                ['Total Controls', str(len(self.evidence_trail))],
                ['Passed', str(len([e for e in self.evidence_trail if e.status == "pass"]))],
                ['Failed', str(len([e for e in self.evidence_trail if e.status == "fail"]))],
            ]
            
            summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(summary_table)
            elements.append(Spacer(1, 0.3*inch))
            
            # Evidence details
            elements.append(Paragraph("Detailed Findings", styles['Heading2']))
            elements.append(Spacer(1, 0.2*inch))
            
            for evidence in self.evidence_trail:
                if standard != "ALL" and evidence.standard != standard:
                    continue
                
                # Control info
                control_text = f"<b>{evidence.control_id}: {evidence.control_name}</b><br/>"
                control_text += f"Status: <b>{evidence.status.upper()}</b> | "
                control_text += f"Severity: {evidence.severity}<br/>"
                control_text += f"{evidence.description}"
                
                elements.append(Paragraph(control_text, styles['Normal']))
                elements.append(Spacer(1, 0.1*inch))
                
                if evidence.remediation:
                    elements.append(Paragraph(
                        f"<i>Remediation: {evidence.remediation}</i>",
                        styles['Normal']
                    ))
                
                elements.append(Spacer(1, 0.2*inch))
            
            doc.build(elements)
            logger.info(f"PDF report generated: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to generate PDF: {e}")
            return ""
    
    def generate_all_reports(self, compliance_standard: ComplianceStandard) -> Dict[str, str]:
        """Run all compliance checks for a given standard and generate reports"""
        logger.info(f"Generating {compliance_standard.value} compliance reports...")
        
        if compliance_standard == ComplianceStandard.SOC2:
            self.check_soc2_access_control()
            self.check_soc2_change_management()
            self.check_soc2_availability()
        elif compliance_standard == ComplianceStandard.PCI_DSS:
            self.check_pci_dss_network_segmentation()
            self.check_pci_dss_encryption()
            self.check_pci_dss_logging()
        elif compliance_standard == ComplianceStandard.HIPAA:
            self.check_hipaa_access_controls()
            self.check_hipaa_audit_controls()
            self.check_hipaa_encryption()
        
        # Generate output files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        standard_name = compliance_standard.value.replace("-", "_")
        output_dir = f"compliance_reports/{standard_name}/{timestamp}"
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        reports = {
            "json": self.generate_evidence_json(f"{output_dir}/evidence.json"),
            "csv": self.generate_evidence_csv(f"{output_dir}/evidence.csv"),
            "pdf": self.generate_pdf_report(f"{output_dir}/report.pdf", standard_name)
        }
        
        logger.info(f"Reports generated in {output_dir}")
        return reports


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Compliance Reporting System")
    parser.add_argument("--standard", choices=["SOC2", "PCI-DSS", "HIPAA", "ALL"],
                        default="SOC2", help="Compliance standard to audit")
    parser.add_argument("--es-url", default=None,
                        help="Elasticsearch URL (default: $ELASTICSEARCH_URL)")
    parser.add_argument("--username", default=None,
                        help="Elasticsearch username (default: $ELASTICSEARCH_USERNAME)")
    parser.add_argument("--password", default=None,
                        help="Elasticsearch password (default: $ELASTICSEARCH_PASSWORD)")
    parser.add_argument("--no-verify-ssl", action="store_true",
                        help="Disable TLS certificate verification (not recommended)")

    args = parser.parse_args()

    reporter = ComplianceReporter(
        es_url=args.es_url,
        username=args.username,
        password=args.password,
        verify_ssl=False if args.no_verify_ssl else None
    )
    
    standards = [ComplianceStandard[args.standard]] if args.standard != "ALL" else list(ComplianceStandard)
    
    for standard in standards:
        reports = reporter.generate_all_reports(standard)
        print(f"\n{standard.value} Compliance Report:")
        print(f"  JSON: {reports['json']}")
        print(f"  CSV:  {reports['csv']}")
        print(f"  PDF:  {reports['pdf']}")


if __name__ == "__main__":
    main()
