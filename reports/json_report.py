"""
JSON report generator for firewall policy analysis.
"""
import json
import csv
from typing import Dict, Any
from app.reports.base import BaseReportGenerator
from app.models.base import PolicyComparisonResult, ComplianceReport
from app.exceptions.custom_exceptions import ReportGenerationError


class JSONReportGenerator(BaseReportGenerator):
    """Multi-format report generator for firewall policy analysis."""

    def generate_comparison_report(self, comparison_result: PolicyComparisonResult) -> str:
        """
        Generate a JSON comparison report from comparison results.
        
        Args:
            comparison_result: Results from policy comparison
            
        Returns:
            JSON formatted report as string
        """
        report_data = {
            "report_type": "comparison",
            "firewall_a_id": comparison_result.firewall_a_id,
            "firewall_b_id": comparison_result.firewall_b_id,
            "generated_at": __import__('datetime').datetime.utcnow().isoformat(),
            "parity_matrix": comparison_result.parity_matrix,
            "differences": comparison_result.differences,
            "recommendations": comparison_result.recommendations,
            "compliance_gaps": comparison_result.compliance_gaps
        }
        
        return json.dumps(report_data, indent=2)

    def generate_compliance_report(self, compliance_result: ComplianceReport) -> str:
        """
        Generate a JSON compliance report from compliance results.
        
        Args:
            compliance_result: Results from compliance check
            
        Returns:
            JSON formatted report as string
        """
        report_data = {
            "report_type": "compliance",
            "firewall_id": compliance_result.firewall_id,
            "generated_at": __import__('datetime').datetime.utcnow().isoformat(),
            "compliance_status": compliance_result.compliance_status,
            "missing_policies": compliance_result.missing_policies,
            "risk_assessment": compliance_result.risk_assessment
        }
        
        return json.dumps(report_data, indent=2)

    def export_report(self, report_content: str, format: str, filename: str) -> bool:
        """
        Export report to a file.
        
        Args:
            report_content: The report content to export
            format: The format to export to (json, csv)
            filename: The filename to save to
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if format.lower() == 'json':
                with open(filename, 'w') as f:
                    f.write(report_content)
            elif format.lower() == 'csv':
                self._export_to_csv(report_content, filename)
            else:
                raise ReportGenerationError(f"Unsupported format: {format}")
            return True
        except Exception as e:
            raise ReportGenerationError(f"Error exporting report: {str(e)}")

    def _export_to_csv(self, report_content: str, filename: str) -> None:
        """Export report data to CSV format."""
        import json
        
        # Parse the JSON report content
        report_data = json.loads(report_content)
        report_type = report_data.get("report_type", "unknown")
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(["Report Type", "Generated At", "Firewall ID(s)"])
            
            # Write basic info
            if report_type == "comparison":
                writer.writerow([
                    report_type,
                    report_data.get("generated_at", ""),
                    f"{report_data.get('firewall_a_id', '')} vs {report_data.get('firewall_b_id', '')}"
                ])
            else:
                writer.writerow([
                    report_type,
                    report_data.get("generated_at", ""),
                    report_data.get("firewall_id", "")
                ])
            
            # Write section headers and data
            writer.writerow([])  # Empty row
            writer.writerow(["Section", "Details"])
            
            # Write differences (for comparison reports)
            if "differences" in report_data:
                writer.writerow(["Differences", ""])
                for diff in report_data["differences"]:
                    writer.writerow([
                        diff.get("type", ""),
                        diff.get("description", "")
                    ])
                    
            # Write recommendations
            if "recommendations" in report_data:
                writer.writerow([])  # Empty row
                writer.writerow(["Recommendations", ""])
                for rec in report_data["recommendations"]:
                    writer.writerow(["Recommendation", rec])
                    
            # Write compliance gaps
            if "compliance_gaps" in report_data:
                writer.writerow([])  # Empty row
                writer.writerow(["Compliance Gaps", ""])
                for gap in report_data["compliance_gaps"]:
                    writer.writerow([
                        gap.get("type", ""),
                        gap.get("description", "")
                    ])

    def generate_html_report(self, report_content: str) -> str:
        """Generate an HTML report from JSON content."""
        import json
        
        report_data = json.loads(report_content)
        report_type = report_data.get("report_type", "unknown")
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Firewall Policy Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #666; border-bottom: 1px solid #ccc; }}
                table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .section {{ margin: 20px 0; }}
                .recommendation {{ background-color: #e7f3ff; padding: 10px; margin: 5px 0; }}
            </style>
        </head>
        <body>
            <h1>Firewall Policy Analysis Report</h1>
            <p><strong>Report Type:</strong> {report_type}</p>
            <p><strong>Generated At:</strong> {report_data.get("generated_at", "")}</p>
        """
        
        if report_type == "comparison":
            html += f"""
            <p><strong>Firewall A:</strong> {report_data.get('firewall_a_id', '')}</p>
            <p><strong>Firewall B:</strong> {report_data.get('firewall_b_id', '')}</p>
            """
        else:
            html += f"<p><strong>Firewall:</strong> {report_data.get('firewall_id', '')}</p>"
        
        # Add differences section
        if "differences" in report_data and report_data["differences"]:
            html += """
            <div class="section">
                <h2>Differences</h2>
                <table>
                    <tr><th>Type</th><th>Description</th></tr>
            """
            for diff in report_data["differences"]:
                html += f"<tr><td>{diff.get('type', '')}</td><td>{diff.get('description', '')}</td></tr>"
            html += "</table></div>"
        
        # Add recommendations section
        if "recommendations" in report_data and report_data["recommendations"]:
            html += """
            <div class="section">
                <h2>Recommendations</h2>
            """
            for rec in report_data["recommendations"]:
                html += f'<div class="recommendation">{rec}</div>'
            html += "</div>"
        
        # Add compliance gaps section
        if "compliance_gaps" in report_data and report_data["compliance_gaps"]:
            html += """
            <div class="section">
                <h2>Compliance Gaps</h2>
                <table>
                    <tr><th>Type</th><th>Description</th></tr>
            """
            for gap in report_data["compliance_gaps"]:
                html += f"<tr><td>{gap.get('type', '')}</td><td>{gap.get('description', '')}</td></tr>"
            html += "</table></div>"
        
        html += """
        </body>
        </html>
        """
        
        return html