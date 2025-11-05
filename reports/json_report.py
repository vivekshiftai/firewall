"""
JSON report generator for firewall policy analysis.
"""
import logging
import json
from typing import Dict, Any
from reports.base import BaseReportGenerator
from models.base import PolicyComparisonResult, ComplianceReport

# Configure logging
logger = logging.getLogger(__name__)

class JSONReportGenerator(BaseReportGenerator):
    """JSON report generator for firewall policy analysis."""

    def generate_comparison_report(self, comparison_result: PolicyComparisonResult) -> str:
        """
        Generate a JSON comparison report from comparison results.
        
        Args:
            comparison_result: Results from policy comparison
            
        Returns:
            Formatted JSON report as string
        """
        logger.info("Generating JSON comparison report")
        try:
            logger.debug("Converting comparison result to dictionary")
            report_dict = comparison_result.dict()
            logger.debug("Converting dictionary to JSON string")
            report_json = json.dumps(report_dict, indent=2)
            logger.info("JSON comparison report generated successfully")
            return report_json
        except Exception as e:
            logger.error(f"Error generating JSON comparison report: {str(e)}")
            raise

    def generate_compliance_report(self, compliance_result: ComplianceReport) -> str:
        """
        Generate a JSON compliance report from compliance results.
        
        Args:
            compliance_result: Results from compliance check
            
        Returns:
            Formatted JSON report as string
        """
        logger.info("Generating JSON compliance report")
        try:
            logger.debug("Converting compliance result to dictionary")
            report_dict = compliance_result.dict()
            logger.debug("Converting dictionary to JSON string")
            report_json = json.dumps(report_dict, indent=2)
            logger.info("JSON compliance report generated successfully")
            return report_json
        except Exception as e:
            logger.error(f"Error generating JSON compliance report: {str(e)}")
            raise

    def export_report(self, report_content: str, format: str, filename: str) -> bool:
        """
        Export report to a specific format.
        
        Args:
            report_content: The report content to export
            format: The format to export to (json, csv, html, etc.)
            filename: The filename to save to
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Exporting report to {format} format with filename: {filename}")
        try:
            if format.lower() == "json":
                logger.debug("Writing JSON report to file")
                with open(filename, 'w') as f:
                    f.write(report_content)
                logger.info(f"JSON report exported successfully to {filename}")
                return True
            else:
                logger.warning(f"Unsupported export format: {format}")
                return False
        except Exception as e:
            logger.error(f"Error exporting report: {str(e)}")
            return False

    def generate_html_report(self, report_content: str) -> str:
        """
        Generate an HTML report from report content.
        
        Args:
            report_content: The report content to convert to HTML
            
        Returns:
            HTML formatted report
        """
        logger.info("Generating HTML report")
        try:
            # Simple HTML wrapper for JSON content
            html_content = f"""
            <html>
            <head>
                <title>Firewall Policy Analysis Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    pre {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <h1>Firewall Policy Analysis Report</h1>
                <pre>{report_content}</pre>
            </body>
            </html>
            """
            logger.info("HTML report generated successfully")
            return html_content
        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
            raise
