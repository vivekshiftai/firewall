"""
Base report generator for firewall policy analysis.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any
from app.models.base import PolicyComparisonResult, ComplianceReport


class BaseReportGenerator(ABC):
    """Abstract base class for report generators."""

    @abstractmethod
    def generate_comparison_report(self, comparison_result: PolicyComparisonResult) -> str:
        """
        Generate a comparison report from comparison results.
        
        Args:
            comparison_result: Results from policy comparison
            
        Returns:
            Formatted report as string
        """
        pass

    @abstractmethod
    def generate_compliance_report(self, compliance_result: ComplianceReport) -> str:
        """
        Generate a compliance report from compliance results.
        
        Args:
            compliance_result: Results from compliance check
            
        Returns:
            Formatted report as string
        """
        pass

    @abstractmethod
    def export_report(self, report_content: str, format: str, filename: str) -> bool:
        """
        Export report to a specific format.
        
        Args:
            report_content: The report content to export
            format: The format to export to (pdf, html, csv, etc.)
            filename: The filename to save to
            
        Returns:
            True if successful, False otherwise
        """
        pass