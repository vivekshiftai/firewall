"""
Custom exception classes for cross-firewall policy analysis.
"""
from typing import Optional


class FirewallAnalysisError(Exception):
    """Base exception for firewall analysis errors."""
    
    def __init__(self, message: str, error_code: Optional[str] = None):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)


class ParserError(FirewallAnalysisError):
    """Exception raised when parsing firewall configuration fails."""
    
    def __init__(self, message: str, vendor: Optional[str] = None):
        self.vendor = vendor
        super().__init__(message, "PARSER_ERROR")


class AnalyzerError(FirewallAnalysisError):
    """Exception raised when analysis fails."""
    
    def __init__(self, message: str):
        super().__init__(message, "ANALYZER_ERROR")


class ReportGenerationError(FirewallAnalysisError):
    """Exception raised when report generation fails."""
    
    def __init__(self, message: str):
        super().__init__(message, "REPORT_ERROR")


class ComplianceError(FirewallAnalysisError):
    """Exception raised when compliance checking fails."""
    
    def __init__(self, message: str):
        super().__init__(message, "COMPLIANCE_ERROR")