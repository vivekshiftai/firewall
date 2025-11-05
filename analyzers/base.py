"""
Base analyzer for firewall policy analysis.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from models.base import FirewallConfig, PolicyComparisonResult


class BaseAnalyzer(ABC):
    """Abstract base class for firewall policy analyzers."""

    @abstractmethod
    def analyze_single_firewall(self, config: FirewallConfig) -> Dict[str, Any]:
        """
        Analyze a single firewall configuration for internal inconsistencies.
        
        Args:
            config: Firewall configuration to analyze
            
        Returns:
            Analysis results including inconsistencies and recommendations
        """
        pass

    @abstractmethod
    def compare_firewalls(self, config_a: FirewallConfig, config_b: FirewallConfig) -> PolicyComparisonResult:
        """
        Compare two firewall configurations.
        
        Args:
            config_a: First firewall configuration
            config_b: Second firewall configuration
            
        Returns:
            Comparison results including differences and recommendations
        """
        pass

    @abstractmethod
    def check_compliance(self, config: FirewallConfig, standards: List[str]) -> Dict[str, Any]:
        """
        Check firewall configuration against compliance standards.
        
        Args:
            config: Firewall configuration to check
            standards: List of compliance standards to check against
            
        Returns:
            Compliance check results
        """
        pass