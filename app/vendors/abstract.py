"""
Abstract base classes for vendor-specific implementations.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List
from pydantic import BaseModel


class ParsedConfig(BaseModel):
    """Standardized parsed configuration model."""
    vendor: str
    version: str
    interfaces: List[Dict[str, Any]] = []
    addresses: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    policies: List[Dict[str, Any]] = []
    zones: List[Dict[str, Any]] = []
    metadata: Dict[str, Any] = {}


class NormalizedPolicy(BaseModel):
    """Standardized policy model for cross-vendor comparison."""
    id: str
    name: str
    source_zones: List[str] = []
    destination_zones: List[str] = []
    source_addresses: List[str] = []
    destination_addresses: List[str] = []
    services: List[str] = []
    action: str
    enabled: bool = True
    logging: bool = False
    schedule: str = "always"
    comments: str = ""


class PolicyInconsistency(BaseModel):
    """Model for policy inconsistencies."""
    type: str
    severity: str
    description: str
    policy_ids: List[str] = []
    recommendation: str = ""


class AbstractVendorParser(ABC):
    """Abstract base class for vendor-specific parsers."""

    @abstractmethod
    def parse_config(self, config_data: Dict[str, Any]) -> ParsedConfig:
        """
        Parse vendor-specific configuration data into a standardized ParsedConfig.
        
        Args:
            config_data: Raw configuration data from the firewall
            
        Returns:
            Standardized ParsedConfig object
        """
        pass

    @abstractmethod
    def extract_interfaces(self) -> List[Dict[str, Any]]:
        """Extract interface information from configuration."""
        pass

    @abstractmethod
    def extract_addresses(self) -> List[Dict[str, Any]]:
        """Extract address objects from configuration."""
        pass

    @abstractmethod
    def extract_services(self) -> List[Dict[str, Any]]:
        """Extract service objects from configuration."""
        pass

    @abstractmethod
    def extract_policies(self) -> List[Dict[str, Any]]:
        """Extract policies from configuration."""
        pass

    @abstractmethod
    def extract_zones(self) -> List[Dict[str, Any]]:
        """Extract zones from configuration."""
        pass


class AbstractFirewallAnalyzer(ABC):
    """Abstract base class for firewall analyzers."""

    @abstractmethod
    def analyze(self) -> List[PolicyInconsistency]:
        """
        Analyze parsed configuration for inconsistencies.
        
        Returns:
            List of policy inconsistencies found
        """
        pass


class AbstractPolicyNormalizer(ABC):
    """Abstract base class for policy normalizers."""

    @abstractmethod
    def normalize_policies(self) -> List[NormalizedPolicy]:
        """
        Convert vendor-specific policies to normalized format.
        
        Returns:
            List of normalized policies
        """
        pass