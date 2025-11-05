"""
Base parser for firewall configurations.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any
from models.base import FirewallConfig


class BaseParser(ABC):
    """Abstract base class for firewall configuration parsers."""

    @abstractmethod
    def parse(self, config_data: Dict[str, Any]) -> FirewallConfig:
        """
        Parse vendor-specific configuration data into a standardized FirewallConfig.
        
        Args:
            config_data: Raw configuration data from the firewall
            
        Returns:
            Standardized FirewallConfig object
        """
        pass

    @abstractmethod
    def validate_config(self, config: FirewallConfig) -> bool:
        """
        Validate the parsed configuration.
        
        Args:
            config: Parsed firewall configuration
            
        Returns:
            True if valid, False otherwise
        """
        pass