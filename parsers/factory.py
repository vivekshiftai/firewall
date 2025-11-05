"""
Factory for creating firewall parser instances.
"""
import logging
from typing import Dict, Type
from parsers.base import BaseParser
from parsers.fortinet_parser import FortinetParser
from parsers.zscaler_parser import ZscalerParser
from parsers.cisco_parser import CiscoParser

# Configure logging
logger = logging.getLogger(__name__)

class ParserFactory:
    """Factory class for creating parser instances."""
    
    # Registry of available parsers
    _parsers: Dict[str, Type[BaseParser]] = {
        "fortinet": FortinetParser,
        "zscaler": ZscalerParser,
        "cisco": CiscoParser
    }
    
    @classmethod
    def register_parser(cls, vendor: str, parser_class: Type[BaseParser]):
        """
        Register a new parser for a vendor.
        
        Args:
            vendor: The vendor name
            parser_class: The parser class
        """
        logger.info(f"Registering parser for vendor: {vendor}")
        cls._parsers[vendor] = parser_class
        logger.debug(f"Parser registered successfully for vendor: {vendor}")
    
    @classmethod
    def create_parser(cls, vendor: str) -> BaseParser:
        """
        Create a parser instance for a specific vendor.
        
        Args:
            vendor: The vendor name
            
        Returns:
            Parser instance
            
        Raises:
            ValueError: If vendor is not supported
        """
        logger.info(f"Creating parser for vendor: {vendor}")
        if vendor not in cls._parsers:
            logger.error(f"Unsupported vendor: {vendor}")
            raise ValueError(f"Unsupported vendor: {vendor}")
        
        parser = cls._parsers[vendor]()
        logger.info(f"Parser created successfully for vendor: {vendor}")
        return parser
    
    @classmethod
    def get_supported_vendors(cls) -> list:
        """
        Get list of supported vendors.
        
        Returns:
            List of supported vendor names
        """
        vendors = list(cls._parsers.keys())
        logger.debug(f"Supported vendors: {vendors}")
        return vendors