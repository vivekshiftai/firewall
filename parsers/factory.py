"""
Parser factory for creating vendor-specific parsers.
"""
from typing import Dict, Type
from parsers.base import BaseParser
from parsers.fortinet_parser import FortinetParser
from parsers.zscaler_parser import ZscalerParser
from parsers.cisco_parser import CiscoParser


class ParserFactory:
    """Factory for creating firewall configuration parsers."""
    
    _parsers: Dict[str, Type[BaseParser]] = {
        "fortinet": FortinetParser,
        "zscaler": ZscalerParser,
        "cisco": CiscoParser
    }
    
    @classmethod
    def register_parser(cls, vendor: str, parser_class: Type[BaseParser]) -> None:
        """
        Register a new parser for a vendor.
        
        Args:
            vendor: The vendor name
            parser_class: The parser class to register
        """
        cls._parsers[vendor.lower()] = parser_class
    
    @classmethod
    def create_parser(cls, vendor: str) -> BaseParser:
        """
        Create a parser for the specified vendor.
        
        Args:
            vendor: The vendor name
            
        Returns:
            An instance of the appropriate parser
            
        Raises:
            ValueError: If no parser is registered for the vendor
        """
        vendor_lower = vendor.lower()
        if vendor_lower not in cls._parsers:
            raise ValueError(f"No parser registered for vendor: {vendor}")
        
        return cls._parsers[vendor_lower]()
    
    @classmethod
    def get_supported_vendors(cls) -> list:
        """
        Get a list of supported vendors.
        
        Returns:
            List of supported vendor names
        """
        return list(cls._parsers.keys())