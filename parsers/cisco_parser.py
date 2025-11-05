"""
Cisco ASA configuration parser.
"""
import logging
from typing import Dict, Any, List
from app.parsers.base import BaseParser
from app.models.base import FirewallConfig
from app.exceptions.custom_exceptions import ParserError

logger = logging.getLogger(__name__)


class CiscoParser(BaseParser):
    """Parser for Cisco ASA firewall configurations."""

    def parse(self, config_data: Dict[str, Any]) -> FirewallConfig:
        """
        Parse Cisco ASA configuration data into a standardized FirewallConfig.
        
        Args:
            config_data: Raw Cisco ASA configuration data
            
        Returns:
            Standardized FirewallConfig object
        """
        try:
            # Extract basic information
            firewall_id = config_data.get("hostname", "unknown")
            
            # Parse policies (access control lists in Cisco)
            policies = self._parse_access_lists(config_data.get("access_lists", {}))
            
            # Parse network objects
            address_objects = self._parse_network_objects(config_data.get("network_objects", {}))
            service_objects = self._parse_service_objects(config_data.get("service_objects", {}))
            
            # Combine all objects
            objects = address_objects + service_objects
            
            return FirewallConfig(
                id=firewall_id,
                vendor="cisco",
                version=config_data.get("version", ""),
                policies=policies,
                objects=objects,
                metadata={
                    "config_type": "cisco_asa",
                    "parsed_at": __import__('datetime').datetime.utcnow().isoformat()
                }
            )
        except Exception as e:
            logger.error(f"Error parsing Cisco configuration: {str(e)}")
            raise ParserError(f"Failed to parse Cisco configuration: {str(e)}", "cisco")

    def _parse_access_lists(self, acl_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Cisco access lists."""
        policies = []
        try:
            for acl_name, acl_entries in acl_data.items():
                for i, entry in enumerate(acl_entries):
                    # Convert Cisco ACL format to standardized policy format
                    policy = {
                        "id": f"{acl_name}_{i}",
                        "name": f"{acl_name}_Rule_{i+1}",
                        "srcaddr": [entry.get("source", "any")],
                        "dstaddr": [entry.get("destination", "any")],
                        "service": [entry.get("service", "ip")],
                        "action": "accept" if entry.get("action", "deny") == "permit" else "deny",
                        "status": "enable",
                        "comments": entry.get("remark", "")
                    }
                    policies.append(policy)
        except Exception as e:
            logger.warning(f"Error parsing access lists: {str(e)}")
        return policies

    def _parse_network_objects(self, network_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Cisco network objects."""
        objects = []
        try:
            for name, network in network_data.items():
                obj = {
                    "name": name,
                    "type": network.get("type", "host"),
                    "subnet": network.get("address"),
                    "comment": network.get("description", "")
                }
                objects.append(obj)
        except Exception as e:
            logger.warning(f"Error parsing network objects: {str(e)}")
        return objects

    def _parse_service_objects(self, service_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Cisco service objects."""
        objects = []
        try:
            for name, service in service_data.items():
                obj = {
                    "name": name,
                    "protocol": service.get("protocol", "tcp"),
                    "port_range": service.get("port"),
                    "comment": service.get("description", "")
                }
                objects.append(obj)
        except Exception as e:
            logger.warning(f"Error parsing service objects: {str(e)}")
        return objects

    def validate_config(self, config: FirewallConfig) -> bool:
        """
        Validate the parsed Cisco configuration.
        
        Args:
            config: Parsed firewall configuration
            
        Returns:
            True if valid, False otherwise
        """
        if not config.id or not config.vendor:
            return False
        
        if config.vendor != "cisco":
            return False
            
        return True