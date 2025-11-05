"""
Fortinet FortiGate configuration parser.
"""
import json
import logging
from typing import Dict, Any, List
from app.parsers.base import BaseParser
from app.models.base import FirewallConfig
from app.models.fortinet import FortinetPolicy, FortinetAddressObject, FortinetServiceObject
from app.exceptions.custom_exceptions import ParserError

logger = logging.getLogger(__name__)


class FortinetParser(BaseParser):
    """Parser for Fortinet FortiGate firewall configurations."""

    def parse(self, config_data: Dict[str, Any]) -> FirewallConfig:
        """
        Parse Fortinet configuration data into a standardized FirewallConfig.
        
        Args:
            config_data: Raw Fortinet configuration data
            
        Returns:
            Standardized FirewallConfig object
        """
        try:
            # Extract basic information
            firewall_id = config_data.get("system", {}).get("global", {}).get("hostname", "unknown")
            
            # Parse policies
            policies = self._parse_policies(config_data.get("firewall", {}).get("policy", {}))
            
            # Parse objects
            address_objects = self._parse_address_objects(config_data.get("firewall", {}).get("address", {}))
            service_objects = self._parse_service_objects(config_data.get("firewall", {}).get("service", {}))
            
            # Combine all objects
            objects = address_objects + service_objects
            
            return FirewallConfig(
                id=firewall_id,
                vendor="fortinet",
                version=config_data.get("version", ""),
                policies=policies,
                objects=objects,
                metadata={
                    "config_type": "fortinet_fortigate",
                    "parsed_at": __import__('datetime').datetime.utcnow().isoformat()
                }
            )
        except Exception as e:
            logger.error(f"Error parsing Fortinet configuration: {str(e)}")
            raise ParserError(f"Failed to parse Fortinet configuration: {str(e)}", "fortinet")

    def _parse_policies(self, policy_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Fortinet policy data."""
        policies = []
        try:
            for policy_id, policy in policy_data.items():
                fortinet_policy = FortinetPolicy(
                    id=int(policy_id),
                    name=policy.get("name", f"Policy-{policy_id}"),
                    srcintf=policy.get("srcintf", []),
                    dstintf=policy.get("dstintf", []),
                    srcaddr=policy.get("srcaddr", []),
                    dstaddr=policy.get("dstaddr", []),
                    service=policy.get("service", []),
                    action=policy.get("action", "deny"),
                    status=policy.get("status", "disable"),
                    schedule=policy.get("schedule", "always"),
                    comments=policy.get("comments", "")
                )
                policies.append(fortinet_policy.dict())
        except Exception as e:
            logger.warning(f"Error parsing policies: {str(e)}")
        return policies

    def _parse_address_objects(self, address_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Fortinet address objects."""
        objects = []
        try:
            for name, addr in address_data.items():
                address_obj = FortinetAddressObject(
                    name=name,
                    type=addr.get("type", "ipmask"),
                    subnet=addr.get("subnet"),
                    fqdn=addr.get("fqdn"),
                    comment=addr.get("comment", "")
                )
                objects.append(address_obj.dict())
        except Exception as e:
            logger.warning(f"Error parsing address objects: {str(e)}")
        return objects

    def _parse_service_objects(self, service_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Fortinet service objects."""
        objects = []
        try:
            for name, svc in service_data.items():
                service_obj = FortinetServiceObject(
                    name=name,
                    protocol=svc.get("protocol", "TCP/UDP/SCTP"),
                    port_range=svc.get("tcp-portrange") or svc.get("udp-portrange"),
                    comment=svc.get("comment", "")
                )
                objects.append(service_obj.dict())
        except Exception as e:
            logger.warning(f"Error parsing service objects: {str(e)}")
        return objects

    def validate_config(self, config: FirewallConfig) -> bool:
        """
        Validate the parsed Fortinet configuration.
        
        Args:
            config: Parsed firewall configuration
            
        Returns:
            True if valid, False otherwise
        """
        if not config.id or not config.vendor:
            return False
        
        if config.vendor != "fortinet":
            return False
            
        return True