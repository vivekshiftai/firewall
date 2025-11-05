"""
Fortinet configuration parser implementation.
"""
import logging
from typing import Dict, Any, List
from app.vendors.abstract import AbstractVendorParser, ParsedConfig

logger = logging.getLogger(__name__)


class FortinetConfigParser(AbstractVendorParser):
    """Parser for Fortinet FortiGate firewall configurations."""

    def __init__(self):
        self.config_data = None
        self.parsed_config = None

    def parse_config(self, config_data: Dict[str, Any]) -> ParsedConfig:
        """
        Parse Fortinet configuration data into a standardized ParsedConfig.
        
        Args:
            config_data: Raw Fortinet configuration data
            
        Returns:
            Standardized ParsedConfig object
        """
        try:
            self.config_data = config_data
            
            # Extract basic information
            vendor = "fortinet"
            version = config_data.get("version", "unknown")
            
            # Extract all components
            interfaces = self.extract_interfaces()
            addresses = self.extract_addresses()
            services = self.extract_services()
            policies = self.extract_policies()
            zones = self.extract_zones()
            
            self.parsed_config = ParsedConfig(
                vendor=vendor,
                version=version,
                interfaces=interfaces,
                addresses=addresses,
                services=services,
                policies=policies,
                zones=zones,
                metadata={
                    "config_type": "fortinet_fortigate",
                    "parsed_at": __import__('datetime').datetime.utcnow().isoformat()
                }
            )
            
            return self.parsed_config
        except Exception as e:
            logger.error(f"Error parsing Fortinet configuration: {str(e)}")
            raise ValueError(f"Failed to parse Fortinet configuration: {str(e)}")

    def extract_interfaces(self) -> List[Dict[str, Any]]:
        """Extract interface information from Fortinet configuration."""
        interfaces = []
        try:
            interface_data = self.config_data.get("system", {}).get("interface", {})
            for name, interface in interface_data.items():
                interfaces.append({
                    "name": name,
                    "ip": interface.get("ip", ""),
                    "status": interface.get("status", "down"),
                    "role": interface.get("role", "undefined"),
                    "vlanid": interface.get("vlanid", 0)
                })
        except Exception as e:
            logger.warning(f"Error extracting interfaces: {str(e)}")
        return interfaces

    def extract_addresses(self) -> List[Dict[str, Any]]:
        """Extract address objects from Fortinet configuration."""
        addresses = []
        try:
            address_data = self.config_data.get("firewall", {}).get("address", {})
            for name, address in address_data.items():
                addresses.append({
                    "name": name,
                    "type": address.get("type", "ipmask"),
                    "subnet": address.get("subnet", ""),
                    "fqdn": address.get("fqdn", ""),
                    "comment": address.get("comment", "")
                })
        except Exception as e:
            logger.warning(f"Error extracting addresses: {str(e)}")
        return addresses

    def extract_services(self) -> List[Dict[str, Any]]:
        """Extract service objects from Fortinet configuration."""
        services = []
        try:
            service_data = self.config_data.get("firewall", {}).get("service", {}).get("custom", {})
            for name, service in service_data.items():
                services.append({
                    "name": name,
                    "protocol": service.get("protocol", "TCP/UDP/SCTP"),
                    "tcp_portrange": service.get("tcp-portrange", ""),
                    "udp_portrange": service.get("udp-portrange", ""),
                    "comment": service.get("comment", "")
                })
        except Exception as e:
            logger.warning(f"Error extracting services: {str(e)}")
        return services

    def extract_policies(self) -> List[Dict[str, Any]]:
        """Extract policies from Fortinet configuration."""
        policies = []
        try:
            policy_data = self.config_data.get("firewall", {}).get("policy", {})
            for policy_id, policy in policy_data.items():
                policies.append({
                    "id": policy_id,
                    "name": policy.get("name", f"Policy-{policy_id}"),
                    "srcintf": policy.get("srcintf", []),
                    "dstintf": policy.get("dstintf", []),
                    "srcaddr": policy.get("srcaddr", []),
                    "dstaddr": policy.get("dstaddr", []),
                    "service": policy.get("service", []),
                    "action": policy.get("action", "deny"),
                    "status": policy.get("status", "disable"),
                    "schedule": policy.get("schedule", "always"),
                    "logtraffic": policy.get("logtraffic", "disable"),
                    "comments": policy.get("comments", "")
                })
        except Exception as e:
            logger.warning(f"Error extracting policies: {str(e)}")
        return policies

    def extract_zones(self) -> List[Dict[str, Any]]:
        """Extract zones from Fortinet configuration."""
        zones = []
        try:
            zone_data = self.config_data.get("system", {}).get("zone", {})
            for name, zone in zone_data.items():
                zones.append({
                    "name": name,
                    "interface": zone.get("interface", []),
                    "intrazone": zone.get("intrazone", "deny")
                })
        except Exception as e:
            logger.warning(f"Error extracting zones: {str(e)}")
        return zones

    def extract_vlans(self) -> List[Dict[str, Any]]:
        """Extract VLANs from Fortinet configuration."""
        vlans = []
        try:
            vlan_data = self.config_data.get("system", {}).get("interface", {})
            for name, interface in vlan_data.items():
                if interface.get("vlanid"):
                    vlans.append({
                        "name": name,
                        "vlanid": interface.get("vlanid"),
                        "interface": interface.get("interface", ""),
                        "ip": interface.get("ip", "")
                    })
        except Exception as e:
            logger.warning(f"Error extracting VLANs: {str(e)}")
        return vlans