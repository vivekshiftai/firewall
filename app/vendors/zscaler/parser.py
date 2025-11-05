"""
Zscaler configuration parser implementation.
"""
import logging
from typing import Dict, Any, List
from app.vendors.abstract import AbstractVendorParser, ParsedConfig

logger = logging.getLogger(__name__)


class ZscalerConfigParser(AbstractVendorParser):
    """Parser for Zscaler cloud security platform configurations."""

    def __init__(self):
        self.config_data = None
        self.parsed_config = None

    def parse_config(self, config_data: Dict[str, Any]) -> ParsedConfig:
        """
        Parse Zscaler configuration data into a standardized ParsedConfig.
        
        Args:
            config_data: Raw Zscaler configuration data
            
        Returns:
            Standardized ParsedConfig object
        """
        try:
            self.config_data = config_data
            
            # Extract basic information
            vendor = "zscaler"
            version = config_data.get("version", "unknown")
            
            # Extract all components
            interfaces = []  # Zscaler is cloud-based, no physical interfaces
            addresses = self.extract_addresses()
            services = []  # Zscaler uses applications instead of services
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
                    "config_type": "zscaler_cloud",
                    "parsed_at": __import__('datetime').datetime.utcnow().isoformat()
                }
            )
            
            return self.parsed_config
        except Exception as e:
            logger.error(f"Error parsing Zscaler configuration: {str(e)}")
            raise ValueError(f"Failed to parse Zscaler configuration: {str(e)}")

    def extract_interfaces(self) -> List[Dict[str, Any]]:
        """Extract interface information from Zscaler configuration."""
        # Zscaler is cloud-based, no physical interfaces
        return []

    def extract_addresses(self) -> List[Dict[str, Any]]:
        """Extract address objects from Zscaler configuration."""
        addresses = []
        try:
            # Zscaler uses locations instead of addresses
            location_data = self.config_data.get("locations", [])
            for location in location_data:
                addresses.append({
                    "name": location.get("name", ""),
                    "ip_addresses": location.get("ipAddresses", []),
                    "vpn_credentials": location.get("vpnCredentials", [])
                })
        except Exception as e:
            logger.warning(f"Error extracting addresses from locations: {str(e)}")
        return addresses

    def extract_services(self) -> List[Dict[str, Any]]:
        """Extract service objects from Zscaler configuration."""
        # Zscaler uses applications instead of services
        services = []
        try:
            app_data = self.config_data.get("application_groups", [])
            for app in app_data:
                services.append({
                    "name": app.get("name", ""),
                    "applications": app.get("applications", [])
                })
        except Exception as e:
            logger.warning(f"Error extracting services from applications: {str(e)}")
        return services

    def extract_policies(self) -> List[Dict[str, Any]]:
        """Extract policies from Zscaler configuration."""
        policies = []
        try:
            # Handle both ZPA (Zero Trust) and ZIA (Internet Access) configs
            rules_data = self.config_data.get("rules", [])
            for rule in rules_data:
                policies.append({
                    "id": rule.get("id", ""),
                    "name": rule.get("name", f"Rule-{rule.get('id', '')}"),
                    "locations": rule.get("locations", []),
                    "departments": rule.get("departments", []),
                    "users": rule.get("users", []),
                    "applications": rule.get("applications", []),
                    "action": rule.get("action", "BLOCK"),
                    "enabled": rule.get("enabled", True),
                    "order": rule.get("order", 0)
                })
        except Exception as e:
            logger.warning(f"Error extracting policies: {str(e)}")
        return policies

    def extract_zones(self) -> List[Dict[str, Any]]:
        """Extract zones from Zscaler configuration."""
        zones = []
        try:
            # Zscaler uses locations as zones
            location_data = self.config_data.get("locations", [])
            for location in location_data:
                zones.append({
                    "name": location.get("name", ""),
                    "type": "location",
                    "ip_addresses": location.get("ipAddresses", [])
                })
            
            # Zscaler also has departments which can be treated as zones
            department_data = self.config_data.get("departments", [])
            for department in department_data:
                zones.append({
                    "name": department.get("name", ""),
                    "type": "department",
                    "groups": department.get("groups", [])
                })
        except Exception as e:
            logger.warning(f"Error extracting zones: {str(e)}")
        return zones

    def extract_locations(self) -> List[Dict[str, Any]]:
        """Extract locations from Zscaler configuration."""
        locations = []
        try:
            location_data = self.config_data.get("locations", [])
            for location in location_data:
                locations.append({
                    "id": location.get("id", ""),
                    "name": location.get("name", ""),
                    "ip_addresses": location.get("ipAddresses", []),
                    "vpn_credentials": location.get("vpnCredentials", [])
                })
        except Exception as e:
            logger.warning(f"Error extracting locations: {str(e)}")
        return locations

    def extract_user_groups(self) -> List[Dict[str, Any]]:
        """Extract user groups from Zscaler configuration."""
        user_groups = []
        try:
            group_data = self.config_data.get("user_groups", [])
            for group in group_data:
                user_groups.append({
                    "id": group.get("id", ""),
                    "name": group.get("name", ""),
                    "users": group.get("users", [])
                })
        except Exception as e:
            logger.warning(f"Error extracting user groups: {str(e)}")
        return user_groups

    def extract_departments(self) -> List[Dict[str, Any]]:
        """Extract departments from Zscaler configuration."""
        departments = []
        try:
            dept_data = self.config_data.get("departments", [])
            for dept in dept_data:
                departments.append({
                    "id": dept.get("id", ""),
                    "name": dept.get("name", ""),
                    "groups": dept.get("groups", [])
                })
        except Exception as e:
            logger.warning(f"Error extracting departments: {str(e)}")
        return departments

    def extract_rules(self) -> List[Dict[str, Any]]:
        """Extract rules from Zscaler configuration."""
        return self.extract_policies()