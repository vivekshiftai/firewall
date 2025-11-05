"""
Zscaler cloud security configuration parser.
"""
import json
import logging
from typing import Dict, Any, List
from parsers.base import BaseParser
from models.base import FirewallConfig
from models.zscaler import ZscalerRule, ZscalerLocation, ZscalerUserGroup
from exceptions.custom_exceptions import ParserError

logger = logging.getLogger(__name__)


class ZscalerParser(BaseParser):
    """Parser for Zscaler cloud security platform configurations."""

    def parse(self, config_data: Dict[str, Any]) -> FirewallConfig:
        """
        Parse Zscaler configuration data into a standardized FirewallConfig.
        
        Args:
            config_data: Raw Zscaler configuration data
            
        Returns:
            Standardized FirewallConfig object
        """
        try:
            # Extract basic information
            firewall_id = config_data.get("cloud", "zscaler")
            
            # Parse rules
            rules = self._parse_rules(config_data.get("rules", []))
            
            # Parse objects
            locations = self._parse_locations(config_data.get("locations", []))
            user_groups = self._parse_user_groups(config_data.get("user_groups", []))
            departments = self._parse_departments(config_data.get("departments", []))
            app_groups = self._parse_application_groups(config_data.get("application_groups", []))
            
            # Combine all objects
            objects = locations + user_groups + departments + app_groups
            
            return FirewallConfig(
                id=firewall_id,
                vendor="zscaler",
                version=config_data.get("version", ""),
                policies=rules,
                objects=objects,
                metadata={
                    "config_type": "zscaler_cloud",
                    "parsed_at": __import__('datetime').datetime.utcnow().isoformat()
                }
            )
        except Exception as e:
            logger.error(f"Error parsing Zscaler configuration: {str(e)}")
            raise ParserError(f"Failed to parse Zscaler configuration: {str(e)}", "zscaler")

    def _parse_rules(self, rule_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse Zscaler rule data."""
        rules = []
        try:
            for rule in rule_data:
                zscaler_rule = ZscalerRule(
                    id=rule.get("id", ""),
                    name=rule.get("name", f"Rule-{rule.get('id', '')}"),
                    locations=rule.get("locations", []),
                    departments=rule.get("departments", []),
                    users=rule.get("users", []),
                    applications=rule.get("applications", []),
                    action=rule.get("action", "BLOCK"),
                    enabled=rule.get("enabled", True)
                )
                rules.append(zscaler_rule.dict())
        except Exception as e:
            logger.warning(f"Error parsing rules: {str(e)}")
        return rules

    def _parse_locations(self, location_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse Zscaler location data."""
        locations = []
        try:
            for location in location_data:
                zscaler_location = ZscalerLocation(
                    id=location.get("id", ""),
                    name=location.get("name", ""),
                    ip_addresses=location.get("ipAddresses", []),
                    vpn_credentials=location.get("vpnCredentials", [])
                )
                locations.append(zscaler_location.dict())
        except Exception as e:
            logger.warning(f"Error parsing locations: {str(e)}")
        return locations

    def _parse_user_groups(self, group_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse Zscaler user group data."""
        groups = []
        try:
            for group in group_data:
                zscaler_group = ZscalerUserGroup(
                    id=group.get("id", ""),
                    name=group.get("name", ""),
                    users=group.get("users", [])
                )
                groups.append(zscaler_group.dict())
        except Exception as e:
            logger.warning(f"Error parsing user groups: {str(e)}")
        return groups

    def _parse_departments(self, dept_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse Zscaler department data."""
        depts = []
        try:
            for dept in dept_data:
                # Implementation would depend on actual Zscaler API structure
                dept_obj = {
                    "id": dept.get("id", ""),
                    "name": dept.get("name", ""),
                    "type": "department"
                }
                depts.append(dept_obj)
        except Exception as e:
            logger.warning(f"Error parsing departments: {str(e)}")
        return depts

    def _parse_application_groups(self, app_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse Zscaler application group data."""
        apps = []
        try:
            for app in app_data:
                # Implementation would depend on actual Zscaler API structure
                app_obj = {
                    "id": app.get("id", ""),
                    "name": app.get("name", ""),
                    "type": "application_group"
                }
                apps.append(app_obj)
        except Exception as e:
            logger.warning(f"Error parsing application groups: {str(e)}")
        return apps

    def validate_config(self, config: FirewallConfig) -> bool:
        """
        Validate the parsed Zscaler configuration.
        
        Args:
            config: Parsed firewall configuration
            
        Returns:
            True if valid, False otherwise
        """
        if not config.id or not config.vendor:
            return False
        
        if config.vendor != "zscaler":
            return False
            
        return True