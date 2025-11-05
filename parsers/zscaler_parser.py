"""
Zscaler firewall configuration parser.
"""
import logging
from typing import Dict, Any, List
from parsers.base import BaseParser
from models.base import FirewallConfig
from models.zscaler import ZscalerRule, ZscalerLocation, ZscalerUserGroup
from exceptions.custom_exceptions import ParserError

# Configure logging
logger = logging.getLogger(__name__)

class ZscalerParser(BaseParser):
    """Parser for Zscaler firewall configurations."""

    def parse(self, config_data: Dict[str, Any]) -> FirewallConfig:
        """
        Parse Zscaler configuration data into a standardized FirewallConfig.
        
        Args:
            config_data: Raw Zscaler configuration data
            
        Returns:
            Standardized FirewallConfig object
        """
        logger.info("Starting Zscaler configuration parsing")
        try:
            # Extract basic information
            logger.debug("Extracting basic firewall information")
            firewall_id = config_data.get("id", "zscaler-firewall")
            version = config_data.get("version", "unknown")
            logger.info(f"Parsing Zscaler firewall ID: {firewall_id}, Version: {version}")
            
            # Parse rules
            logger.debug("Parsing rules")
            rules = self._parse_rules(config_data.get("rules", []))
            logger.info(f"Parsed {len(rules)} rules")
            
            # Parse locations
            logger.debug("Parsing locations")
            locations = self._parse_locations(config_data.get("locations", []))
            logger.info(f"Parsed {len(locations)} locations")
            
            # Parse user groups
            logger.debug("Parsing user groups")
            user_groups = self._parse_user_groups(config_data.get("user_groups", []))
            logger.info(f"Parsed {len(user_groups)} user groups")
            
            # Create standardized config
            logger.debug("Creating standardized firewall configuration")
            firewall_config = FirewallConfig(
                id=firewall_id,
                vendor="zscaler",
                version=version,
                policies=rules,
                objects=locations + user_groups,
                metadata=config_data.get("metadata", {})
            )
            
            logger.info("Zscaler configuration parsing completed successfully")
            return firewall_config
            
        except Exception as e:
            logger.error(f"Error parsing Zscaler configuration: {str(e)}")
            raise ParserError(f"Error parsing Zscaler configuration: {str(e)}")

    def _parse_rules(self, rules_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse Zscaler rules into standardized format.
        
        Args:
            rules_data: Raw rule data
            
        Returns:
            List of standardized rules
        """
        logger.debug(f"Parsing {len(rules_data)} Zscaler rules")
        rules = []
        for i, rule_data in enumerate(rules_data):
            try:
                logger.debug(f"Parsing rule {i+1}")
                zscaler_rule = ZscalerRule(**rule_data)
                # Convert to standardized format
                standardized_rule = {
                    "id": zscaler_rule.id,
                    "name": zscaler_rule.name,
                    "source_zones": [],  # Zscaler doesn't have zones in the same way
                    "destination_zones": [],
                    "source_addresses": getattr(zscaler_rule, "source_ips", []),
                    "destination_addresses": getattr(zscaler_rule, "dest_ips", []),
                    "services": getattr(zscaler_rule, "applications", []),
                    "action": zscaler_rule.action,
                    "enabled": getattr(zscaler_rule, "enabled", True),
                    "logging": getattr(zscaler_rule, "audit", False),
                    "schedule": getattr(zscaler_rule, "time_windows", "always"),
                    "comments": getattr(zscaler_rule, "description", "")
                }
                rules.append(standardized_rule)
                logger.debug(f"Rule {i+1} parsed successfully")
            except Exception as e:
                logger.warning(f"Error parsing rule {i+1}: {str(e)}")
                # Continue with other rules
                continue
        logger.info(f"Successfully parsed {len(rules)} out of {len(rules_data)} rules")
        return rules

    def _parse_locations(self, locations_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse Zscaler locations.
        
        Args:
            locations_data: Raw location data
            
        Returns:
            List of location objects
        """
        logger.debug(f"Parsing {len(locations_data)} Zscaler locations")
        locations = []
        for i, location_data in enumerate(locations_data):
            try:
                logger.debug(f"Parsing location {i+1}")
                location_obj = ZscalerLocation(**location_data)
                locations.append(location_obj.dict())
                logger.debug(f"Location {i+1} parsed successfully")
            except Exception as e:
                logger.warning(f"Error parsing location {i+1}: {str(e)}")
                continue
        logger.info(f"Successfully parsed {len(locations)} out of {len(locations_data)} locations")
        return locations

    def _parse_user_groups(self, user_groups_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse Zscaler user groups.
        
        Args:
            user_groups_data: Raw user group data
            
        Returns:
            List of user group objects
        """
        logger.debug(f"Parsing {len(user_groups_data)} Zscaler user groups")
        user_groups = []
        for i, group_data in enumerate(user_groups_data):
            try:
                logger.debug(f"Parsing user group {i+1}")
                group_obj = ZscalerUserGroup(**group_data)
                user_groups.append(group_obj.dict())
                logger.debug(f"User group {i+1} parsed successfully")
            except Exception as e:
                logger.warning(f"Error parsing user group {i+1}: {str(e)}")
                continue
        logger.info(f"Successfully parsed {len(user_groups)} out of {len(user_groups_data)} user groups")
        return user_groups

    def validate_config(self, config: FirewallConfig) -> bool:
        """
        Validate the parsed Zscaler configuration.
        
        Args:
            config: Parsed firewall configuration
            
        Returns:
            True if valid, False otherwise
        """
        logger.info("Validating Zscaler configuration")
        try:
            # Check if required fields are present
            if not config.id:
                logger.error("Firewall ID is missing")
                return False
            
            if not config.vendor or config.vendor != "zscaler":
                logger.error("Invalid vendor for Zscaler parser")
                return False
            
            # Check policies
            logger.debug("Validating policies")
            for i, policy in enumerate(config.policies):
                if not isinstance(policy, dict):
                    logger.error(f"Policy {i+1} is not a dictionary")
                    return False
                # Check required fields
                required_fields = ["id", "action"]
                for field in required_fields:
                    if field not in policy:
                        logger.error(f"Required field '{field}' missing in policy {i+1}")
                        return False
            
            logger.info("Zscaler configuration validation completed successfully")
            return True
        except Exception as e:
            logger.error(f"Error validating Zscaler configuration: {str(e)}")
            return False