"""
Fortinet firewall configuration parser.
"""
import logging
from typing import Dict, Any, List
from parsers.base import BaseParser
from models.base import FirewallConfig
from models.fortinet import FortinetPolicy, FortinetAddressObject, FortinetServiceObject
from exceptions.custom_exceptions import ParserError

# Configure logging
logger = logging.getLogger(__name__)

class FortinetParser(BaseParser):
    """Parser for Fortinet firewall configurations."""

    def parse(self, config_data: Dict[str, Any]) -> FirewallConfig:
        """
        Parse Fortinet configuration data into a standardized FirewallConfig.
        
        Args:
            config_data: Raw Fortinet configuration data
            
        Returns:
            Standardized FirewallConfig object
        """
        logger.info("Starting Fortinet configuration parsing")
        try:
            # Extract basic information
            logger.debug("Extracting basic firewall information")
            firewall_id = config_data.get("id", "fortinet-firewall")
            version = config_data.get("version", "unknown")
            logger.info(f"Parsing Fortinet firewall ID: {firewall_id}, Version: {version}")
            
            # Parse policies
            logger.debug("Parsing policies")
            policies = self._parse_policies(config_data.get("policies", []))
            logger.info(f"Parsed {len(policies)} policies")
            
            # Parse address objects
            logger.debug("Parsing address objects")
            address_objects = self._parse_address_objects(config_data.get("addresses", []))
            logger.info(f"Parsed {len(address_objects)} address objects")
            
            # Parse service objects
            logger.debug("Parsing service objects")
            service_objects = self._parse_service_objects(config_data.get("services", []))
            logger.info(f"Parsed {len(service_objects)} service objects")
            
            # Create standardized config
            logger.debug("Creating standardized firewall configuration")
            firewall_config = FirewallConfig(
                id=firewall_id,
                vendor="fortinet",
                version=version,
                policies=policies,
                objects=address_objects + service_objects,
                metadata=config_data.get("metadata", {})
            )
            
            logger.info("Fortinet configuration parsing completed successfully")
            return firewall_config
            
        except Exception as e:
            logger.error(f"Error parsing Fortinet configuration: {str(e)}")
            raise ParserError(f"Error parsing Fortinet configuration: {str(e)}")

    def _parse_policies(self, policies_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse Fortinet policies into standardized format.
        
        Args:
            policies_data: Raw policy data
            
        Returns:
            List of standardized policies
        """
        logger.debug(f"Parsing {len(policies_data)} Fortinet policies")
        policies = []
        for i, policy_data in enumerate(policies_data):
            try:
                logger.debug(f"Parsing policy {i+1}")
                fortinet_policy = FortinetPolicy(**policy_data)
                # Convert to standardized format
                standardized_policy = {
                    "id": fortinet_policy.id,
                    "name": fortinet_policy.name,
                    "source_zones": fortinet_policy.srcintf,
                    "destination_zones": fortinet_policy.dstintf,
                    "source_addresses": fortinet_policy.srcaddr,
                    "destination_addresses": fortinet_policy.dstaddr,
                    "services": fortinet_policy.service,
                    "action": fortinet_policy.action,
                    "enabled": fortinet_policy.status == "enable",
                    "logging": "log" in fortinet_policy and fortinet_policy.log != "disable",
                    "schedule": getattr(fortinet_policy, "schedule", "always"),
                    "comments": getattr(fortinet_policy, "comments", "")
                }
                policies.append(standardized_policy)
                logger.debug(f"Policy {i+1} parsed successfully")
            except Exception as e:
                logger.warning(f"Error parsing policy {i+1}: {str(e)}")
                # Continue with other policies
                continue
        logger.info(f"Successfully parsed {len(policies)} out of {len(policies_data)} policies")
        return policies

    def _parse_address_objects(self, addresses_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse Fortinet address objects.
        
        Args:
            addresses_data: Raw address object data
            
        Returns:
            List of address objects
        """
        logger.debug(f"Parsing {len(addresses_data)} Fortinet address objects")
        address_objects = []
        for i, addr_data in enumerate(addresses_data):
            try:
                logger.debug(f"Parsing address object {i+1}")
                addr_obj = FortinetAddressObject(**addr_data)
                address_objects.append(addr_obj.dict())
                logger.debug(f"Address object {i+1} parsed successfully")
            except Exception as e:
                logger.warning(f"Error parsing address object {i+1}: {str(e)}")
                continue
        logger.info(f"Successfully parsed {len(address_objects)} out of {len(addresses_data)} address objects")
        return address_objects

    def _parse_service_objects(self, services_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse Fortinet service objects.
        
        Args:
            services_data: Raw service object data
            
        Returns:
            List of service objects
        """
        logger.debug(f"Parsing {len(services_data)} Fortinet service objects")
        service_objects = []
        for i, service_data in enumerate(services_data):
            try:
                logger.debug(f"Parsing service object {i+1}")
                service_obj = FortinetServiceObject(**service_data)
                service_objects.append(service_obj.dict())
                logger.debug(f"Service object {i+1} parsed successfully")
            except Exception as e:
                logger.warning(f"Error parsing service object {i+1}: {str(e)}")
                continue
        logger.info(f"Successfully parsed {len(service_objects)} out of {len(services_data)} service objects")
        return service_objects

    def validate_config(self, config: FirewallConfig) -> bool:
        """
        Validate the parsed Fortinet configuration.
        
        Args:
            config: Parsed firewall configuration
            
        Returns:
            True if valid, False otherwise
        """
        logger.info("Validating Fortinet configuration")
        try:
            # Check if required fields are present
            if not config.id:
                logger.error("Firewall ID is missing")
                return False
            
            if not config.vendor or config.vendor != "fortinet":
                logger.error("Invalid vendor for Fortinet parser")
                return False
            
            # Check policies
            logger.debug("Validating policies")
            for i, policy in enumerate(config.policies):
                if not isinstance(policy, dict):
                    logger.error(f"Policy {i+1} is not a dictionary")
                    return False
                # Check required fields
                required_fields = ["id", "source_zones", "destination_zones", "action"]
                for field in required_fields:
                    if field not in policy:
                        logger.error(f"Required field '{field}' missing in policy {i+1}")
                        return False
            
            logger.info("Fortinet configuration validation completed successfully")
            return True
        except Exception as e:
            logger.error(f"Error validating Fortinet configuration: {str(e)}")
            return False