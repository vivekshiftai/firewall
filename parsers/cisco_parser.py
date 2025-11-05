"""
Cisco ASA firewall configuration parser.
"""
import logging
from typing import Dict, Any, List
from parsers.base import BaseParser
from models.base import FirewallConfig
from exceptions.custom_exceptions import ParserError

# Configure logging
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
        logger.info("Starting Cisco ASA configuration parsing")
        try:
            # Extract basic information
            logger.debug("Extracting basic firewall information")
            firewall_id = config_data.get("id", "cisco-asa-firewall")
            version = config_data.get("version", "unknown")
            logger.info(f"Parsing Cisco ASA firewall ID: {firewall_id}, Version: {version}")
            
            # Parse access control entries (ACEs) as policies
            logger.debug("Parsing access control entries")
            policies = self._parse_aces(config_data.get("access_lists", []))
            logger.info(f"Parsed {len(policies)} access control entries")
            
            # Parse network objects
            logger.debug("Parsing network objects")
            network_objects = self._parse_network_objects(config_data.get("network_objects", []))
            logger.info(f"Parsed {len(network_objects)} network objects")
            
            # Parse service objects
            logger.debug("Parsing service objects")
            service_objects = self._parse_service_objects(config_data.get("service_objects", []))
            logger.info(f"Parsed {len(service_objects)} service objects")
            
            # Create standardized config
            logger.debug("Creating standardized firewall configuration")
            firewall_config = FirewallConfig(
                id=firewall_id,
                vendor="cisco",
                version=version,
                policies=policies,
                objects=network_objects + service_objects,
                metadata=config_data.get("metadata", {})
            )
            
            logger.info("Cisco ASA configuration parsing completed successfully")
            return firewall_config
            
        except Exception as e:
            logger.error(f"Error parsing Cisco ASA configuration: {str(e)}")
            raise ParserError(f"Error parsing Cisco ASA configuration: {str(e)}")

    def _parse_aces(self, aces_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse Cisco ASA access control entries into standardized policies.
        
        Args:
            aces_data: Raw ACE data
            
        Returns:
            List of standardized policies
        """
        logger.debug(f"Parsing {len(aces_data)} Cisco ASA access control entries")
        policies = []
        for i, ace_data in enumerate(aces_data):
            try:
                logger.debug(f"Parsing access control entry {i+1}")
                # Convert ACE to standardized policy format
                standardized_policy = {
                    "id": ace_data.get("id", f"ace-{i+1}"),
                    "name": ace_data.get("name", f"Access Control Entry {i+1}"),
                    "source_zones": ace_data.get("source_interfaces", []),
                    "destination_zones": ace_data.get("destination_interfaces", []),
                    "source_addresses": ace_data.get("source_addresses", []),
                    "destination_addresses": ace_data.get("destination_addresses", []),
                    "services": ace_data.get("services", []),
                    "action": ace_data.get("action", "deny"),
                    "enabled": ace_data.get("enabled", True),
                    "logging": ace_data.get("logging", False),
                    "schedule": "always",
                    "comments": ace_data.get("remark", "")
                }
                policies.append(standardized_policy)
                logger.debug(f"Access control entry {i+1} parsed successfully")
            except Exception as e:
                logger.warning(f"Error parsing access control entry {i+1}: {str(e)}")
                # Continue with other ACEs
                continue
        logger.info(f"Successfully parsed {len(policies)} out of {len(aces_data)} access control entries")
        return policies

    def _parse_network_objects(self, network_objects_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse Cisco ASA network objects.
        
        Args:
            network_objects_data: Raw network object data
            
        Returns:
            List of network objects
        """
        logger.debug(f"Parsing {len(network_objects_data)} Cisco ASA network objects")
        network_objects = []
        for i, obj_data in enumerate(network_objects_data):
            try:
                logger.debug(f"Parsing network object {i+1}")
                network_objects.append(obj_data)
                logger.debug(f"Network object {i+1} parsed successfully")
            except Exception as e:
                logger.warning(f"Error parsing network object {i+1}: {str(e)}")
                continue
        logger.info(f"Successfully parsed {len(network_objects)} out of {len(network_objects_data)} network objects")
        return network_objects

    def _parse_service_objects(self, service_objects_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse Cisco ASA service objects.
        
        Args:
            service_objects_data: Raw service object data
            
        Returns:
            List of service objects
        """
        logger.debug(f"Parsing {len(service_objects_data)} Cisco ASA service objects")
        service_objects = []
        for i, obj_data in enumerate(service_objects_data):
            try:
                logger.debug(f"Parsing service object {i+1}")
                service_objects.append(obj_data)
                logger.debug(f"Service object {i+1} parsed successfully")
            except Exception as e:
                logger.warning(f"Error parsing service object {i+1}: {str(e)}")
                continue
        logger.info(f"Successfully parsed {len(service_objects)} out of {len(service_objects_data)} service objects")
        return service_objects

    def validate_config(self, config: FirewallConfig) -> bool:
        """
        Validate the parsed Cisco ASA configuration.
        
        Args:
            config: Parsed firewall configuration
            
        Returns:
            True if valid, False otherwise
        """
        logger.info("Validating Cisco ASA configuration")
        try:
            # Check if required fields are present
            if not config.id:
                logger.error("Firewall ID is missing")
                return False
            
            if not config.vendor or config.vendor != "cisco":
                logger.error("Invalid vendor for Cisco ASA parser")
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
            
            logger.info("Cisco ASA configuration validation completed successfully")
            return True
        except Exception as e:
            logger.error(f"Error validating Cisco ASA configuration: {str(e)}")
            return False