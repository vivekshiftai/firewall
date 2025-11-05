"""
Fortinet policy normalizer implementation.
"""
import logging
from typing import List
from app.vendors.abstract import AbstractPolicyNormalizer, NormalizedPolicy, ParsedConfig

logger = logging.getLogger(__name__)


class FortinetPolicyNormalizer(AbstractPolicyNormalizer):
    """Normalizer for Fortinet policies to standardized format."""

    def __init__(self, parsed_config: ParsedConfig):
        self.parsed_config = parsed_config

    def normalize_policies(self) -> List[NormalizedPolicy]:
        """
        Convert Fortinet policies to normalized format.
        
        Returns:
            List of normalized policies
        """
        normalized_policies = []
        try:
            for policy in self.parsed_config.policies:
                normalized_policy = self._normalize_policy(policy)
                if normalized_policy:
                    normalized_policies.append(normalized_policy)
        except Exception as e:
            logger.error(f"Error normalizing Fortinet policies: {str(e)}")
            raise ValueError(f"Failed to normalize Fortinet policies: {str(e)}")
        
        return normalized_policies

    def _normalize_policy(self, policy: dict) -> NormalizedPolicy:
        """Normalize a single Fortinet policy."""
        try:
            # Map Fortinet zones to common zone types
            source_zones = self._map_zones(policy.get("srcintf", []))
            destination_zones = self._map_zones(policy.get("dstintf", []))
            
            # Map Fortinet user groups to common user categories
            source_addresses = self._map_addresses(policy.get("srcaddr", []))
            destination_addresses = self._map_addresses(policy.get("dstaddr", []))
            
            # Map services
            services = self._map_services(policy.get("service", []))
            
            # Map action
            action = self._map_action(policy.get("action", "deny"))
            
            # Map status to enabled
            enabled = policy.get("status", "disable") == "enable"
            
            # Map logging
            logging_enabled = policy.get("logtraffic", "disable") != "disable"
            
            return NormalizedPolicy(
                id=str(policy.get("id", "")),
                name=policy.get("name", f"Policy-{policy.get('id', '')}"),
                source_zones=source_zones,
                destination_zones=destination_zones,
                source_addresses=source_addresses,
                destination_addresses=destination_addresses,
                services=services,
                action=action,
                enabled=enabled,
                logging=logging_enabled,
                schedule=policy.get("schedule", "always"),
                comments=policy.get("comments", "")
            )
        except Exception as e:
            logger.warning(f"Error normalizing policy {policy.get('id', 'unknown')}: {str(e)}")
            return None

    def _map_zones(self, zones: List[str]) -> List[str]:
        """Map Fortinet zones to common zone types."""
        # In a real implementation, this would map Fortinet specific zones
        # to common zone types (e.g., "internal", "external", "dmz")
        zone_mapping = {
            "port1": "external",
            "port2": "internal",
            "port3": "dmz",
            "wan1": "external",
            "lan": "internal",
            "dmz": "dmz"
        }
        
        mapped_zones = []
        for zone in zones:
            if isinstance(zone, dict) and "name" in zone:
                zone_name = zone["name"]
                mapped_zones.append(zone_mapping.get(zone_name, zone_name))
            else:
                mapped_zones.append(zone_mapping.get(zone, zone))
                
        return mapped_zones

    def _map_addresses(self, addresses: List[str]) -> List[str]:
        """Map Fortinet address objects to common address categories."""
        # In a real implementation, this would categorize addresses
        # (e.g., "all", "internal_networks", "external_networks")
        address_mapping = {
            "all": "any",
            "any": "any",
            "0.0.0.0/0": "any"
        }
        
        mapped_addresses = []
        for address in addresses:
            if isinstance(address, dict) and "name" in address:
                addr_name = address["name"]
                mapped_addresses.append(address_mapping.get(addr_name, addr_name))
            else:
                mapped_addresses.append(address_mapping.get(address, address))
                
        return mapped_addresses

    def _map_services(self, services: List[str]) -> List[str]:
        """Map Fortinet services to common service categories."""
        # In a real implementation, this would categorize services
        service_mapping = {
            "ALL": "any",
            "ANY": "any",
            "HTTP": "web",
            "HTTPS": "web",
            "SSH": "admin",
            "TELNET": "admin",
            "FTP": "file-transfer"
        }
        
        mapped_services = []
        for service in services:
            if isinstance(service, dict) and "name" in service:
                svc_name = service["name"]
                mapped_services.append(service_mapping.get(svc_name, svc_name))
            else:
                mapped_services.append(service_mapping.get(service, service))
                
        return mapped_services

    def _map_action(self, action: str) -> str:
        """Map Fortinet action to common action types."""
        action_mapping = {
            "accept": "allow",
            "deny": "deny",
            "reject": "deny"
        }
        return action_mapping.get(action.lower(), action.lower())