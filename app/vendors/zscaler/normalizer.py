"""
Zscaler policy normalizer implementation.
"""
import logging
from typing import List
from app.vendors.abstract import AbstractPolicyNormalizer, NormalizedPolicy, ParsedConfig

logger = logging.getLogger(__name__)


class ZscalerPolicyNormalizer(AbstractPolicyNormalizer):
    """Normalizer for Zscaler rules to standardized format."""

    def __init__(self, parsed_config: ParsedConfig):
        self.parsed_config = parsed_config

    def normalize_policies(self) -> List[NormalizedPolicy]:
        """
        Convert Zscaler rules to normalized format.
        
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
            logger.error(f"Error normalizing Zscaler policies: {str(e)}")
            raise ValueError(f"Failed to normalize Zscaler policies: {str(e)}")
        
        return normalized_policies

    def _normalize_policy(self, policy: dict) -> NormalizedPolicy:
        """Normalize a single Zscaler policy."""
        try:
            # Map Zscaler locations to common zone types
            source_zones = self._map_locations(policy.get("locations", []))
            destination_zones = []  # Zscaler doesn't have explicit destination zones
            
            # Map Zscaler user groups to common user categories
            source_addresses = self._map_user_groups(policy.get("users", []))
            destination_addresses = self._map_applications(policy.get("applications", []))
            
            # Map services (applications in Zscaler)
            services = self._map_applications(policy.get("applications", []))
            
            # Map action
            action = self._map_action(policy.get("action", "BLOCK"))
            
            # Map enabled status
            enabled = policy.get("enabled", True)
            
            # Zscaler doesn't have explicit logging per rule, but all activity is logged
            logging_enabled = True
            
            return NormalizedPolicy(
                id=policy.get("id", ""),
                name=policy.get("name", f"Rule-{policy.get('id', '')}"),
                source_zones=source_zones,
                destination_zones=destination_zones,
                source_addresses=source_addresses,
                destination_addresses=destination_addresses,
                services=services,
                action=action,
                enabled=enabled,
                logging=logging_enabled,
                schedule="always",  # Zscaler rules are always active unless scheduled
                comments=""
            )
        except Exception as e:
            logger.warning(f"Error normalizing policy {policy.get('id', 'unknown')}: {str(e)}")
            return None

    def _map_locations(self, locations: List[str]) -> List[str]:
        """Map Zscaler locations to common zone types."""
        # In a real implementation, this would map Zscaler specific locations
        # to common zone types (e.g., "internal", "external", "branch_office")
        zone_mapping = {
            "Headquarters": "internal",
            "Remote_Office": "branch",
            "Data_Center": "internal",
            "Cloud_DC": "internal"
        }
        
        mapped_zones = []
        for location in locations:
            mapped_zones.append(zone_mapping.get(location, location))
                
        return mapped_zones

    def _map_user_groups(self, user_groups: List[str]) -> List[str]:
        """Map Zscaler user groups to common user categories."""
        # In a real implementation, this would categorize user groups
        user_mapping = {
            "All_Users": "any",
            "Contractors": "guest",
            "Developers": "internal",
            "Executives": "internal"
        }
        
        mapped_users = []
        for user_group in user_groups:
            mapped_users.append(user_mapping.get(user_group, user_group))
                
        return mapped_users

    def _map_applications(self, applications: List[str]) -> List[str]:
        """Map Zscaler applications to common service categories."""
        # In a real implementation, this would categorize applications
        app_mapping = {
            "Microsoft_Office_365": "office",
            "Google_Workspace": "office",
            "Salesforce": "business",
            "Facebook": "social",
            "Twitter": "social",
            "LinkedIn": "social",
            "Dropbox": "file-sharing",
            "Box": "file-sharing"
        }
        
        mapped_apps = []
        for app in applications:
            mapped_apps.append(app_mapping.get(app, app))
                
        return mapped_apps

    def _map_action(self, action: str) -> str:
        """Map Zscaler action to common action types."""
        action_mapping = {
            "ALLOW": "allow",
            "BLOCK": "deny",
            "ISOLATE": "deny"
        }
        return action_mapping.get(action.upper(), action.lower())