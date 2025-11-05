"""
Policy normalization for cross-vendor firewall analysis.
"""
from typing import List, Dict, Any
from app.models.vendors import VendorType, VendorNormalizedPolicy, NormalizedZone, NormalizedUserGroup, VendorParsedConfig
from app.vendors.abstract import NormalizedPolicy, ParsedConfig
from models.fortinet import FortinetPolicy, FortinetZone
from models.zscaler import ZscalerRule, ZscalerLocation, ZscalerUserGroup


class FortinetNormalizer:
    """Normalizer for Fortinet firewall policies."""

    def normalize_policy(self, fw_policy: Dict[str, Any]) -> NormalizedPolicy:
        """
        Normalize a Fortinet policy to the common format.
        
        Args:
            fw_policy: Fortinet policy dictionary
            
        Returns:
            NormalizedPolicy object
        """
        # Extract Fortinet-specific fields
        policy_id = str(fw_policy.get("id", ""))
        policy_name = fw_policy.get("name", f"Policy-{policy_id}")
        src_interfaces = fw_policy.get("srcintf", [])
        dst_interfaces = fw_policy.get("dstintf", [])
        src_addresses = fw_policy.get("srcaddr", [])
        dst_addresses = fw_policy.get("dstaddr", [])
        services = fw_policy.get("service", [])
        action = fw_policy.get("action", "deny")
        status = fw_policy.get("status", "disable")
        schedule = fw_policy.get("schedule", "always")
        comments = fw_policy.get("comments", "")
        
        # Map Fortinet action to common format
        normalized_action = "allow" if action.lower() == "accept" else action.lower()
        
        # Map Fortinet protocols to common format
        application_protocols = self._map_protocols(services)
        
        # Convert port ranges to standard format
        ports = self._extract_ports(services)
        
        return NormalizedPolicy(
            id=policy_id,
            name=policy_name,
            source_zones=src_interfaces,
            destination_zones=dst_interfaces,
            source_addresses=src_addresses,
            destination_addresses=dst_addresses,
            services=services,
            action=normalized_action,
            enabled=(status.lower() == "enable"),
            logging=(fw_policy.get("logtraffic", "disable") != "disable"),
            schedule=schedule,
            comments=comments
        )

    def map_zone_to_normalized(self, zone: Dict[str, Any]) -> NormalizedZone:
        """
        Map a Fortinet zone to a normalized zone.
        
        Args:
            zone: Fortinet zone dictionary
            
        Returns:
            NormalizedZone object
        """
        zone_name = zone.get("name", "")
        zone_type = self.get_zone_type(zone_name)
        
        # Determine trust level based on zone type
        trust_level_map = {
            "internal": "trusted",
            "dmz": "semi-trusted",
            "restricted": "untrusted",
            "external": "untrusted",
            "guest": "untrusted"
        }
        
        return NormalizedZone(
            zone_id=zone_name,
            zone_name=zone_name,
            zone_type=zone_type,
            entities=[],  # Would be populated with actual entities in a full implementation
            trust_level=trust_level_map.get(zone_type, "untrusted"),
            vendor_specific_type="fortinet_zone",
            source_vendor=VendorType.FORTINET
        )

    def map_user_group_to_normalized(self, group: Dict[str, Any]) -> NormalizedUserGroup:
        """
        Map a Fortinet user group to a normalized user group.
        
        Args:
            group: User group dictionary
            
        Returns:
            NormalizedUserGroup object
        """
        group_name = group.get("name", "")
        
        return NormalizedUserGroup(
            group_id=group_name,
            group_name=group_name,
            group_type="user",  # Default assumption
            member_count=None,  # Not available in basic Fortinet model
            requires_mfa=False,  # Not available in basic Fortinet model
            requires_vpn=False,  # Not available in basic Fortinet model
            allowed_applications=[],  # Not available in basic Fortinet model
            data_access_level="internal",  # Default assumption
            source_vendor=VendorType.FORTINET
        )

    def get_zone_type(self, zone_name: str) -> str:
        """
        Determine zone type based on zone name.
        
        Args:
            zone_name: Name of the zone
            
        Returns:
            Zone type (internal, dmz, restricted, etc.)
        """
        zone_name_lower = zone_name.lower()
        
        if "internal" in zone_name_lower:
            return "internal"
        elif "dmz" in zone_name_lower or "external" in zone_name_lower:
            return "dmz"
        elif "ot" in zone_name_lower or "industrial" in zone_name_lower:
            return "restricted"
        elif "guest" in zone_name_lower:
            return "guest"
        else:
            return "internal"  # Default assumption

    def _map_protocols(self, services: List[str]) -> List[str]:
        """
        Map Fortinet protocols to common format.
        
        Args:
            services: List of service names
            
        Returns:
            List of common protocol names
        """
        # In a real implementation, this would map Fortinet service objects
        # to common protocol names. For now, we'll return a default list.
        return ["tcp", "udp"]  # Default assumption

    def _extract_ports(self, services: List[str]) -> List[int]:
        """
        Extract ports from Fortinet services.
        
        Args:
            services: List of service names
            
        Returns:
            List of port numbers
        """
        # In a real implementation, this would extract actual port numbers
        # from Fortinet service objects. For now, we'll return a default list.
        return [80, 443]  # Default assumption


class ZscalerNormalizer:
    """Normalizer for Zscaler cloud security rules."""

    def normalize_rule(self, zs_rule: Dict[str, Any]) -> NormalizedPolicy:
        """
        Normalize a Zscaler rule to the common format.
        
        Args:
            zs_rule: Zscaler rule dictionary
            
        Returns:
            NormalizedPolicy object
        """
        # Extract Zscaler-specific fields
        rule_id = zs_rule.get("id", "")
        rule_name = zs_rule.get("name", f"Rule-{rule_id}")
        locations = zs_rule.get("locations", [])
        departments = zs_rule.get("departments", [])
        users = zs_rule.get("users", [])
        applications = zs_rule.get("applications", [])
        action = zs_rule.get("action", "BLOCK")
        enabled = zs_rule.get("enabled", False)
        
        # Map Zscaler action to common format
        normalized_action = "allow" if action.upper() == "ALLOW" else "deny"
        
        # Combine locations and departments as source zones
        source_zones = locations + departments
        
        return NormalizedPolicy(
            id=rule_id,
            name=rule_name,
            source_zones=source_zones,
            destination_zones=[],  # Zscaler doesn't have explicit destination zones
            source_addresses=users,
            destination_addresses=applications,
            services=applications,  # In Zscaler, applications serve as services
            action=normalized_action,
            enabled=enabled,
            logging=True,  # Zscaler logs all activity by default
            schedule="always",  # Zscaler rules are always active unless scheduled
            comments=""
        )

    def map_location_to_normalized(self, loc: Dict[str, Any]) -> NormalizedZone:
        """
        Map a Zscaler location to a normalized zone.
        
        Args:
            loc: Zscaler location dictionary
            
        Returns:
            NormalizedZone object
        """
        location_name = loc.get("name", "")
        location_id = loc.get("id", "")
        zone_type = self.get_zone_type(loc)
        
        # Determine trust level based on zone type
        trust_level_map = {
            "internal": "trusted",
            "dmz": "semi-trusted",
            "restricted": "untrusted",
            "external": "untrusted",
            "guest": "untrusted"
        }
        
        return NormalizedZone(
            zone_id=location_id,
            zone_name=location_name,
            zone_type=zone_type,
            entities=loc.get("ip_addresses", []),  # IP addresses in the location
            trust_level=trust_level_map.get(zone_type, "untrusted"),
            vendor_specific_type="zscaler_location",
            source_vendor=VendorType.ZSCALER
        )

    def map_user_group_to_normalized(self, group: Dict[str, Any]) -> NormalizedUserGroup:
        """
        Map a Zscaler user group to a normalized user group.
        
        Args:
            group: Zscaler user group dictionary
            
        Returns:
            NormalizedUserGroup object
        """
        group_id = group.get("id", "")
        group_name = group.get("name", "")
        users = group.get("users", [])
        
        return NormalizedUserGroup(
            group_id=group_id,
            group_name=group_name,
            group_type="user",  # Default assumption
            member_count=len(users) if users else None,
            requires_mfa=False,  # Not specified in basic model
            requires_vpn=False,  # Not specified in basic model
            allowed_applications=[],  # Not specified in basic model
            data_access_level="internal",  # Default assumption
            source_vendor=VendorType.ZSCALER
        )

    def get_zone_type(self, location_info: Dict[str, Any]) -> str:
        """
        Determine zone type based on location information.
        
        Args:
            location_info: Location information dictionary
            
        Returns:
            Zone type (internal, dmz, restricted, etc.)
        """
        location_name = location_info.get("name", "").lower()
        
        if "cloud" in location_name and ("hq" in location_name or "data" in location_name):
            return "internal"
        elif "branch" in location_name or "remote" in location_name:
            return "dmz"
        elif "restricted" in location_name:
            return "restricted"
        elif "guest" in location_name:
            return "guest"
        else:
            return "internal"  # Default assumption


class NormalizationEngine:
    """Engine for normalizing firewall configurations."""

    def normalize_config(self, config: ParsedConfig) -> VendorParsedConfig:
        """
        Normalize a parsed configuration to the vendor-neutral format.
        
        Args:
            config: Parsed configuration
            
        Returns:
            VendorParsedConfig object
        """
        # Determine the vendor and create appropriate normalizer
        if config.vendor == "fortinet":
            normalizer = FortinetNormalizer()
        elif config.vendor == "zscaler":
            normalizer = ZscalerNormalizer()
        else:
            raise ValueError(f"Unsupported vendor: {config.vendor}")
        
        # Normalize policies
        normalized_policies = self.normalize_policies(config.policies, normalizer, config.vendor)
        
        # Normalize zones
        normalized_zones = []
        for zone in config.zones:
            if config.vendor == "fortinet":
                normalized_zones.append(normalizer.map_zone_to_normalized(zone))
            elif config.vendor == "zscaler":
                normalized_zones.append(normalizer.map_location_to_normalized(zone))
        
        # Normalize user groups
        normalized_user_groups = []
        # In a full implementation, this would process user groups from the config objects
        
        # Create vendor info
        vendor_info = {
            "vendor_name": config.vendor,
            "vendor_version": config.version,
            "config_format": "json",  # Assuming JSON format
            "features_supported": [],  # Would be populated in a full implementation
            "last_updated": __import__('datetime').datetime.utcnow()
        }
        
        return VendorParsedConfig(
            config_id=f"normalized_{config.vendor}_{__import__('datetime').datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            vendor=VendorType(config.vendor),
            vendor_info=vendor_info,
            policies=normalized_policies,
            zones=normalized_zones,
            user_groups=normalized_user_groups,
            addresses={},  # Would be populated in a full implementation
            services={},  # Would be populated in a full implementation
            statistics={
                "policy_count": len(normalized_policies),
                "zone_count": len(normalized_zones),
                "user_group_count": len(normalized_user_groups)
            }
        )

    def normalize_policies(self, policies: List[Dict[str, Any]], normalizer, vendor: str) -> List[VendorNormalizedPolicy]:
        """
        Normalize policies using the appropriate normalizer.
        
        Args:
            policies: List of policy dictionaries
            normalizer: Normalizer instance (FortinetNormalizer or ZscalerNormalizer)
            vendor: Vendor name
            
        Returns:
            List of normalized policies
        """
        normalized_policies = []
        
        for policy in policies:
            if vendor == "fortinet" and hasattr(normalizer, 'normalize_policy'):
                normalized_policy = normalizer.normalize_policy(policy)
                # Convert abstract NormalizedPolicy to VendorNormalizedPolicy
                vendor_policy = self._convert_to_vendor_policy(normalized_policy, VendorType.FORTINET)
                normalized_policies.append(vendor_policy)
            elif vendor == "zscaler" and hasattr(normalizer, 'normalize_rule'):
                normalized_policy = normalizer.normalize_rule(policy)
                # Convert abstract NormalizedPolicy to VendorNormalizedPolicy
                vendor_policy = self._convert_to_vendor_policy(normalized_policy, VendorType.ZSCALER)
                normalized_policies.append(vendor_policy)
                
        return normalized_policies

    def _convert_to_vendor_policy(self, normalized_policy: NormalizedPolicy, vendor: VendorType) -> VendorNormalizedPolicy:
        """
        Convert abstract NormalizedPolicy to VendorNormalizedPolicy.
        
        Args:
            normalized_policy: Abstract normalized policy
            vendor: Vendor type
            
        Returns:
            VendorNormalizedPolicy object
        """
        return VendorNormalizedPolicy(
            policy_id=normalized_policy.id,
            policy_name=normalized_policy.name,
            source_entity=",".join(normalized_policy.source_zones) if normalized_policy.source_zones else "",
            source_entity_type="zone",
            dest_entity=",".join(normalized_policy.destination_addresses) if normalized_policy.destination_addresses else "",
            dest_entity_type="address",
            application_protocol=normalized_policy.services,
            ports=[],  # Would be populated in a full implementation
            action=normalized_policy.action,
            enforcement_layer="network",  # Default assumption
            priority=0,  # Default assumption
            enabled=normalized_policy.enabled,
            logging_enabled=normalized_policy.logging,
            enforcement_technologies=["firewall"],  # Default assumption
            vendor_specific_data={},  # Would be populated in a full implementation
            source_vendor=vendor,
            timestamp_added=__import__('datetime').datetime.utcnow(),
            timestamp_modified=__import__('datetime').datetime.utcnow()
        )

    def create_canonical_form(self, policy: VendorNormalizedPolicy) -> str:
        """
        Create a canonical form of a policy for comparison.
        
        Args:
            policy: Normalized policy
            
        Returns:
            Canonical string representation
        """
        # Create a canonical string representation for comparison
        # This would be used to identify semantically equivalent policies across vendors
        canonical_parts = [
            f"source:{'|'.join(sorted(policy.source_entity.split(','))) if policy.source_entity else 'any'}",
            f"dest:{'|'.join(sorted(policy.dest_entity.split(','))) if policy.dest_entity else 'any'}",
            f"action:{policy.action}",
            f"protocols:{'|'.join(sorted(policy.application_protocol))}"
        ]
        
        return "|".join(canonical_parts)