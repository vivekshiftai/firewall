"""
Policy normalization for cross-vendor firewall analysis.
Includes enhanced normalization with better variant handling.
"""
import logging
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass, field
import hashlib
from app.models.vendors import VendorType, VendorNormalizedPolicy, NormalizedZone, NormalizedUserGroup, VendorParsedConfig
from app.vendors.abstract import NormalizedPolicy, ParsedConfig
from models.fortinet import FortinetPolicy, FortinetZone
from models.zscaler import ZscalerRule, ZscalerLocation, ZscalerUserGroup

logger = logging.getLogger(__name__)


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


# ============================================================================
# Enhanced Normalization Classes (merged from enhanced_normalizer.py)
# ============================================================================

@dataclass
class NormalizedPolicyEnhanced:
    """Vendor-neutral policy representation with enhanced fields."""
    policy_id: str
    policy_name: str
    source_users: Set[str] = field(default_factory=set)
    source_location: Optional[str] = None
    dest_resource: Optional[str] = None
    dest_type: str = "unknown"  # app, server, network, url, internet
    action: str = "unknown"  # allow, deny, quarantine
    protocols: Set[str] = field(default_factory=set)
    ports: Set[int] = field(default_factory=set)
    applies_to_all_destinations: bool = False
    applies_to_all_sources: bool = False
    requires_mfa: bool = False
    requires_encryption: bool = False
    dlp_enabled: bool = False
    logging_enabled: bool = False
    utm_profiles: Set[str] = field(default_factory=set)
    priority: int = 999
    enabled: bool = True
    source_vendor: str = "unknown"
    raw_policy: Dict = field(default_factory=dict)
    
    def __hash__(self):
        """Allow NormalizedPolicyEnhanced to be used in sets/dicts."""
        return hash(self.policy_id)
    
    def semantic_hash(self) -> str:
        """Create hash of policy semantics for duplicate detection."""
        key = f"{sorted(self.source_users)}_{self.dest_resource}_{self.action}_{self.dest_type}"
        return hashlib.md5(key.encode()).hexdigest()


class PolicyNormalizerEnhanced:
    """Enhanced normalizer with better variant handling."""
    
    # All variants that represent "all" destinations
    ALL_DESTINATION_VARIANTS = {
        'all', 'any', '*', '0.0.0.0/0', '::/0', 'internet',
        'untrusted', 'dmz', 'any-ipv4', 'any-ipv6'
    }
    
    # All variants that represent "all" sources
    ALL_SOURCE_VARIANTS = {
        'all', 'any', '*', '0.0.0.0/0', '::/0', 'any-ipv4', 'any-ipv6'
    }
    
    # All variants that represent "all" services
    ALL_SERVICE_VARIANTS = {
        'all', 'any', 'all_tcp', 'all_udp', 'all_icmp', 'any-service'
    }
    
    @staticmethod
    def is_all_destinations(destinations: List) -> bool:
        """
        Check if destinations represent 'all'.
        Handles all variants: "all", "0.0.0.0/0", "ANY", etc.
        
        Args:
            destinations: List of destination addresses
            
        Returns:
            True if represents all destinations
        """
        if not destinations:
            return False
        
        normalization = PolicyNormalizerEnhanced.ALL_DESTINATION_VARIANTS
        
        return any(str(d).lower() in normalization for d in destinations if d)
    
    @staticmethod
    def is_all_sources(sources: List) -> bool:
        """
        Check if sources represent 'all'.
        
        Args:
            sources: List of source addresses
            
        Returns:
            True if represents all sources
        """
        if not sources:
            return False
        
        normalization = PolicyNormalizerEnhanced.ALL_SOURCE_VARIANTS
        
        return any(str(s).lower() in normalization for s in sources if s)
    
    @staticmethod
    def is_all_services(services: List) -> bool:
        """
        Check if services represent 'all'.
        
        Args:
            services: List of services
            
        Returns:
            True if represents all services
        """
        if not services:
            return False
        
        normalization = PolicyNormalizerEnhanced.ALL_SERVICE_VARIANTS
        
        return any(str(s).upper() in {v.upper() for v in normalization} for s in services if s)
    
    @staticmethod
    def determine_dest_type(policy: Dict, vendor: str = "fortinet") -> str:
        """
        Determine destination type from policy.
        
        Args:
            policy: Policy dictionary
            vendor: Vendor name
            
        Returns:
            Destination type: 'internet', 'internal_network', 'resource', 'url'
        """
        # Handle Fortinet field names (dstaddr, dstintf)
        dests = (policy.get('destination_addresses', []) or 
                policy.get('destination_zones', []) or
                policy.get('dstaddr', []) or
                policy.get('dstintf', []) or
                [])
        
        if PolicyNormalizerEnhanced.is_all_destinations(dests):
            return 'internet'
        
        # Check for private IP ranges
        if any(str(d).startswith(('10.', '192.168', '172.')) for d in dests if d):
            return 'internal_network'
        
        # Zscaler specific
        if vendor == 'zscaler':
            if 'url_categories' in policy:
                return 'url'
            if 'applications' in policy:
                return 'app'
        
        return 'resource'
    
    @staticmethod
    def normalize_fortinet_policy(policy: Dict) -> NormalizedPolicyEnhanced:
        """
        Normalize a Fortinet policy to enhanced format.
        
        Args:
            policy: Fortinet policy dictionary
            
        Returns:
            NormalizedPolicyEnhanced object
        """
        # Extract policy ID - handle policyid, policy_id, and id
        policy_id = str(policy.get('policyid', policy.get('policy_id', policy.get('id', 'unknown'))))
        
        # Extract source/destination addresses - handle Fortinet field names
        sources = (policy.get('source_addresses', []) or 
                  policy.get('source_zones', []) or 
                  policy.get('srcaddr', []) or 
                  policy.get('srcintf', []) or 
                  [])
        
        destinations = (policy.get('destination_addresses', []) or 
                       policy.get('destination_zones', []) or 
                       policy.get('dstaddr', []) or 
                       policy.get('dstintf', []) or 
                       [])
        
        # Extract services - handle Fortinet field names
        services = (policy.get('services', []) or 
                   policy.get('service', []) or 
                   [])
        
        # Extract user groups - handle multiple formats
        groups = []
        if 'user_groups' in policy:
            groups = policy['user_groups'] if isinstance(policy['user_groups'], list) else [policy['user_groups']]
        elif 'groups' in policy:
            groups_str = policy['groups']
            if isinstance(groups_str, str):
                # Handle Fortinet format: "Group1\" \"Group2"
                if "\\\"" in groups_str:
                    groups = [g.strip().strip('"') for g in groups_str.split('\\"') if g.strip()]
                elif " " in groups_str:
                    groups = [g.strip() for g in groups_str.split() if g.strip()]
                else:
                    groups = [groups_str]
            elif isinstance(groups_str, list):
                groups = groups_str
        
        # Extract UTM profiles - handle Fortinet field names
        utm_profiles = set()
        for key in ['av-profile', 'av_profile', 'ips-sensor', 'ips_sensor', 
                   'webfilter-profile', 'webfilter_profile', 'application-list', 'application_list',
                   'av', 'ips', 'webfilter']:
            if policy.get(key):
                utm_profiles.add(str(policy[key]))
        
        # Check logging - handle Fortinet field names
        logging_enabled = bool(
            policy.get('log_enabled', False) or 
            policy.get('log', False) or 
            policy.get('logtraffic', '').lower() in ['all', 'utm', 'security']
        )
        
        # Check enabled status - handle Fortinet field names
        enabled = True
        if 'enabled' in policy:
            enabled = policy['enabled']
        elif 'status' in policy:
            enabled = policy.get('status', 'enable').lower() == 'enable'
        
        return NormalizedPolicyEnhanced(
            policy_id=policy_id,
            policy_name=str(policy.get('name', 'unknown')),
            source_users=set(groups) if groups else set(),
            dest_resource='_'.join(str(d) for d in destinations[:3]) if destinations else 'unknown',
            dest_type=PolicyNormalizerEnhanced.determine_dest_type(policy, 'fortinet'),
            action=policy.get('action', 'unknown').lower().replace('accept', 'allow'),
            protocols=set(str(s) for s in services),
            applies_to_all_destinations=PolicyNormalizerEnhanced.is_all_destinations(destinations),
            applies_to_all_sources=PolicyNormalizerEnhanced.is_all_sources(sources),
            requires_mfa=bool(policy.get('require_mfa', False)),
            requires_encryption=bool(policy.get('require_encryption', False)),
            dlp_enabled=bool(policy.get('dlp-sensor') or policy.get('dlp_sensor')),
            logging_enabled=logging_enabled,
            utm_profiles=utm_profiles,
            priority=int(policy.get('priority', 999)),
            enabled=enabled,
            source_vendor='fortinet',
            raw_policy=policy
        )
    
    @staticmethod
    def normalize_zscaler_policy(policy: Dict, policy_type: str = 'url_filtering') -> NormalizedPolicyEnhanced:
        """
        Normalize a Zscaler policy to enhanced format.
        
        Args:
            policy: Zscaler policy dictionary
            policy_type: Type of policy ('url_filtering', 'dlp', 'zpa')
            
        Returns:
            NormalizedPolicyEnhanced object
        """
        # Extract groups
        groups = policy.get('apply_to_groups', []) or []
        if isinstance(groups, str):
            groups = [g.strip() for g in groups.split(',') if g.strip()]
        
        # Determine if applies to all destinations
        applies_to_all = False
        if not policy.get('destinations') and not policy.get('url_categories'):
            applies_to_all = True
        elif policy.get('url_categories') == ['ANY'] or policy.get('url_categories') == ['*']:
            applies_to_all = True
        
        return NormalizedPolicyEnhanced(
            policy_id=str(policy.get('id', policy.get('policy_id', 'unknown'))),
            policy_name=str(policy.get('policy_name', policy.get('name', 'unknown'))),
            source_users=set(groups) if groups else set(),
            dest_resource=policy.get('policy_name', 'unknown'),
            dest_type=PolicyNormalizerEnhanced.determine_dest_type(policy, 'zscaler'),
            action=policy.get('action', 'unknown').lower(),
            applies_to_all_destinations=applies_to_all,
            dlp_enabled=policy_type == 'dlp' or bool(policy.get('dlp_settings')),
            logging_enabled=bool(policy.get('audit_enabled', False)),
            priority=int(policy.get('priority', 999)),
            enabled=policy.get('enabled', True),
            source_vendor='zscaler',
            raw_policy=policy
        )