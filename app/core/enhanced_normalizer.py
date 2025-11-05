"""
Enhanced policy normalizer with better variant handling.
Handles all variants of policy representation (e.g., "all" vs "0.0.0.0/0" vs "ANY").
"""
import logging
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, field
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class EnhancedNormalizedPolicy:
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
        """Allow EnhancedNormalizedPolicy to be used in sets/dicts."""
        return hash(self.policy_id)
    
    def semantic_hash(self) -> str:
        """Create hash of policy semantics for duplicate detection."""
        key = f"{sorted(self.source_users)}_{self.dest_resource}_{self.action}_{self.dest_type}"
        return hashlib.md5(key.encode()).hexdigest()


class EnhancedPolicyNormalizer:
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
        
        normalization = EnhancedPolicyNormalizer.ALL_DESTINATION_VARIANTS
        
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
        
        normalization = EnhancedPolicyNormalizer.ALL_SOURCE_VARIANTS
        
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
        
        normalization = EnhancedPolicyNormalizer.ALL_SERVICE_VARIANTS
        
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
        dests = policy.get('destination_addresses', []) or policy.get('destination_zones', [])
        
        if EnhancedPolicyNormalizer.is_all_destinations(dests):
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
    def normalize_fortinet_policy(policy: Dict) -> EnhancedNormalizedPolicy:
        """
        Normalize a Fortinet policy to enhanced format.
        
        Args:
            policy: Fortinet policy dictionary
            
        Returns:
            EnhancedNormalizedPolicy object
        """
        # Extract user groups (handle multiple formats)
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
        
        # Extract source/destination addresses
        sources = policy.get('source_addresses', []) or policy.get('source_zones', []) or []
        destinations = policy.get('destination_addresses', []) or policy.get('destination_zones', []) or []
        
        # Extract services
        services = policy.get('services', []) or policy.get('service', []) or []
        
        # Extract UTM profiles
        utm_profiles = set()
        for key in ['av-profile', 'av_profile', 'ips-sensor', 'ips_sensor', 
                   'webfilter-profile', 'webfilter_profile', 'application-list', 'application_list']:
            if policy.get(key):
                utm_profiles.add(str(policy[key]))
        
        return EnhancedNormalizedPolicy(
            policy_id=str(policy.get('policy_id', policy.get('id', 'unknown'))),
            policy_name=str(policy.get('name', 'unknown')),
            source_users=set(groups) if groups else set(),
            dest_resource='_'.join(str(d) for d in destinations[:3]) if destinations else 'unknown',
            dest_type=EnhancedPolicyNormalizer.determine_dest_type(policy, 'fortinet'),
            action=policy.get('action', 'unknown').lower().replace('accept', 'allow'),
            protocols=set(str(s) for s in services),
            applies_to_all_destinations=EnhancedPolicyNormalizer.is_all_destinations(destinations),
            applies_to_all_sources=EnhancedPolicyNormalizer.is_all_sources(sources),
            requires_mfa=bool(policy.get('require_mfa', False)),
            requires_encryption=bool(policy.get('require_encryption', False)),
            dlp_enabled=bool(policy.get('dlp-sensor') or policy.get('dlp_sensor')),
            logging_enabled=bool(policy.get('log_enabled', False) or policy.get('log', False)),
            utm_profiles=utm_profiles,
            priority=int(policy.get('priority', 999)),
            enabled=policy.get('enabled', True) if 'enabled' in policy else policy.get('status', 'enable').lower() == 'enable',
            source_vendor='fortinet',
            raw_policy=policy
        )
    
    @staticmethod
    def normalize_zscaler_policy(policy: Dict, policy_type: str = 'url_filtering') -> EnhancedNormalizedPolicy:
        """
        Normalize a Zscaler policy to enhanced format.
        
        Args:
            policy: Zscaler policy dictionary
            policy_type: Type of policy ('url_filtering', 'dlp', 'zpa')
            
        Returns:
            EnhancedNormalizedPolicy object
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
        
        return EnhancedNormalizedPolicy(
            policy_id=str(policy.get('id', policy.get('policy_id', 'unknown'))),
            policy_name=str(policy.get('policy_name', policy.get('name', 'unknown'))),
            source_users=set(groups) if groups else set(),
            dest_resource=policy.get('policy_name', 'unknown'),
            dest_type=EnhancedPolicyNormalizer.determine_dest_type(policy, 'zscaler'),
            action=policy.get('action', 'unknown').lower(),
            applies_to_all_destinations=applies_to_all,
            dlp_enabled=policy_type == 'dlp' or bool(policy.get('dlp_settings')),
            logging_enabled=bool(policy.get('audit_enabled', False)),
            priority=int(policy.get('priority', 999)),
            enabled=policy.get('enabled', True),
            source_vendor='zscaler',
            raw_policy=policy
        )

