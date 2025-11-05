"""
Semantic mapping utilities for cross-vendor firewall policy analysis.
"""
from typing import Dict, List, Any


class SemanticMapper:
    """Utility class for mapping concepts between different firewall vendors."""
    
    # Semantic mappings between Fortinet and Zscaler concepts
    FORTINET_TO_ZSCALER_MAPPING = {
        "address_object": "location",
        "service_object": "application_group",
        "policy": "rule",
        "interface": "location",
        "zone": "department",
        "user_group": "user_group"
    }
    
    ZSCALER_TO_FORTINET_MAPPING = {v: k for k, v in FORTINET_TO_ZSCALER_MAPPING.items()}
    
    # Action mappings
    ACTION_MAPPING = {
        "accept": "ALLOW",
        "deny": "BLOCK",
        "reject": "BLOCK",
        "ALLOW": "accept",
        "BLOCK": "deny"
    }
    
    @classmethod
    def map_concept(cls, concept: str, from_vendor: str, to_vendor: str) -> str:
        """
        Map a concept from one vendor to another.
        
        Args:
            concept: The concept to map
            from_vendor: The source vendor
            to_vendor: The target vendor
            
        Returns:
            The mapped concept
        """
        if from_vendor.lower() == "fortinet" and to_vendor.lower() == "zscaler":
            return cls.FORTINET_TO_ZSCALER_MAPPING.get(concept.lower(), concept)
        elif from_vendor.lower() == "zscaler" and to_vendor.lower() == "fortinet":
            return cls.ZSCALER_TO_FORTINET_MAPPING.get(concept.lower(), concept)
        else:
            return concept
    
    @classmethod
    def map_action(cls, action: str, from_vendor: str, to_vendor: str) -> str:
        """
        Map an action from one vendor to another.
        
        Args:
            action: The action to map
            from_vendor: The source vendor
            to_vendor: The target vendor
            
        Returns:
            The mapped action
        """
        key = f"{action.upper()}_{from_vendor.upper()}_TO_{to_vendor.upper()}"
        reverse_key = f"{action.upper()}_{to_vendor.upper()}_TO_{from_vendor.upper()}"
        
        if key in cls.ACTION_MAPPING:
            return cls.ACTION_MAPPING[key]
        elif reverse_key in cls.ACTION_MAPPING:
            return cls.ACTION_MAPPING[reverse_key]
        else:
            return action
    
    @classmethod
    def normalize_policy(cls, policy: Dict[str, Any], vendor: str) -> Dict[str, Any]:
        """
        Normalize a policy to a common format for comparison.
        
        Args:
            policy: The policy to normalize
            vendor: The vendor of the policy
            
        Returns:
            Normalized policy
        """
        normalized = policy.copy()
        
        if vendor.lower() == "fortinet":
            # Map Fortinet fields to common format
            normalized["sources"] = policy.get("srcaddr", [])
            normalized["destinations"] = policy.get("dstaddr", [])
            normalized["services"] = policy.get("service", [])
            normalized["action"] = cls.map_action(policy.get("action", "deny"), "fortinet", "common")
        elif vendor.lower() == "zscaler":
            # Map Zscaler fields to common format
            normalized["sources"] = policy.get("locations", []) + policy.get("departments", [])
            normalized["destinations"] = policy.get("applications", [])
            normalized["services"] = policy.get("applications", [])
            normalized["action"] = cls.map_action(policy.get("action", "BLOCK"), "zscaler", "common")
            
        return normalized