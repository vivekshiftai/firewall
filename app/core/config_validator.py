"""
Configuration validator for firewall policy data.
Validates structure before processing to ensure data quality.
"""
import logging
from typing import Dict, List, Tuple, Any

logger = logging.getLogger(__name__)


class ConfigValidator:
    """Validates firewall configuration structure."""
    
    @staticmethod
    def validate_fortinet(config: Dict) -> Tuple[bool, List[str]]:
        """
        Validate Fortinet config structure.
        
        Args:
            config: Fortinet configuration dictionary
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check required top-level keys (handle both 'policies' and 'firewall_policies')
        if 'policies' not in config and 'firewall_policies' not in config:
            errors.append("Missing 'policies' or 'firewall_policies' key")
        
        # Validate policies structure
        policies = config.get('policies', config.get('firewall_policies', []))
        if not isinstance(policies, list):
            errors.append(f"'firewall_policies' should be list, got {type(policies)}")
            return False, errors
        
        for i, policy in enumerate(policies):
            if not isinstance(policy, dict):
                errors.append(f"Policy {i} is not a dict: {type(policy)}")
                continue
            
            # Check required policy fields (handle both policyid and policy_id)
            # Check all possible field names - policyid (no underscore) is the correct Fortinet format
            has_policy_id = 'policyid' in policy or 'policy_id' in policy or 'id' in policy
            has_name = 'name' in policy
            has_action = 'action' in policy
            
            if not has_policy_id:
                # Log available keys for debugging
                available_keys = list(policy.keys())[:10]  # First 10 keys for debugging
                logger.debug(f"Policy {i} available keys: {available_keys}")
                errors.append(f"Policy {i} missing 'policyid' or 'policy_id' or 'id' (available keys: {available_keys})")
            if not has_name:
                errors.append(f"Policy {i} missing 'name'")
            if not has_action:
                errors.append(f"Policy {i} missing 'action'")
            
            # Validate field types
            if 'action' in policy and not isinstance(policy['action'], str):
                errors.append(f"Policy {i} 'action' should be string")
            
            if 'source_addresses' in policy and not isinstance(policy.get('source_addresses'), (list, type(None))):
                errors.append(f"Policy {i} 'source_addresses' should be list or None")
            
            if 'destination_addresses' in policy and not isinstance(policy.get('destination_addresses'), (list, type(None))):
                errors.append(f"Policy {i} 'destination_addresses' should be list or None")
        
        is_valid = len(errors) == 0
        if not is_valid:
            logger.warning(f"Fortinet config validation found {len(errors)} errors")
        else:
            logger.debug("Fortinet config validation passed")
        
        return is_valid, errors
    
    @staticmethod
    def validate_zscaler(config: Dict) -> Tuple[bool, List[str]]:
        """
        Validate Zscaler config structure.
        
        Args:
            config: Zscaler configuration dictionary
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check for at least one policy source
        has_policies = any(key in config for key in [
            'zia_url_filtering_policies',
            'zia_dlp_policies',
            'zpa_access_policies'
        ])
        
        if not has_policies:
            errors.append("No policy sections found (ZIA URL, DLP, ZPA)")
        
        # Validate policy structure
        for policy_type in ['zia_url_filtering_policies', 'zia_dlp_policies', 'zpa_access_policies']:
            policies = config.get(policy_type, [])
            if policies and not isinstance(policies, list):
                errors.append(f"'{policy_type}' should be list, got {type(policies)}")
            elif isinstance(policies, list):
                for i, policy in enumerate(policies):
                    if not isinstance(policy, dict):
                        errors.append(f"{policy_type}[{i}] is not a dict: {type(policy)}")
        
        is_valid = len(errors) == 0
        if not is_valid:
            logger.warning(f"Zscaler config validation found {len(errors)} errors")
        else:
            logger.debug("Zscaler config validation passed")
        
        return is_valid, errors
    
    @staticmethod
    def validate_data_quality(config: Dict, vendor: str) -> Tuple[bool, List[str]]:
        """
        Validate data quality and completeness.
        
        Args:
            config: Configuration dictionary
            vendor: Vendor name ('fortinet' or 'zscaler')
            
        Returns:
            Tuple of (is_acceptable, list_of_warnings)
        """
        warnings = []
        
        if vendor == 'fortinet':
            policies = config.get('firewall_policies', [])
            
            # Check for policies with missing critical fields
            for i, policy in enumerate(policies):
                if not policy.get('source_addresses') and not policy.get('source_zones'):
                    warnings.append(f"Policy {i} has no source addresses or zones")
                
                if not policy.get('destination_addresses') and not policy.get('destination_zones'):
                    warnings.append(f"Policy {i} has no destination addresses or zones")
                
                if not policy.get('services') and not policy.get('service'):
                    warnings.append(f"Policy {i} has no services defined")
        
        elif vendor == 'zscaler':
            # Check URL filtering policies
            url_policies = config.get('zia_url_filtering_policies', [])
            for i, policy in enumerate(url_policies):
                if not policy.get('apply_to_groups'):
                    warnings.append(f"URL filtering policy {i} has no groups")
            
            # Check DLP policies
            dlp_policies = config.get('zia_dlp_policies', [])
            for i, policy in enumerate(dlp_policies):
                if not policy.get('apply_to_groups'):
                    warnings.append(f"DLP policy {i} has no groups")
        
        is_acceptable = len(warnings) < len(policies) * 0.5  # Allow up to 50% missing data
        if warnings:
            logger.warning(f"Data quality check found {len(warnings)} warnings")
        
        return is_acceptable, warnings

