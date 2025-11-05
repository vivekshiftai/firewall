"""
Zscaler firewall analyzer implementation.
"""
from typing import List, Dict, Any
from app.vendors.abstract import AbstractFirewallAnalyzer, PolicyInconsistency, ParsedConfig


class ZscalerAnalyzer(AbstractFirewallAnalyzer):
    """Analyzer for Zscaler cloud security platform configurations."""

    def __init__(self, config: ParsedConfig):
        """
        Initialize with Zscaler config.
        
        Args:
            config: Parsed Zscaler configuration
        """
        self.config = config
        self.locations_map = {}
        self.user_groups_map = {}
        self.applications_map = {}
        self._build_reference_maps()

    def _build_reference_maps(self) -> None:
        """Create lookup maps for locations, user groups, apps."""
        # Build locations map
        for zone in self.config.zones:
            if zone.get("type") == "location":
                self.locations_map[zone.get("name")] = zone
                
        # Build user groups map
        for obj in self.config.objects:
            if obj.get("type") == "user_group":
                self.user_groups_map[obj.get("name")] = obj
                
        # Build applications map
        for obj in self.config.objects:
            if obj.get("type") == "application_group":
                self.applications_map[obj.get("name")] = obj

    def analyze(self) -> List[PolicyInconsistency]:
        """
        Run all checks and return list of policy inconsistencies.
        
        Returns:
            List of policy inconsistencies found
        """
        inconsistencies = []
        
        # Run all checks
        inconsistencies.extend(self.check_duplicate_rule_ids())
        inconsistencies.extend(self.check_user_group_references())
        inconsistencies.extend(self.check_location_references())
        inconsistencies.extend(self.check_application_references())
        inconsistencies.extend(self.check_authentication_gaps())
        inconsistencies.extend(self.check_data_protection_gaps())
        inconsistencies.extend(self.check_location_isolation())
        inconsistencies.extend(self.check_traffic_enforcement_gaps())
        
        return inconsistencies

    def check_duplicate_rule_ids(self) -> List[PolicyInconsistency]:
        """Detect duplicate rule IDs."""
        inconsistencies = []
        rule_ids = {}
        
        for i, policy in enumerate(self.config.policies):
            rule_id = policy.get("id")
            if rule_id:
                if rule_id in rule_ids:
                    inconsistencies.append(PolicyInconsistency(
                        type="duplicate_rule_id",
                        severity="MEDIUM",
                        description=f"Duplicate rule ID '{rule_id}' found in policies {rule_ids[rule_id]} and {i}",
                        policy_ids=[str(rule_ids[rule_id]), str(i)],
                        recommendation="Remove duplicate rules or assign unique IDs"
                    ))
                else:
                    rule_ids[rule_id] = i
                    
        return inconsistencies

    def check_user_group_references(self) -> List[PolicyInconsistency]:
        """Verify user groups exist."""
        inconsistencies = []
        
        for i, policy in enumerate(self.config.policies):
            user_groups = policy.get("users", [])
            for group in user_groups:
                if group not in self.user_groups_map and group != "all":
                    inconsistencies.append(PolicyInconsistency(
                        type="invalid_user_group_reference",
                        severity="HIGH",
                        description=f"Policy {i} references non-existent user group '{group}'",
                        policy_ids=[str(i)],
                        recommendation="Verify user group exists or remove reference"
                    ))
                    
        return inconsistencies

    def check_location_references(self) -> List[PolicyInconsistency]:
        """Verify locations defined."""
        inconsistencies = []
        
        for i, policy in enumerate(self.config.policies):
            locations = policy.get("locations", [])
            for location in locations:
                if location not in self.locations_map:
                    inconsistencies.append(PolicyInconsistency(
                        type="invalid_location_reference",
                        severity="HIGH",
                        description=f"Policy {i} references non-existent location '{location}'",
                        policy_ids=[str(i)],
                        recommendation="Verify location exists or remove reference"
                    ))
                    
        return inconsistencies

    def check_application_references(self) -> List[PolicyInconsistency]:
        """Verify applications exist."""
        inconsistencies = []
        
        for i, policy in enumerate(self.config.policies):
            applications = policy.get("applications", [])
            for app in applications:
                if app not in self.applications_map and app != "any":
                    inconsistencies.append(PolicyInconsistency(
                        type="invalid_application_reference",
                        severity="MEDIUM",
                        description=f"Policy {i} references non-existent application '{app}'",
                        policy_ids=[str(i)],
                        recommendation="Verify application exists or remove reference"
                    ))
                    
        return inconsistencies

    def check_authentication_gaps(self) -> List[PolicyInconsistency]:
        """Check for missing MFA/auth enforcement."""
        inconsistencies = []
        
        # Check if MFA is enforced for high-risk applications
        for i, policy in enumerate(self.config.policies):
            applications = policy.get("applications", [])
            action = policy.get("action", "").upper()
            
            # Check for high-risk applications without authentication
            high_risk_apps = ["Facebook", "Twitter", "LinkedIn", "Dropbox", "Box"]
            for app in applications:
                if app in high_risk_apps and action == "ALLOW":
                    # Check if MFA is required
                    requires_auth = policy.get("require_auth", False)
                    if not requires_auth:
                        inconsistencies.append(PolicyInconsistency(
                            type="authentication_gap",
                            severity="HIGH",
                            description=f"High-risk application '{app}' allowed without authentication in policy {i}",
                            policy_ids=[str(i)],
                            recommendation="Enable authentication or MFA for high-risk applications"
                        ))
                        
        return inconsistencies

    def check_data_protection_gaps(self) -> List[PolicyInconsistency]:
        """Check for missing DLP/encryption."""
        inconsistencies = []
        
        # Check if DLP is enabled for sensitive applications
        for i, policy in enumerate(self.config.policies):
            applications = policy.get("applications", [])
            action = policy.get("action", "").upper()
            
            # Check for sensitive applications without DLP
            sensitive_apps = ["Gmail", "Outlook", "Dropbox", "Box", "OneDrive"]
            for app in applications:
                if app in sensitive_apps and action == "ALLOW":
                    # Check if DLP is enabled
                    dlp_enabled = policy.get("dlp_enabled", False)
                    if not dlp_enabled:
                        inconsistencies.append(PolicyInconsistency(
                            type="data_protection_gap",
                            severity="MEDIUM",
                            description=f"Sensitive application '{app}' allowed without DLP in policy {i}",
                            policy_ids=[str(i)],
                            recommendation="Enable DLP for sensitive applications"
                        ))
                        
        return inconsistencies

    def check_location_isolation(self) -> List[PolicyInconsistency]:
        """Check geographic or organizational isolation."""
        inconsistencies = []
        
        # Check if locations are properly isolated
        for i, policy in enumerate(self.config.policies):
            locations = policy.get("locations", [])
            departments = policy.get("departments", [])
            
            # Check for overly broad location access
            if "all" in locations and len(locations) == 1:
                inconsistencies.append(PolicyInconsistency(
                    type="location_isolation_gap",
                    severity="MEDIUM",
                    description=f"Policy {i} applies to all locations without proper isolation",
                    policy_ids=[str(i)],
                    recommendation="Restrict policy to specific locations for better isolation"
                ))
                
            # Check for overly broad department access
            if "all" in departments and len(departments) == 1:
                inconsistencies.append(PolicyInconsistency(
                    type="department_isolation_gap",
                    severity="MEDIUM",
                    description=f"Policy {i} applies to all departments without proper isolation",
                    policy_ids=[str(i)],
                    recommendation="Restrict policy to specific departments for better isolation"
                ))
                
        return inconsistencies

    def check_traffic_enforcement_gaps(self) -> List[PolicyInconsistency]:
        """Check for missing logging or monitoring."""
        inconsistencies = []
        
        # Check if logging is enabled
        for i, policy in enumerate(self.config.policies):
            logging_enabled = policy.get("logtraffic", "disable") != "disable"
            if not logging_enabled:
                inconsistencies.append(PolicyInconsistency(
                    type="traffic_enforcement_gap",
                    severity="LOW",
                    description=f"Policy {i} does not have logging enabled",
                    policy_ids=[str(i)],
                    recommendation="Enable logging for better visibility and monitoring"
                ))
                
        return inconsistencies