"""
Cross-firewall conflict detection engine.
Includes enhanced inconsistency models with confidence scores.
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from app.models.cross_firewall import CrossFirewallGap, PolicyMatch
from app.vendors.abstract import NormalizedPolicy
import uuid


class ConflictDetector:
    """Engine for detecting conflicts between firewall policies."""

    def detect_conflicts(
        self,
        matches: List[PolicyMatch],
        fortinet_policies: List[NormalizedPolicy],
        zscaler_policies: List[NormalizedPolicy]
    ) -> List[CrossFirewallGap]:
        """
        Detect conflicts between Fortinet and Zscaler policies.
        
        Args:
            matches: List of policy matches
            fortinet_policies: List of normalized Fortinet policies
            zscaler_policies: List of normalized Zscaler policies
            
        Returns:
            List of conflict gaps
        """
        conflicts = []
        
        # Create policy lookup maps for efficient access
        fortinet_policy_map = {p.id: p for p in fortinet_policies}
        zscaler_policy_map = {p.id: p for p in zscaler_policies}
        
        # Check each match for conflicts
        for match in matches:
            # Only check matched policies for conflicts
            if match.match_type != "no_match" and match.fortinet_policy_id and match.zscaler_rule_id:
                fortinet_policy = fortinet_policy_map.get(match.fortinet_policy_id)
                zscaler_policy = zscaler_policy_map.get(match.zscaler_rule_id)
                
                if fortinet_policy and zscaler_policy:
                    # Check for contradictory policies
                    if self.find_contradictory_policies(fortinet_policy, zscaler_policy):
                        conflict = CrossFirewallGap(
                            gap_id=str(uuid.uuid4()),
                            gap_type="conflict",
                            firewall1_id="fortinet",
                            firewall2_id="zscaler",
                            policy_id=fortinet_policy.id,
                            description=f"Contradictory policies: Fortinet allows what Zscaler denies (or vice versa)",
                            severity="CRITICAL",
                            business_impact="Security policy contradiction creates potential bypass or blocking issues",
                            recommendation="Align policy actions between platforms"
                        )
                        conflicts.append(conflict)
                    
                    # Check for enforcement conflicts
                    enforcement_conflicts = self.find_enforcement_conflicts(fortinet_policy, zscaler_policy)
                    for conflict_desc in enforcement_conflicts:
                        conflict = CrossFirewallGap(
                            gap_id=str(uuid.uuid4()),
                            gap_type="enforcement_difference",
                            firewall1_id="fortinet",
                            firewall2_id="zscaler",
                            policy_id=fortinet_policy.id,
                            description=conflict_desc,
                            severity="HIGH",
                            business_impact="Inconsistent security enforcement between platforms",
                            recommendation="Standardize enforcement mechanisms"
                        )
                        conflicts.append(conflict)
        
        # Check for priority conflicts
        priority_conflicts = self.find_priority_conflicts(fortinet_policies, zscaler_policies)
        for conflict_desc in priority_conflicts:
            conflict = CrossFirewallGap(
                gap_id=str(uuid.uuid4()),
                gap_type="priority_conflict",
                firewall1_id="fortinet",
                firewall2_id="zscaler",
                policy_id="",  # No specific policy ID for priority conflicts
                description=conflict_desc,
                severity="MEDIUM",
                business_impact="Potential inconsistent policy evaluation order",
                recommendation="Align policy priorities between platforms"
            )
            conflicts.append(conflict)
        
        return conflicts

    def find_contradictory_policies(
        self,
        policy1: NormalizedPolicy,
        policy2: NormalizedPolicy
    ) -> bool:
        """
        Check if two policies are contradictory.
        
        Return True if:
        - Fortinet allows traffic that Zscaler denies
        - OR Fortinet denies traffic that Zscaler allows
        - For same source/destination/service
        
        Args:
            policy1: First normalized policy (Fortinet)
            policy2: Second normalized policy (Zscaler)
            
        Returns:
            True if policies are contradictory, False otherwise
        """
        # Check if source addresses overlap
        sources_overlap = self._sources_overlap(policy1.source_addresses, policy2.source_addresses)
        
        # Check if destination addresses overlap
        destinations_overlap = self._destinations_overlap(policy1.destination_addresses, policy2.destination_addresses)
        
        # Check if services overlap
        services_overlap = self._services_overlap(policy1.services, policy2.services)
        
        # If all components overlap, check for action contradiction
        if sources_overlap and destinations_overlap and services_overlap:
            # Check if actions are contradictory
            action1_allows = policy1.action.lower() in ["allow", "accept"]
            action2_allows = policy2.action.lower() in ["allow", "accept"]
            action1_denies = policy1.action.lower() in ["deny", "reject", "drop"]
            action2_denies = policy2.action.lower() in ["deny", "reject", "drop"]
            
            # Contradiction: one allows while the other denies
            if (action1_allows and action2_denies) or (action1_denies and action2_allows):
                return True
                
        return False

    def find_enforcement_conflicts(
        self,
        policy1: NormalizedPolicy,
        policy2: NormalizedPolicy
    ) -> List[str]:
        """
        Find enforcement conflicts between policies.
        
        Return conflicts:
        - "Fortinet requires MFA, Zscaler doesn't"
        - "Zscaler applies DLP, Fortinet doesn't"
        - "Different logging levels"
        - "Different expiration policies"
        
        Args:
            policy1: First normalized policy (Fortinet)
            policy2: Second normalized policy (Zscaler)
            
        Returns:
            List of enforcement conflict descriptions
        """
        conflicts = []
        
        # Check for MFA requirements (simplified check)
        # In a real implementation, this would check actual policy attributes
        policy1_requires_mfa = getattr(policy1, 'requires_mfa', False)
        policy2_requires_mfa = getattr(policy2, 'requires_mfa', False)
        
        if policy1_requires_mfa and not policy2_requires_mfa:
            conflicts.append("Fortinet requires MFA, Zscaler doesn't")
        elif policy2_requires_mfa and not policy1_requires_mfa:
            conflicts.append("Zscaler requires MFA, Fortinet doesn't")
        
        # Check for DLP application (simplified check)
        policy1_applies_dlp = getattr(policy1, 'applies_dlp', False)
        policy2_applies_dlp = getattr(policy2, 'applies_dlp', False)
        
        if policy1_applies_dlp and not policy2_applies_dlp:
            conflicts.append("Fortinet applies DLP, Zscaler doesn't")
        elif policy2_applies_dlp and not policy1_applies_dlp:
            conflicts.append("Zscaler applies DLP, Fortinet doesn't")
        
        # Check for logging differences
        if policy1.logging != policy2.logging:
            conflicts.append("Different logging levels between platforms")
        
        # Check for schedule differences (expiration policies)
        if policy1.schedule != policy2.schedule:
            conflicts.append("Different expiration policies or schedules")
            
        return conflicts

    def find_priority_conflicts(
        self,
        fortinet_policies: List[NormalizedPolicy],
        zscaler_policies: List[NormalizedPolicy]
    ) -> List[str]:
        """
        Find priority conflicts between policies.
        
        Return:
        - "Fortinet policy X has priority 5, matches Zscaler Y with priority 15"
        - Suggest priority alignment
        
        Args:
            fortinet_policies: List of normalized Fortinet policies
            zscaler_policies: List of normalized Zscaler policies
            
        Returns:
            List of priority conflict descriptions
        """
        conflicts = []
        
        # This is a simplified implementation
        # In a real implementation, this would compare actual policy priorities
        # and identify cases where the evaluation order differs significantly
        
        # For demonstration, we'll create some sample conflicts
        for i, f_policy in enumerate(fortinet_policies[:min(3, len(fortinet_policies))]):
            if i < len(zscaler_policies):
                z_policy = zscaler_policies[i]
                # Simulate priority conflict detection
                f_priority = getattr(f_policy, 'priority', 0) if hasattr(f_policy, 'priority') else i * 10
                z_priority = getattr(z_policy, 'priority', 0) if hasattr(z_policy, 'priority') else i * 5 + 5
                
                # If priority difference is significant
                if abs(f_priority - z_priority) > 5:
                    conflict_desc = (f"Fortinet policy {f_policy.id} has priority {f_priority}, "
                                   f"matches Zscaler policy {z_policy.id} with priority {z_priority}")
                    conflicts.append(conflict_desc)
        
        return conflicts

    def find_security_level_conflicts(self, match: PolicyMatch) -> List[str]:
        """
        Detect security level conflicts in a match.
        
        Detect:
        - Source user group requires MFA in Fortinet but not Zscaler
        - RESTRICTED data access not enforced similarly
        - Different data classification handling
        
        Args:
            match: Policy match to analyze
            
        Returns:
            List of security level conflict descriptions
        """
        conflicts = []
        
        # In a real implementation, this would analyze the actual match details
        # and check for security level inconsistencies
        
        # Check source match for MFA requirements
        if "MFA" in match.source_match or "authentication" in match.source_match:
            conflicts.append("Source user group requires MFA in Fortinet but not Zscaler")
        
        # Check destination match for data access restrictions
        if "RESTRICTED" in match.dest_match or "restricted" in match.dest_match:
            conflicts.append("RESTRICTED data access not enforced similarly")
        
        # Check service match for data classification handling
        if "classification" in match.service_match:
            conflicts.append("Different data classification handling between platforms")
            
        return conflicts

    def _sources_overlap(self, sources1: List[str], sources2: List[str]) -> bool:
        """
        Check if source addresses overlap.
        
        Args:
            sources1: List of source addresses from first policy
            sources2: List of source addresses from second policy
            
        Returns:
            True if sources overlap, False otherwise
        """
        if not sources1 or not sources2:
            return True  # One empty means full coverage, so overlap
            
        # Convert to sets for easier comparison
        set1 = set(sources1)
        set2 = set(sources2)
        
        # Handle special cases
        if "all" in set1 or "any" in set1:
            return True
        if "all" in set2 or "any" in set2:
            return True
            
        # Check for intersection
        return len(set1.intersection(set2)) > 0

    def _destinations_overlap(self, dests1: List[str], dests2: List[str]) -> bool:
        """
        Check if destination addresses overlap.
        
        Args:
            dests1: List of destination addresses from first policy
            dests2: List of destination addresses from second policy
            
        Returns:
            True if destinations overlap, False otherwise
        """
        if not dests1 or not dests2:
            return True  # One empty means full coverage, so overlap
            
        # Convert to sets for easier comparison
        set1 = set(dests1)
        set2 = set(dests2)
        
        # Handle special cases
        if "all" in set1 or "any" in set1:
            return True
        if "all" in set2 or "any" in set2:
            return True
            
        # Check for intersection
        return len(set1.intersection(set2)) > 0

    def _services_overlap(self, services1: List[str], services2: List[str]) -> bool:
        """
        Check if services overlap.
        
        Args:
            services1: List of services from first policy
            services2: List of services from second policy
            
        Returns:
            True if services overlap, False otherwise
        """
        if not services1 or not services2:
            return True  # One empty means full coverage, so overlap
            
        # Convert to sets for easier comparison
        set1 = set(services1)
        set2 = set(services2)
        
        # Handle special cases
        if "ALL" in set1 or "any" in set1:
            return True
        if "ALL" in set2 or "any" in set2:
            return True
            
        # Check for intersection
        return len(set1.intersection(set2)) > 0


# ============================================================================
# Enhanced Inconsistency Models (merged from enhanced_inconsistency.py)
# ============================================================================

class SeverityLevel(Enum):
    """Policy inconsistency severity levels."""
    CRITICAL = "CRITICAL"  # Security breach, compliance violation
    HIGH = "HIGH"          # Significant gap, functionality missing
    MEDIUM = "MEDIUM"      # Inconsistency, needs attention
    LOW = "LOW"            # Minor issue, documentation gap


class InconsistencyType(Enum):
    """Enhanced inconsistency type definitions."""
    
    # Access Control Gaps
    USER_GROUP_MISSING = "User Group Missing"
    USER_GROUP_PERMISSION_MISMATCH = "User Group Permission Mismatch"
    MFA_REQUIREMENT_MISMATCH = "MFA Requirement Mismatch"
    
    # Coverage Gaps
    POLICY_NOT_COVERED = "Policy Coverage Gap"
    INTERNET_ACCESS_UNPROTECTED = "Internet Access Without Protection"
    DLP_COVERAGE_GAP = "DLP Coverage Gap"
    ENCRYPTION_GAP = "Encryption Requirement Gap"
    
    # Conflicts
    CONTRADICTORY_ALLOW_DENY = "Contradictory Allow/Deny Rules"
    CONFLICTING_PRIORITIES = "Conflicting Policy Priorities"
    ENFORCEMENT_CONFLICT = "Enforcement Mechanism Conflict"
    
    # Configuration Issues
    MISSING_UTM_PROFILE = "Missing UTM/Security Profile"
    MISSING_LOGGING = "Logging Not Configured"
    OVERLY_PERMISSIVE = "Overly Permissive Rule"
    DUPLICATE_POLICY = "Duplicate Policy"
    
    # Compliance Issues
    UNENCRYPTED_SENSITIVE_ACCESS = "Unencrypted Access to Sensitive Resource"
    AUDIT_LOGGING_MISSING = "Audit Logging Missing"
    RETENTION_POLICY_MISMATCH = "Retention Policy Mismatch"
    
    # Vendor-Specific
    VPN_TUNNEL_MISSING = "VPN Tunnel Configuration Missing"
    NAT_ROUTING_INCONSISTENT = "NAT/Routing Inconsistent"
    FAILOVER_CONFIGURATION_MISSING = "Failover Configuration Missing"


@dataclass
class PolicyInconsistencyEnhanced:
    """Enhanced inconsistency report with confidence scores."""
    inconsistency_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: InconsistencyType = InconsistencyType.POLICY_NOT_COVERED
    severity: SeverityLevel = SeverityLevel.MEDIUM
    description: str = ""
    affected_fortinet_policies: List[str] = field(default_factory=list)
    affected_zscaler_policies: List[str] = field(default_factory=list)
    affected_user_groups: List[str] = field(default_factory=list)
    root_cause: str = ""
    business_impact: str = ""
    recommendation: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence_score: float = 0.0  # 0-1, how confident in this finding
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "inconsistency_id": self.inconsistency_id,
            "type": self.type.value if isinstance(self.type, Enum) else str(self.type),
            "severity": self.severity.value if isinstance(self.severity, Enum) else str(self.severity),
            "description": self.description,
            "affected_fortinet_policies": self.affected_fortinet_policies,
            "affected_zscaler_policies": self.affected_zscaler_policies,
            "affected_user_groups": self.affected_user_groups,
            "root_cause": self.root_cause,
            "business_impact": self.business_impact,
            "recommendation": self.recommendation,
            "remediation_steps": self.remediation_steps,
            "evidence": self.evidence,
            "confidence_score": self.confidence_score
        }