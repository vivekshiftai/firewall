"""
Enhanced inconsistency models with confidence scores and better categorization.
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import uuid


class SeverityLevel(Enum):
    """Policy inconsistency severity levels."""
    CRITICAL = "CRITICAL"  # Security breach, compliance violation
    HIGH = "HIGH"          # Significant gap, functionality missing
    MEDIUM = "MEDIUM"      # Inconsistency, needs attention
    LOW = "LOW"            # Minor issue, documentation gap


class EnhancedInconsistencyType(Enum):
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
class EnhancedPolicyInconsistency:
    """Enhanced inconsistency report with confidence scores."""
    inconsistency_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: EnhancedInconsistencyType = EnhancedInconsistencyType.POLICY_NOT_COVERED
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

