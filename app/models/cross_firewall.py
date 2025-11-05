"""
Cross-firewall analysis models.
"""
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
from app.models.vendors import VendorType, VendorNormalizedPolicy, NormalizedZone, NormalizedUserGroup
from app.vendors.abstract import PolicyInconsistency as AbstractPolicyInconsistency


class PolicyMatch(BaseModel):
    """Model representing a match between policies across firewalls."""
    fortinet_policy_id: str
    zscaler_rule_id: Optional[str]
    match_type: str  # exact, semantic, partial, no_match
    confidence_score: float  # 0-1
    source_match: str  # reason for match
    dest_match: str
    service_match: str
    action_match: str
    differences: List[str]  # what's different


class CrossFirewallGap(BaseModel):
    """Model representing a gap between firewall configurations."""
    gap_id: str
    gap_type: str  # coverage_gap, conflict, enforcement_difference
    firewall1_id: str  # has policy
    firewall2_id: str  # missing policy
    policy_id: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    business_impact: str
    recommendation: str


class PolicyParity(BaseModel):
    """Model representing policy parity between firewalls."""
    parity_id: str
    total_policies_f1: int
    total_policies_f2: int
    matched_policies: int
    coverage_percentage_f1_to_f2: float
    coverage_percentage_f2_to_f1: float
    gaps_found: int
    conflicts_found: int
    enforcement_gaps: int
    parity_score: float  # 0-100, both in sync


class EnforcementCapabilityMatrix(BaseModel):
    """Model representing enforcement capabilities across vendors."""
    capability_id: str
    fortinet_supports: bool
    zscaler_supports: bool
    capability_name: str  # mfa, dlp, ips, av, geofencing, etc.
    fortinet_method: Optional[str]
    zscaler_method: Optional[str]
    notes: str


class CrossFirewallAnalysisReport(BaseModel):
    """Comprehensive cross-firewall analysis report."""
    analysis_id: str
    timestamp: datetime
    fortinet_config_id: str
    zscaler_config_id: str
    fortinet_inconsistencies: List[AbstractPolicyInconsistency]
    zscaler_inconsistencies: List[AbstractPolicyInconsistency]
    policy_matches: List[PolicyMatch]
    cross_firewall_gaps: List[CrossFirewallGap]
    policy_parity: PolicyParity
    enforcement_matrix: List[EnforcementCapabilityMatrix]
    standardization_recommendations: List[str]
    overall_parity_score: float