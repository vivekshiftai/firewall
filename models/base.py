"""
Base models for firewall policy analysis.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from datetime import datetime
from app.models.vendors import VendorType, VendorNormalizedPolicy, NormalizedZone, NormalizedUserGroup


class FirewallConfig(BaseModel):
    """Base model for firewall configuration."""
    id: str
    vendor: VendorType
    version: Optional[str] = None
    policies: List[Dict[str, Any]] = []
    objects: List[Dict[str, Any]] = []
    metadata: Optional[Dict[str, Any]] = None
    parsed_at: datetime = None


class PolicyComparisonResult(BaseModel):
    """Model for policy comparison results."""
    firewall_a_id: str
    firewall_b_id: str
    parity_matrix: Dict[str, Any]
    differences: List[Dict[str, Any]]
    recommendations: List[str]
    compliance_gaps: List[Dict[str, Any]]


class ComplianceReport(BaseModel):
    """Model for compliance reporting."""
    firewall_id: str
    compliance_status: str
    missing_policies: List[Dict[str, Any]]
    risk_assessment: Dict[str, Any]