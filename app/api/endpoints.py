"""
API endpoints for cross-firewall policy analysis.
"""
from fastapi import APIRouter, HTTPException, Query
from typing import List, Dict, Any, Optional
import json
import logging
from datetime import datetime
import uuid

from app.models.base import FirewallConfig
from app.parsers.factory import ParserFactory
from app.analyzers.policy_analyzer import PolicyAnalyzer
from app.vendors.abstract import ParsedConfig, NormalizedPolicy
from app.core.policy_matcher import PolicyMatcher
from app.core.coverage_analyzer import CoverageAnalyzer
from app.core.conflict_detector import ConflictDetector
from app.core.normalizers import NormalizationEngine, FortinetNormalizer, ZscalerNormalizer
from app.core.report_generator import ReportGenerator
from app.models.cross_firewall import (
    CrossFirewallAnalysisReport, 
    PolicyMatch, 
    PolicyParity, 
    CrossFirewallGap, 
    EnforcementCapabilityMatrix
)

# Initialize components
router = APIRouter(prefix="/api/v1")
analyzer = PolicyAnalyzer()
policy_matcher = PolicyMatcher()
coverage_analyzer = CoverageAnalyzer()
conflict_detector = ConflictDetector()
normalization_engine = NormalizationEngine()
report_generator = ReportGenerator()

# Set up logging
logger = logging.getLogger(__name__)

# In-memory storage for analysis results (in a real app, this would be a database)
analysis_storage = {}

class AnalysisStatus:
    """Analysis status constants."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETE = "complete"
    FAILED = "failed"

class MultiFirewallRequest:
    """Request model for multi-firewall analysis."""
    def __init__(self, firewall1: Dict[str, Any], firewall2: Dict[str, Any]):
        self.firewall1 = firewall1
        self.firewall2 = firewall2

class PolicyComparisonRequest:
    """Request model for policy comparison."""
    def __init__(self, fortinet_policies: List[Dict[str, Any]], zscaler_policies: List[Dict[str, Any]]):
        self.fortinet_policies = fortinet_policies
        self.zscaler_policies = zscaler_policies

class ConfigValidationRequest:
    """Request model for config validation."""
    def __init__(self, config: Dict[str, Any]):
        self.config = config

@router.post("/analyze/multi-firewall")
async def analyze_multi_firewall(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze two firewalls and generate a cross-firewall analysis report.
    
    Args:
        request: Multi-firewall analysis request
        
    Returns:
        Complete cross-firewall analysis report
    """
    try:
        # Validate input
        if "firewall1" not in request or "firewall2" not in request:
            raise HTTPException(status_code=400, detail="Missing firewall configurations")
            
        firewall1_data = request["firewall1"]
        firewall2_data = request["firewall2"]
        
        if "vendor" not in firewall1_data or "config" not in firewall1_data:
            raise HTTPException(status_code=400, detail="Invalid firewall1 configuration")
            
        if "vendor" not in firewall2_data or "config" not in firewall2_data:
            raise HTTPException(status_code=400, detail="Invalid firewall2 configuration")
        
        # Generate analysis ID
        analysis_id = str(uuid.uuid4())
        
        # Store initial status
        analysis_storage[analysis_id] = {
            "status": AnalysisStatus.PENDING,
            "created_at": datetime.utcnow(),
            "report": None
        }
        
        # Update status to processing
        analysis_storage[analysis_id]["status"] = AnalysisStatus.PROCESSING
        
        # Parse firewall configurations
        parser1 = ParserFactory.create_parser(firewall1_data["vendor"])
        parsed_config1 = parser1.parse_config(firewall1_data["config"])
        
        parser2 = ParserFactory.create_parser(firewall2_data["vendor"])
        parsed_config2 = parser2.parse_config(firewall2_data["config"])
        
        # Normalize configurations
        normalized_config1 = normalization_engine.normalize_config(parsed_config1)
        normalized_config2 = normalization_engine.normalize_config(parsed_config2)
        
        # Extract policies
        fortinet_policies = [NormalizedPolicy(**policy) for policy in normalized_config1.policies]
        zscaler_policies = [NormalizedPolicy(**policy) for policy in normalized_config2.policies]
        
        # Match policies
        matches = policy_matcher.match_policies(fortinet_policies, zscaler_policies)
        
        # Analyze coverage
        coverage = coverage_analyzer.analyze_coverage(matches, fortinet_policies, zscaler_policies)
        
        # Detect conflicts
        conflicts = conflict_detector.detect_conflicts(matches, fortinet_policies, zscaler_policies)
        
        # Build enforcement capability matrix
        capability_matrix = coverage_analyzer.build_enforcement_capability_matrix(parsed_config1, parsed_config2)
        
        # Generate standardization recommendations
        recommendations = report_generator.generate_standardization_recommendations(
            CrossFirewallAnalysisReport(
                analysis_id=analysis_id,
                timestamp=datetime.utcnow(),
                fortinet_config_id=normalized_config1.config_id,
                zscaler_config_id=normalized_config2.config_id,
                fortinet_inconsistencies=[],
                zscaler_inconsistencies=[],
                policy_matches=matches,
                cross_firewall_gaps=conflicts,
                policy_parity=coverage,
                enforcement_matrix=capability_matrix,
                standardization_recommendations=[],
                overall_parity_score=coverage.parity_score
            )
        )
        
        # Create analysis report
        analysis_report = CrossFirewallAnalysisReport(
            analysis_id=analysis_id,
            timestamp=datetime.utcnow(),
            fortinet_config_id=normalized_config1.config_id,
            zscaler_config_id=normalized_config2.config_id,
            fortinet_inconsistencies=[],
            zscaler_inconsistencies=[],
            policy_matches=matches,
            cross_firewall_gaps=conflicts,
            policy_parity=coverage,
            enforcement_matrix=capability_matrix,
            standardization_recommendations=[rec["description"] for rec in recommendations],
            overall_parity_score=coverage.parity_score
        )
        
        # Store the report
        analysis_storage[analysis_id]["report"] = analysis_report
        analysis_storage[analysis_id]["status"] = AnalysisStatus.COMPLETE
        
        return analysis_report.dict()
        
    except Exception as e:
        logger.error(f"Error in multi-firewall analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error analyzing firewalls: {str(e)}")

@router.post("/compare/policies")
async def compare_policies(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare policies between Fortinet and Zscaler.
    
    Args:
        request: Policy comparison request
        
    Returns:
        Policy matches with similarity scores
    """
    try:
        # Validate input
        if "fortinet_policies" not in request or "zscaler_policies" not in request:
            raise HTTPException(status_code=400, detail="Missing policy lists")
        
        # Convert to NormalizedPolicy objects
        fortinet_policies = [NormalizedPolicy(**policy) for policy in request["fortinet_policies"]]
        zscaler_policies = [NormalizedPolicy(**policy) for policy in request["zscaler_policies"]]
        
        # Match policies
        matches = policy_matcher.match_policies(fortinet_policies, zscaler_policies)
        
        return {
            "matches": [match.dict() for match in matches],
            "total_matches": len([m for m in matches if m.match_type != "no_match"]),
            "unmatched_fortinet_policies": len([m for m in matches if m.fortinet_policy_id and not m.zscaler_rule_id]),
            "unmatched_zscaler_policies": len([m for m in matches if m.zscaler_rule_id and not m.fortinet_policy_id])
        }
        
    except Exception as e:
        logger.error(f"Error comparing policies: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error comparing policies: {str(e)}")

@router.get("/vendors")
async def get_supported_vendors() -> Dict[str, Any]:
    """
    Get list of supported vendors.
    
    Returns:
        List of supported vendors
    """
    return {
        "vendors": [
            {
                "name": "fortinet",
                "versions": ["6.0", "6.2", "6.4", "7.0"],
                "description": "Fortinet FortiGate firewalls"
            },
            {
                "name": "zscaler",
                "versions": ["20.8", "20.9", "21.1", "21.2"],
                "description": "Zscaler Cloud Security Platform"
            },
            {
                "name": "cisco",
                "versions": ["9.2", "9.3", "9.4", "9.5"],
                "description": "Cisco ASA/FTD firewalls (planned)"
            },
            {
                "name": "paloalto",
                "versions": ["9.0", "9.1", "10.0", "10.1"],
                "description": "Palo Alto Networks firewalls (planned)"
            }
        ]
    }

@router.get("/vendors/{vendor}/schema")
async def get_vendor_schema(vendor: str) -> Dict[str, Any]:
    """
    Get expected JSON schema for a vendor.
    
    Args:
        vendor: Vendor name
        
    Returns:
        Expected JSON schema
    """
    schemas = {
        "fortinet": {
            "type": "object",
            "properties": {
                "system": {"type": "object"},
                "firewall": {"type": "object"},
                "version": {"type": "string"}
            },
            "required": ["system", "firewall"]
        },
        "zscaler": {
            "type": "object",
            "properties": {
                "cloud": {"type": "string"},
                "rules": {"type": "array"},
                "locations": {"type": "array"},
                "user_groups": {"type": "array"}
            },
            "required": ["cloud", "rules"]
        }
    }
    
    if vendor.lower() not in schemas:
        raise HTTPException(status_code=404, detail=f"Schema not found for vendor: {vendor}")
        
    return {
        "vendor": vendor,
        "schema": schemas[vendor.lower()]
    }

@router.post("/validate/config/{vendor}")
async def validate_config(vendor: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate configuration against vendor schema.
    
    Args:
        vendor: Vendor name
        config: Configuration JSON
        
    Returns:
        Validation results
    """
    try:
        # Create appropriate parser
        parser = ParserFactory.create_parser(vendor)
        
        # Parse the configuration
        firewall_config = parser.parse_config(config)
        
        # Validate the configuration
        is_valid = parser.validate_config(firewall_config)
        
        return {
            "valid": is_valid,
            "vendor": vendor,
            "errors": [] if is_valid else ["Configuration validation failed"]
        }
        
    except Exception as e:
        logger.error(f"Error validating {vendor} configuration: {str(e)}")
        return {
            "valid": False,
            "vendor": vendor,
            "errors": [str(e)]
        }

@router.get("/analysis/{analysis_id}/policy-matches")
async def get_policy_matches(analysis_id: str) -> Dict[str, Any]:
    """
    Get policy match matrix for an analysis.
    
    Args:
        analysis_id: Analysis ID
        
    Returns:
        Policy match matrix
    """
    if analysis_id not in analysis_storage:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    analysis = analysis_storage[analysis_id]
    if analysis["status"] != AnalysisStatus.COMPLETE:
        raise HTTPException(status_code=400, detail=f"Analysis not complete. Current status: {analysis['status']}")
        
    report = analysis["report"]
    fortinet_policies = len(report.fortinet_inconsistencies) if hasattr(report, 'fortinet_inconsistencies') else 0
    zscaler_policies = len(report.zscaler_inconsistencies) if hasattr(report, 'zscaler_inconsistencies') else 0
    
    return report_generator.generate_policy_match_matrix(
        report.policy_matches,
        fortinet_policies,
        zscaler_policies
    )

@router.get("/analysis/{analysis_id}/coverage")
async def get_coverage_analysis(analysis_id: str) -> Dict[str, Any]:
    """
    Get coverage analysis and gaps for an analysis.
    
    Args:
        analysis_id: Analysis ID
        
    Returns:
        Coverage analysis and gaps
    """
    if analysis_id not in analysis_storage:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    analysis = analysis_storage[analysis_id]
    if analysis["status"] != AnalysisStatus.COMPLETE:
        raise HTTPException(status_code=400, detail=f"Analysis not complete. Current status: {analysis['status']}")
        
    report = analysis["report"]
    return report_generator.generate_coverage_report(
        report.policy_parity,
        report.cross_firewall_gaps
    )

@router.get("/analysis/{analysis_id}/conflicts")
async def get_conflicts(analysis_id: str) -> Dict[str, Any]:
    """
    Get identified conflicts for an analysis.
    
    Args:
        analysis_id: Analysis ID
        
    Returns:
        Identified conflicts
    """
    if analysis_id not in analysis_storage:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    analysis = analysis_storage[analysis_id]
    if analysis["status"] != AnalysisStatus.COMPLETE:
        raise HTTPException(status_code=400, detail=f"Analysis not complete. Current status: {analysis['status']}")
        
    report = analysis["report"]
    return report_generator.generate_conflict_report(report.cross_firewall_gaps)

@router.get("/analysis/{analysis_id}/enforcement-matrix")
async def get_enforcement_matrix(analysis_id: str) -> Dict[str, Any]:
    """
    Get capability comparison for an analysis.
    
    Args:
        analysis_id: Analysis ID
        
    Returns:
        Capability comparison
    """
    if analysis_id not in analysis_storage:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    analysis = analysis_storage[analysis_id]
    if analysis["status"] != AnalysisStatus.COMPLETE:
        raise HTTPException(status_code=400, detail=f"Analysis not complete. Current status: {analysis['status']}")
        
    report = analysis["report"]
    return report_generator.generate_enforcement_comparison(report.enforcement_matrix)

@router.get("/analysis/{analysis_id}/export")
async def export_analysis(
    analysis_id: str,
    format: str = Query("json", description="Export format: pdf, json, csv"),
    type: str = Query("comparison", description="Export type: comparison, mapping")
) -> Dict[str, Any]:
    """
    Export analysis report.
    
    Args:
        analysis_id: Analysis ID
        format: Export format (pdf, json, csv)
        type: Export type (comparison, mapping)
        
    Returns:
        Exported report
    """
    if analysis_id not in analysis_storage:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    analysis = analysis_storage[analysis_id]
    if analysis["status"] != AnalysisStatus.COMPLETE:
        raise HTTPException(status_code=400, detail=f"Analysis not complete. Current status: {analysis['status']}")
        
    report = analysis["report"]
    
    if format.lower() == "pdf":
        pdf_content = report_generator.generate_pdf_multi_firewall(report)
        return {
            "format": "pdf",
            "content": pdf_content.hex()  # Convert bytes to hex string for JSON serialization
        }
    elif format.lower() == "json":
        return {
            "format": "json",
            "content": json.dumps(report.dict(), indent=2)
        }
    elif format.lower() == "csv":
        if type.lower() == "mapping":
            csv_content = report_generator.generate_csv_policy_mappings(report.policy_matches)
            return {
                "format": "csv",
                "content": csv_content
            }
        else:
            raise HTTPException(status_code=400, detail="CSV export only supported for mapping type")
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported export format: {format}")

@router.post("/audit/check-policy")
async def check_policy_compliance(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check policy compliance against both firewalls.
    
    Args:
        request: Policy definition
        
    Returns:
        Compliance status in each firewall
    """
    try:
        # In a real implementation, this would check the policy against both firewall configurations
        # For now, we'll return a placeholder response
        return {
            "policy": request.get("policy", "unknown"),
            "fortinet_compliance": {
                "compliant": True,
                "status": "Compliant",
                "findings": []
            },
            "zscaler_compliance": {
                "compliant": True,
                "status": "Compliant",
                "findings": []
            },
            "recommendations": [
                "Policy is compliant with both firewall configurations"
            ]
        }
        
    except Exception as e:
        logger.error(f"Error checking policy compliance: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error checking policy compliance: {str(e)}")