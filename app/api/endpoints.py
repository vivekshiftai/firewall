"""
API endpoints for cross-firewall policy analysis.
"""
from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
import uuid
from datetime import datetime

from app.vendors.abstract import NormalizedPolicy
from app.models.cross_firewall import PolicyMatch
from app.core.policy_matcher import PolicyMatcher
from app.core.semantic_policy_matcher import SemanticPolicyMatcher
from app.core.coverage_analyzer import CoverageAnalyzer
from app.core.conflict_detector import ConflictDetector
from app.core.report_generator import ReportGenerator
from app.models.cross_firewall import (
    CrossFirewallAnalysisReport, 
    PolicyParity, 
    CrossFirewallGap,
    AnalysisStatus
)

router = APIRouter(prefix="/api/v1")

# Initialize components
policy_matcher = PolicyMatcher()
semantic_policy_matcher = SemanticPolicyMatcher()
coverage_analyzer = CoverageAnalyzer()
conflict_detector = ConflictDetector()
report_generator = ReportGenerator()

# In-memory storage for analysis results (in production, use a database)
analysis_storage: Dict[str, Dict[str, Any]] = {}

@router.post("/analyze/multi-firewall")
async def analyze_multi_firewall(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform comprehensive cross-firewall analysis.
    
    Args:
        request: Multi-firewall analysis request
        
    Returns:
        Comprehensive analysis report
    """
    try:
        # Validate input
        if "fortinet_config" not in request or "zscaler_config" not in request:
            raise HTTPException(status_code=400, detail="Missing firewall configurations")
        
        # Generate analysis ID
        analysis_id = str(uuid.uuid4())
        analysis_storage[analysis_id] = {
            "status": AnalysisStatus.IN_PROGRESS,
            "started_at": datetime.utcnow()
        }
        
        # Convert to NormalizedPolicy objects
        fortinet_policies = [NormalizedPolicy(**policy) for policy in request["fortinet_config"]["policies"]]
        zscaler_policies = [NormalizedPolicy(**policy) for policy in request["zscaler_config"]["policies"]]
        
        # Match policies using both traditional and semantic approaches
        traditional_matches = policy_matcher.match_policies(fortinet_policies, zscaler_policies)
        semantic_matches = semantic_policy_matcher.match_policies(fortinet_policies, zscaler_policies)
        
        # Analyze coverage
        coverage = coverage_analyzer.analyze_cross_firewall_coverage(fortinet_policies, zscaler_policies, traditional_matches)
        
        # Detect conflicts
        conflicts = conflict_detector.find_cross_firewall_conflicts(traditional_matches, fortinet_policies, zscaler_policies)
        
        # Generate recommendations
        recommendations = coverage_analyzer.generate_standardization_recommendations(coverage, conflicts)
        
        # Create capability matrix
        capability_matrix = conflict_detector.generate_enforcement_capability_matrix(fortinet_policies, zscaler_policies)
        
        # Generate report
        analysis_report = CrossFirewallAnalysisReport(
            analysis_id=analysis_id,
            timestamp=datetime.utcnow(),
            fortinet_policy_count=len(fortinet_policies),
            zscaler_policy_count=len(zscaler_policies),
            policy_matches=semantic_matches,  # Use semantic matches for the report
            coverage_analysis=coverage,
            conflict_analysis=conflicts,
            parity_analysis=PolicyParity(
                parity_id=str(uuid.uuid4()),
                total_policies_f1=len(fortinet_policies),
                total_policies_f2=len(zscaler_policies),
                matched_policies=len([m for m in semantic_matches if m.match_type != "no_match"])
            ),
            identified_gaps=[],
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
async def compare_policies(request: Dict[str, Any], use_semantic: bool = True) -> Dict[str, Any]:
    """
    Compare policies between Fortinet and Zscaler.
    
    Args:
        request: Policy comparison request
        use_semantic: Whether to use semantic matching (True) or traditional matching (False)
        
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
        
        # Match policies using selected approach
        if use_semantic:
            matches = semantic_policy_matcher.match_policies(fortinet_policies, zscaler_policies)
        else:
            matches = policy_matcher.match_policies(fortinet_policies, zscaler_policies)
        
        return {
            "matches": [match.dict() for match in matches],
            "total_matches": len([m for m in matches if m.match_type != "no_match"]),
            "unmatched_fortinet_policies": len([m for m in matches if m.fortinet_policy_id and not m.zscaler_rule_id]),
            "unmatched_zscaler_policies": len([m for m in matches if m.zscaler_rule_id and not m.fortinet_policy_id]),
            "matching_approach": "semantic" if use_semantic else "traditional"
        }
        
    except Exception as e:
        logger.error(f"Error comparing policies: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error comparing policies: {str(e)}")

@router.post("/find-similar-policies")
async def find_similar_policies(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Find policies semantically similar to a target policy.
    
    Args:
        request: Similar policy search request
        
    Returns:
        List of similar policies with similarity scores
    """
    try:
        # Validate input
        if "target_policy" not in request or "candidate_policies" not in request:
            raise HTTPException(status_code=400, detail="Missing target or candidate policies")
        
        # Convert to NormalizedPolicy objects
        target_policy = NormalizedPolicy(**request["target_policy"])
        candidate_policies = [NormalizedPolicy(**policy) for policy in request["candidate_policies"]]
        
        # Set threshold if provided
        threshold = request.get("threshold", 0.7)
        
        # Find similar policies
        similar_policies = semantic_policy_matcher.find_semantically_similar_policies(
            target_policy, candidate_policies, threshold
        )
        
        return {
            "target_policy_id": target_policy.id,
            "similar_policies": [
                {
                    "policy": policy.dict(),
                    "similarity_score": float(score)
                }
                for policy, score in similar_policies
            ],
            "count": len(similar_policies)
        }
        
    except Exception as e:
        logger.error(f"Error finding similar policies: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error finding similar policies: {str(e)}")

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
                "description": "Cisco ASA/FTD firewalls"
            },
            {
                "name": "paloalto",
                "versions": ["9.0", "9.1", "10.0", "10.1"],
                "description": "Palo Alto Networks firewalls (planned)"
            }
        ]
    }

@router.get("/analysis/{analysis_id}")
async def get_analysis(analysis_id: str) -> Dict[str, Any]:
    """
    Get analysis results.
    
    Args:
        analysis_id: Analysis ID
        
    Returns:
        Analysis results
    """
    if analysis_id not in analysis_storage:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    return analysis_storage[analysis_id]

@router.get("/analysis/{analysis_id}/status")
async def get_analysis_status(analysis_id: str) -> Dict[str, Any]:
    """
    Get analysis status.
    
    Args:
        analysis_id: Analysis ID
        
    Returns:
        Analysis status
    """
    if analysis_id not in analysis_storage:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    return {
        "analysis_id": analysis_id,
        "status": analysis_storage[analysis_id]["status"]
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

@router.post("/validate/config/{vendor}")
async def validate_config(vendor: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate vendor configuration.
    
    Args:
        vendor: Vendor name
        config: Configuration to validate
        
    Returns:
        Validation results
    """
    try:
        # In a real implementation, this would validate against vendor-specific schemas
        # For now, we'll do basic validation
        required_fields = ["policies"]
        is_valid = all(field in config for field in required_fields)
        
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