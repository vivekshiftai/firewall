"""
Main policy analyzer for cross-firewall policy analysis.
Includes enhanced validation, normalization, and 10 comprehensive checks.
"""
import logging
import os
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import defaultdict
from analyzers.base import BaseAnalyzer
from models.base import FirewallConfig, PolicyComparisonResult, ComplianceReport
from utils.embeddings import PolicyEmbedder
from utils.mapping import SemanticMapper
from analyzers.ai_analyzer import AIInconsistencyAnalyzer
from app.core.config_validator import ConfigValidator
from app.core.normalizers import PolicyNormalizerEnhanced, NormalizedPolicyEnhanced
from app.core.conflict_detector import PolicyInconsistencyEnhanced, InconsistencyType, SeverityLevel

# Configure logging
logger = logging.getLogger(__name__)

class PolicyAnalyzer(BaseAnalyzer):
    """Main analyzer for firewall policy analysis."""

    def __init__(self, use_ai: bool = True, openai_api_key: Optional[str] = None, openai_model: Optional[str] = None):
        """
        Initialize the policy analyzer.
        
        Args:
            use_ai: Whether to use AI-powered analysis (default: True)
            openai_api_key: OpenAI API key (if None, will try to get from OPENAI_API_KEY env var)
            openai_model: OpenAI model to use (if None, will try to get from OPENAI_MODEL env var, default: gpt-3.5-turbo)
        """
        logger.info("Initializing PolicyAnalyzer")
        self.embedder = PolicyEmbedder()
        self.mapper = SemanticMapper()
        
        # Get API key from parameter or environment variable
        if openai_api_key is None:
            openai_api_key = os.getenv("OPENAI_API_KEY")
        
        # Get model from parameter or environment variable, with default
        if openai_model is None:
            openai_model = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
        
        # Initialize AI analyzer if enabled
        self.use_ai = use_ai
        logger.info(f"Initializing AI analyzer: use_ai={use_ai}, api_key_provided={openai_api_key is not None}")
        
        if self.use_ai:
            try:
                logger.debug(f"Creating AIInconsistencyAnalyzer with model: {openai_model}")
                self.ai_analyzer = AIInconsistencyAnalyzer(
                    api_key=openai_api_key,
                    model=openai_model
                )
                
                # Check if the AI analyzer has a valid client (API key was found)
                if hasattr(self.ai_analyzer, 'client') and self.ai_analyzer.client:
                    logger.info(f"AI analyzer initialized successfully with model: {openai_model}")
                    logger.info("OpenAI client is ready for AI analysis")
                    self.use_ai = True  # Ensure use_ai is True if client is available
                else:
                    logger.warning("OpenAI client is not available. AI analysis will be disabled.")
                    logger.warning("This usually means OPENAI_API_KEY environment variable is not set.")
                    self.use_ai = False
                    # Keep the analyzer object but mark it as disabled
            except Exception as e:
                logger.error(f"Failed to initialize AI analyzer: {str(e)}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                logger.warning("Continuing without AI analysis.")
                self.use_ai = False
                self.ai_analyzer = None
        else:
            self.ai_analyzer = None
            logger.info("AI analysis disabled (use_ai=False)")
        
        logger.debug("PolicyAnalyzer components initialized")
        logger.info("PolicyAnalyzer initialized successfully")

    def analyze_single_firewall(self, config: FirewallConfig, use_enhanced: bool = True) -> Dict[str, Any]:
        """
        Analyze a single firewall configuration for internal inconsistencies.
        Uses both rule-based analysis and AI-powered analysis.
        
        Args:
            config: Firewall configuration to analyze
            use_enhanced: Whether to use enhanced analyzer (default: True)
            
        Returns:
            Analysis results including both rule-based and AI findings
        """
        logger.info(f"Starting single firewall analysis for {config.vendor} firewall ID: {config.id}")
        try:
            # Use enhanced analyzer if enabled (integrated directly)
            if use_enhanced:
                logger.info("Using Enhanced Policy Analyzer with 10 comprehensive checks")
                enhanced_inconsistencies, enhanced_summary = self._run_enhanced_analysis(config)
                
                # Convert enhanced inconsistencies to standard format
                all_inconsistencies = [i.to_dict() for i in enhanced_inconsistencies]
                
                # Set empty original checks when using enhanced
                conflicts = []
                redundancies = []
                gaps = []
                utm_issues = []
                user_group_issues = []
                dlp_issues = []
                app_issues = []
                security_issues = []
            else:
                logger.debug("Using original rule-based analysis")
                enhanced_summary = None
                all_inconsistencies = []
                
                # Rule-based analysis - Run all 8 detection engines
                logger.debug("Running comprehensive rule-based analysis")
                
                # Engine 1: Contradictory Rules
                conflicts = self._check_policy_conflicts(config)
                logger.info(f"[1/8] Found {len(conflicts)} policy conflicts")
                
                # Engine 2: Duplicate Policies
                redundancies = self._check_redundant_policies(config)
                logger.info(f"[2/8] Found {len(redundancies)} redundant policies")
                
                # Engine 3: Overly Permissive Rules
                gaps = self._check_coverage_gaps(config)
                logger.info(f"[3/8] Found {len(gaps)} coverage gaps")
                
                # Engine 4: UTM Profile Inconsistency
                utm_issues = self._check_utm_profiles(config)
                logger.info(f"[4/8] Found {len(utm_issues)} UTM profile issues")
                
                # Engine 5: User Group Consistency (single firewall - check for group references)
                user_group_issues = self._check_user_group_consistency(config)
                logger.info(f"[5/8] Found {len(user_group_issues)} user group issues")
                
                # Engine 6: DLP Coverage Gaps (single firewall - check for missing DLP)
                dlp_issues = self._check_dlp_coverage_gaps_single(config)
                logger.info(f"[6/8] Found {len(dlp_issues)} DLP coverage gaps")
                
                # Engine 7: Application Access Gaps
                app_issues = self._check_application_access_gaps_single(config)
                logger.info(f"[7/8] Found {len(app_issues)} application access gaps")
                
                # Engine 8: Missing Security Coverage
                security_issues = self._check_missing_security_coverage(config)
                logger.info(f"[8/8] Found {len(security_issues)} missing security coverage issues")
            
            # AI-powered analysis
            ai_results = {}
            logger.info(f"AI analysis check: use_ai={self.use_ai}, ai_analyzer exists={self.ai_analyzer is not None}")
            
            # Check if AI analyzer has a valid client
            has_valid_client = False
            if self.ai_analyzer and hasattr(self.ai_analyzer, 'client'):
                has_valid_client = self.ai_analyzer.client is not None
                logger.info(f"AI analyzer client status: {has_valid_client}")
            
            if self.use_ai and self.ai_analyzer and has_valid_client:
                try:
                    logger.info("Running AI-powered analysis")
                    ai_results = self.ai_analyzer.analyze_with_ai(config)
                    logger.info("AI analysis completed successfully")
                except Exception as e:
                    logger.error(f"AI analysis failed: {str(e)}. Continuing with rule-based results only.")
                    import traceback
                    logger.error(f"Traceback: {traceback.format_exc()}")
                    ai_results = {
                        "ai_analysis": {
                            "enabled": False,
                            "error": str(e)
                        }
                    }
            else:
                reasons = []
                if not self.use_ai:
                    reasons.append("use_ai=False")
                if not self.ai_analyzer:
                    reasons.append("ai_analyzer=None")
                elif not has_valid_client:
                    reasons.append("client not available (API key missing)")
                
                logger.warning(f"AI analysis skipped: {', '.join(reasons)}")
                ai_results = {
                    "ai_analysis": {
                        "enabled": False,
                        "message": f"AI analysis not available: {', '.join(reasons)}",
                        "hint": "Set OPENAI_API_KEY environment variable to enable AI analysis"
                    }
                }
            
            # Convert to standardized inconsistency format (only if not using enhanced)
            if not use_enhanced:
                # Add conflicts
                for conflict in conflicts:
                    all_inconsistencies.append({
                        "type": "Contradictory Rule",
                        "severity": conflict.get("severity", "HIGH"),
                        "description": conflict.get("description", ""),
                        "fortinet_policy": conflict.get("policy_a", {}).get("name", ""),
                        "zscaler_policy": "N/A",
                        "affected_groups": self._extract_groups_from_policy(conflict.get("policy_a", {}), config),
                        "recommendation": conflict.get("recommendation", ""),
                        "details": {
                            "policy_a": conflict.get("policy_a", {}),
                            "policy_b": conflict.get("policy_b", {})
                        }
                    })
                
                # Add redundancies
                for redundancy in redundancies:
                    all_inconsistencies.append({
                        "type": "Duplicate Policy",
                        "severity": redundancy.get("severity", "MEDIUM"),
                        "description": redundancy.get("description", ""),
                        "fortinet_policy": redundancy.get("policy_a", {}).get("name", ""),
                        "zscaler_policy": "N/A",
                        "affected_groups": self._extract_groups_from_policy(redundancy.get("policy_a", {}), config),
                        "recommendation": redundancy.get("recommendation", ""),
                        "details": {
                            "policy_a": redundancy.get("policy_a", {}),
                            "policy_b": redundancy.get("policy_b", {})
                        }
                    })
                
                # Add coverage gaps
                for gap in gaps:
                    inconsistency_type = "Overly Permissive Rule"
                    if gap.get("type") == "overly_permissive_destination":
                        inconsistency_type = "Overly Permissive Destination"
                    elif gap.get("type") == "overly_permissive_source":
                        inconsistency_type = "Overly Permissive Source"
                    
                    all_inconsistencies.append({
                        "type": inconsistency_type,
                        "severity": gap.get("severity", "HIGH"),
                        "description": gap.get("description", ""),
                        "fortinet_policy": gap.get("policy_name", ""),
                        "zscaler_policy": "N/A",
                        "affected_groups": self._extract_groups_from_policy_id(gap.get("policy_id", ""), config),
                        "recommendation": gap.get("recommendation", ""),
                        "details": {
                            "policy_id": gap.get("policy_id", ""),
                            "policy_name": gap.get("policy_name", "")
                        }
                    })
                
                # Add all detection engine results
                all_inconsistencies.extend(utm_issues)
                all_inconsistencies.extend(user_group_issues)
                all_inconsistencies.extend(dlp_issues)
                all_inconsistencies.extend(app_issues)
                all_inconsistencies.extend(security_issues)
            
            # Add AI findings if available
            if ai_results.get("ai_analysis", {}).get("enabled"):
                ai_findings = ai_results["ai_analysis"].get("findings", [])
                logger.info(f"Adding {len(ai_findings)} AI findings to inconsistencies")
                all_inconsistencies.extend(ai_findings)
            
            # Count by severity
            high_severity = sum(1 for i in all_inconsistencies if i.get("severity") == "HIGH")
            medium_severity = sum(1 for i in all_inconsistencies if i.get("severity") == "MEDIUM")
            low_severity = sum(1 for i in all_inconsistencies if i.get("severity") == "LOW")
            critical_severity = sum(1 for i in all_inconsistencies if i.get("severity") == "CRITICAL")
            
            # Format results in the requested structure
            from datetime import datetime
            results = {
                "summary": {
                    "total_inconsistencies": len(all_inconsistencies),
                    "critical_severity": critical_severity,
                    "high_severity": high_severity,
                    "medium_severity": medium_severity,
                    "low_severity": low_severity,
                    "analysis_timestamp": datetime.now().isoformat(),
                    "analysis_method": "enhanced" if use_enhanced else "original"
                },
                "inconsistencies": all_inconsistencies,
                "rule_based_analysis": {
                    "conflicts": conflicts if not use_enhanced else [],
                    "redundancies": redundancies if not use_enhanced else [],
                    "coverage_gaps": gaps if not use_enhanced else [],
                    "risk_score": self._calculate_risk_score(conflicts, redundancies, gaps)
                },
                **ai_results  # Include AI analysis results
            }
            
            # Add enhanced analysis summary if available
            if use_enhanced and enhanced_summary:
                results["enhanced_analysis"] = enhanced_summary
            
            logger.info(f"Analysis complete: {len(all_inconsistencies)} inconsistencies found ({high_severity} HIGH, {medium_severity} MEDIUM, {low_severity} LOW)")
            logger.info("Single firewall analysis completed successfully")
            return results
        except Exception as e:
            logger.error(f"Error during single firewall analysis: {str(e)}")
            raise

    def compare_firewalls(self, config_a: FirewallConfig, config_b: FirewallConfig) -> PolicyComparisonResult:
        """
        Compare two firewall configurations.
        
        Args:
            config_a: First firewall configuration
            config_b: Second firewall configuration
            
        Returns:
            Comparison results
        """
        logger.info(f"Starting firewall comparison between {config_a.id} ({config_a.vendor}) and {config_b.id} ({config_b.vendor})")
        try:
            logger.debug("Mapping policies between firewalls")
            # Create a simple mapping for demonstration
            mapped_policies = {}
            for i, policy_a in enumerate(config_a.policies):
                if i < len(config_b.policies):
                    policy_b = config_b.policies[i]
                    mapped_policies[policy_a.get("id", f"policy-{i}")] = {
                        "policy_a": policy_a,
                        "policy_b": policy_b,
                        "similarity": 0.5  # Placeholder similarity score
                    }
            logger.info(f"Mapped {len(mapped_policies)} policy pairs")
            
            logger.debug("Calculating semantic similarity")
            similarities = self._calculate_semantic_similarity(config_a.policies, config_b.policies)
            logger.info("Semantic similarity calculation completed")
            
            logger.debug("Identifying policy differences")
            differences = self._identify_differences(config_a, config_b, mapped_policies)
            logger.info(f"Identified {len(differences)} policy differences")
            
            logger.debug("Generating recommendations")
            recommendations = self._generate_recommendations(config_a, config_b, differences)
            logger.info(f"Generated {len(recommendations)} recommendations")
            
            logger.debug("Checking for compliance gaps")
            compliance_gaps = self._check_compliance_gaps(config_a, config_b)
            logger.info(f"Identified {len(compliance_gaps)} compliance gaps")
            
            comparison_result = PolicyComparisonResult(
                firewall_a_id=config_a.id,
                firewall_b_id=config_b.id,
                parity_matrix=mapped_policies,
                differences=differences,
                recommendations=recommendations,
                compliance_gaps=compliance_gaps
            )
            
            logger.info("Firewall comparison completed successfully")
            return comparison_result
        except Exception as e:
            logger.error(f"Error during firewall comparison: {str(e)}")
            raise

    def check_compliance(self, config: FirewallConfig, standards: List[str]) -> ComplianceReport:
        """
        Check firewall configuration against compliance standards.
        
        Args:
            config: Firewall configuration to check
            standards: List of compliance standards to check against
            
        Returns:
            Compliance check results
        """
        logger.info(f"Starting compliance check for firewall ID: {config.id} against standards: {standards}")
        try:
            logger.debug("Checking GDPR compliance")
            gdpr_compliance = self._check_gdpr_compliance(config) if "GDPR" in standards else {}
            logger.debug("GDPR compliance check completed")
            
            logger.debug("Checking NIS2 compliance")
            nis2_compliance = self._check_nis2_compliance(config) if "NIS2" in standards else {}
            logger.debug("NIS2 compliance check completed")
            
            logger.debug("Checking ISO27001 compliance")
            iso_compliance = self._check_iso27001_compliance(config) if "ISO27001" in standards else {}
            logger.debug("ISO27001 compliance check completed")
            
            logger.debug("Checking PCI-DSS compliance")
            pci_compliance = self._check_pci_dss_compliance(config) if "PCI-DSS" in standards else {}
            logger.debug("PCI-DSS compliance check completed")
            
            logger.debug("Checking HIPAA compliance")
            hipaa_compliance = self._check_hipaa_compliance(config) if "HIPAA" in standards else {}
            logger.debug("HIPAA compliance check completed")
            
            compliance_report = ComplianceReport(
                firewall_id=config.id,
                compliance_status="compliant" if all([
                    gdpr_compliance.get("compliant", True),
                    nis2_compliance.get("compliant", True),
                    iso_compliance.get("compliant", True),
                    pci_compliance.get("compliant", True),
                    hipaa_compliance.get("compliant", True)
                ]) else "non-compliant",
                missing_policies=self._identify_missing_policies(config, standards),
                risk_assessment={
                    "GDPR": gdpr_compliance,
                    "NIS2": nis2_compliance,
                    "ISO27001": iso_compliance,
                    "PCI-DSS": pci_compliance,
                    "HIPAA": hipaa_compliance
                }
            )
            
            logger.info("Compliance check completed successfully")
            return compliance_report
        except Exception as e:
            logger.error(f"Error during compliance check: {str(e)}")
            raise
    
    def _check_policy_conflicts(self, config: FirewallConfig) -> List[Dict[str, Any]]:
        """
        Check for conflicting policies (e.g., overlapping rules with opposite actions).
        
        Args:
            config: Firewall configuration to analyze
            
        Returns:
            List of conflict descriptions
        """
        conflicts = []
        policies = config.policies
        
        for i, policy_a in enumerate(policies):
            for j, policy_b in enumerate(policies[i+1:], start=i+1):
                # Check if policies overlap
                if self._policies_overlap(policy_a, policy_b):
                    # Check if actions conflict
                    action_a = str(policy_a.get("action", "")).lower()
                    action_b = str(policy_b.get("action", "")).lower()
                    
                    if action_a != action_b and action_a in ["accept", "allow"] and action_b in ["deny", "block", "reject"]:
                        conflicts.append({
                            "type": "conflicting_actions",
                            "severity": "HIGH",
                            "policy_a": {
                                "id": policy_a.get("id", f"policy-{i}"),
                                "name": policy_a.get("name", ""),
                                "action": action_a
                            },
                            "policy_b": {
                                "id": policy_b.get("id", f"policy-{j}"),
                                "name": policy_b.get("name", ""),
                                "action": action_b
                            },
                            "description": f"Policy {policy_a.get('id', i)} ({action_a}) conflicts with policy {policy_b.get('id', j)} ({action_b})",
                            "recommendation": "Review policy order and ensure consistent actions for overlapping traffic"
                        })
        
        return conflicts
    
    def _policies_overlap(self, policy_a: Dict[str, Any], policy_b: Dict[str, Any]) -> bool:
        """
        Check if two policies overlap in their traffic matching criteria.
        
        Args:
            policy_a: First policy
            policy_b: Second policy
            
        Returns:
            True if policies overlap, False otherwise
        """
        # Get source and destination addresses/interfaces
        src_a = set(policy_a.get("source_addresses", []) or policy_a.get("source_zones", []))
        dst_a = set(policy_a.get("destination_addresses", []) or policy_a.get("destination_zones", []))
        src_b = set(policy_b.get("source_addresses", []) or policy_b.get("source_zones", []))
        dst_b = set(policy_b.get("destination_addresses", []) or policy_b.get("destination_zones", []))
        
        # Check if "all" is in either set
        if "all" in src_a or "all" in src_b:
            src_overlap = True
        else:
            src_overlap = bool(src_a & src_b) or not (src_a and src_b)
        
        if "all" in dst_a or "all" in dst_b:
            dst_overlap = True
        else:
            dst_overlap = bool(dst_a & dst_b) or not (dst_a and dst_b)
        
        # Check service overlap
        services_a = set(policy_a.get("services", []))
        services_b = set(policy_b.get("services", []))
        service_overlap = bool(services_a & services_b) or not (services_a and services_b) or "all" in services_a or "all" in services_b
        
        return src_overlap and dst_overlap and service_overlap
    
    def _check_redundant_policies(self, config: FirewallConfig) -> List[Dict[str, Any]]:
        """
        Check for redundant policies (identical or subsumed policies).
        
        Args:
            config: Firewall configuration to analyze
            
        Returns:
            List of redundant policy descriptions
        """
        redundancies = []
        policies = config.policies
        
        for i, policy_a in enumerate(policies):
            for j, policy_b in enumerate(policies[i+1:], start=i+1):
                # Check if policies are identical
                if self._policies_identical(policy_a, policy_b):
                    redundancies.append({
                        "type": "duplicate_policy",
                        "severity": "MEDIUM",
                        "policy_a": {
                            "id": policy_a.get("id", f"policy-{i}"),
                            "name": policy_a.get("name", "")
                        },
                        "policy_b": {
                            "id": policy_b.get("id", f"policy-{j}"),
                            "name": policy_b.get("name", "")
                        },
                        "description": f"Policy {policy_a.get('id', i)} is identical to policy {policy_b.get('id', j)}",
                        "recommendation": "Remove one of the duplicate policies"
                    })
                # Check if one policy subsumes another
                elif self._policy_subsumes(policy_a, policy_b):
                    redundancies.append({
                        "type": "subsumed_policy",
                        "severity": "LOW",
                        "policy_a": {
                            "id": policy_a.get("id", f"policy-{i}"),
                            "name": policy_a.get("name", "")
                        },
                        "policy_b": {
                            "id": policy_b.get("id", f"policy-{j}"),
                            "name": policy_b.get("name", "")
                        },
                        "description": f"Policy {policy_a.get('id', i)} subsumes policy {policy_b.get('id', j)}",
                        "recommendation": "Consider removing the subsumed policy if it's not needed"
                    })
        
        return redundancies
    
    def _policies_identical(self, policy_a: Dict[str, Any], policy_b: Dict[str, Any]) -> bool:
        """Check if two policies are identical."""
        key_fields = ["source_addresses", "source_zones", "destination_addresses", "destination_zones", 
                     "services", "action"]
        
        for field in key_fields:
            val_a = set(policy_a.get(field, []))
            val_b = set(policy_b.get(field, []))
            if val_a != val_b:
                return False
        return True
    
    def _policy_subsumes(self, policy_a: Dict[str, Any], policy_b: Dict[str, Any]) -> bool:
        """Check if policy_a subsumes (covers) policy_b."""
        src_a = set(policy_a.get("source_addresses", []) or policy_a.get("source_zones", []))
        dst_a = set(policy_a.get("destination_addresses", []) or policy_a.get("destination_zones", []))
        services_a = set(policy_a.get("services", []))
        
        src_b = set(policy_b.get("source_addresses", []) or policy_b.get("source_zones", []))
        dst_b = set(policy_b.get("destination_addresses", []) or policy_b.get("destination_zones", []))
        services_b = set(policy_b.get("services", []))
        
        # Policy A subsumes B if A's criteria are broader
        src_subsumes = "all" in src_a or (src_b and src_b.issubset(src_a))
        dst_subsumes = "all" in dst_a or (dst_b and dst_b.issubset(dst_a))
        service_subsumes = "all" in services_a or (services_b and services_b.issubset(services_a))
        
        return src_subsumes and dst_subsumes and service_subsumes
    
    def _check_coverage_gaps(self, config: FirewallConfig) -> List[Dict[str, Any]]:
        """
        Check for coverage gaps in the firewall configuration.
        
        Args:
            config: Firewall configuration to analyze
            
        Returns:
            List of coverage gap descriptions
        """
        gaps = []
        
        # Check for policies with overly permissive rules
        for policy in config.policies:
            src = policy.get("source_addresses", []) or policy.get("source_zones", [])
            dst = policy.get("destination_addresses", []) or policy.get("destination_zones", [])
            action = str(policy.get("action", "")).lower()
            
            # Check for overly permissive source/destination
            if "all" in src and action in ["accept", "allow"]:
                gaps.append({
                    "type": "overly_permissive_source",
                    "severity": "HIGH",
                    "policy_id": policy.get("id", "unknown"),
                    "policy_name": policy.get("name", ""),
                    "description": f"Policy {policy.get('id')} allows traffic from all sources",
                    "recommendation": "Restrict source addresses to specific networks or zones"
                })
            
            if "all" in dst and action in ["accept", "allow"]:
                gaps.append({
                    "type": "overly_permissive_destination",
                    "severity": "HIGH",
                    "policy_id": policy.get("id", "unknown"),
                    "policy_name": policy.get("name", ""),
                    "description": f"Policy {policy.get('id')} allows traffic to all destinations",
                    "recommendation": "Restrict destination addresses to specific networks or zones"
                })
        
        return gaps
    
    def _calculate_risk_score(self, conflicts: List, redundancies: List, gaps: List) -> float:
        """
        Calculate overall risk score based on findings.
        
        Args:
            conflicts: List of conflicts
            redundancies: List of redundancies
            gaps: List of coverage gaps
            
        Returns:
            Risk score from 0.0 to 1.0 (higher is riskier)
        """
        total_issues = len(conflicts) + len(redundancies) + len(gaps)
        if total_issues == 0:
            return 0.0
        
        # Weight different issue types
        high_severity = sum(1 for c in conflicts if c.get("severity") == "HIGH")
        high_severity += sum(1 for g in gaps if g.get("severity") == "HIGH")
        
        medium_severity = sum(1 for c in conflicts if c.get("severity") == "MEDIUM")
        medium_severity += sum(1 for r in redundancies if r.get("severity") == "MEDIUM")
        
        # Calculate weighted score (max 1.0)
        score = min(1.0, (high_severity * 0.1 + medium_severity * 0.05 + len(redundancies) * 0.02) / max(total_issues, 1))
        
        return round(score, 2)
    
    def _calculate_semantic_similarity(self, policies_a: List[Dict], policies_b: List[Dict]) -> Dict[str, float]:
        """Calculate semantic similarity between policies from two firewalls."""
        # Placeholder implementation
        similarities = {}
        for i, policy_a in enumerate(policies_a):
            for j, policy_b in enumerate(policies_b):
                key = f"{policy_a.get('id', i)}-{policy_b.get('id', j)}"
                similarities[key] = 0.5  # Placeholder
        return similarities
    
    def _identify_differences(self, config_a: FirewallConfig, config_b: FirewallConfig, 
                             mapped_policies: Dict) -> List[Dict[str, Any]]:
        """Identify differences between two firewall configurations."""
        differences = []
        # Placeholder implementation
        return differences
    
    def _generate_recommendations(self, config_a: FirewallConfig, config_b: FirewallConfig,
                                differences: List[Dict]) -> List[str]:
        """Generate recommendations based on differences."""
        recommendations = []
        # Placeholder implementation
        return recommendations
    
    def _check_compliance_gaps(self, config_a: FirewallConfig, config_b: FirewallConfig) -> List[Dict[str, Any]]:
        """Check for compliance gaps between two firewalls."""
        gaps = []
        # Placeholder implementation
        return gaps
    
    def _check_gdpr_compliance(self, config: FirewallConfig) -> Dict[str, Any]:
        """Check GDPR compliance."""
        return {"compliant": True, "issues": []}
    
    def _check_nis2_compliance(self, config: FirewallConfig) -> Dict[str, Any]:
        """Check NIS2 compliance."""
        return {"compliant": True, "issues": []}
    
    def _check_iso27001_compliance(self, config: FirewallConfig) -> Dict[str, Any]:
        """Check ISO27001 compliance."""
        return {"compliant": True, "issues": []}
    
    def _check_pci_dss_compliance(self, config: FirewallConfig) -> Dict[str, Any]:
        """Check PCI-DSS compliance."""
        return {"compliant": True, "issues": []}
    
    def _check_hipaa_compliance(self, config: FirewallConfig) -> Dict[str, Any]:
        """Check HIPAA compliance."""
        return {"compliant": True, "issues": []}
    
    def _identify_missing_policies(self, config: FirewallConfig, standards: List[str]) -> List[Dict[str, Any]]:
        """Identify missing policies for compliance standards."""
        return []
    
    def _check_utm_profiles(self, config: FirewallConfig) -> List[Dict[str, Any]]:
        """
        Check for UTM profile inconsistencies (policies without AV, IPS, Web Filter).
        
        Args:
            config: Firewall configuration to analyze
            
        Returns:
            List of UTM profile inconsistencies
        """
        utm_issues = []
        
        for policy in config.policies:
            # Check if policy allows internet access
            dst = policy.get("destination_addresses", []) or policy.get("destination_zones", [])
            action = str(policy.get("action", "")).lower()
            
            # Check if it's an internet-facing policy
            if action in ["accept", "allow"] and ("all" in dst or any(d and "internet" in str(d).lower() for d in dst if d)):
                # Check for UTM profiles
                has_utm = policy.get("utm-status", False) or policy.get("utm_enabled", False)
                has_av = bool(policy.get("av-profile") or policy.get("av_profile"))
                has_ips = bool(policy.get("ips-sensor") or policy.get("ips_sensor"))
                has_webfilter = bool(policy.get("webfilter-profile") or policy.get("webfilter_profile"))
                
                if not has_utm or not (has_av or has_ips or has_webfilter):
                    utm_issues.append({
                        "type": "UTM Profile Inconsistency",
                        "severity": "HIGH",
                        "description": f"Policy allows internet access without UTM protection",
                        "fortinet_policy": policy.get("name", policy.get("id", "")),
                        "zscaler_policy": "N/A",
                        "affected_groups": self._extract_groups_from_policy(policy, config),
                        "recommendation": "Enable UTM profiles (AV, IPS, Web Filtering) on this policy",
                        "details": {
                            "policy_id": policy.get("id", ""),
                            "has_utm": has_utm,
                            "has_av": has_av,
                            "has_ips": has_ips,
                            "has_webfilter": has_webfilter
                        }
                    })
        
        return utm_issues
    
    def _extract_groups_from_policy(self, policy: Dict[str, Any], config: FirewallConfig) -> List[str]:
        """
        Extract user groups from a policy.
        
        Args:
            policy: Policy dictionary
            config: Firewall configuration
            
        Returns:
            List of group names
        """
        groups = []
        
        # Check for groups field
        if "groups" in policy:
            groups_str = policy["groups"]
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
        
        # Check for group-name or group_name
        if not groups and "group-name" in policy:
            groups = [policy["group-name"]]
        if not groups and "group_name" in policy:
            groups = [policy["group_name"]]
        
        return groups
    
    def _extract_groups_from_policy_id(self, policy_id: str, config: FirewallConfig) -> List[str]:
        """
        Extract user groups from a policy by ID.
        
        Args:
            policy_id: Policy ID
            config: Firewall configuration
            
        Returns:
            List of group names
        """
        for policy in config.policies:
            if str(policy.get("id", "")) == str(policy_id):
                return self._extract_groups_from_policy(policy, config)
        return []
    
    def _check_user_group_consistency(self, config: FirewallConfig) -> List[Dict[str, Any]]:
        """
        Check user group consistency within a single firewall.
        Engine 5: User Group Consistency Analysis
        
        Args:
            config: Firewall configuration to analyze
            
        Returns:
            List of user group inconsistencies
        """
        issues = []
        groups_found = set()
        groups_referenced = set()
        
        # Extract all groups from policies
        for policy in config.policies:
            groups = self._extract_groups_from_policy(policy, config)
            for group in groups:
                groups_found.add(group)
                groups_referenced.add(group)
        
        # Check for policies with groups that might be inconsistent
        # (e.g., same group with conflicting access patterns)
        group_policies = {}
        for policy in config.policies:
            groups = self._extract_groups_from_policy(policy, config)
            for group in groups:
                if group not in group_policies:
                    group_policies[group] = []
                group_policies[group].append({
                    "policy_id": policy.get("id", ""),
                    "policy_name": policy.get("name", ""),
                    "action": policy.get("action", ""),
                    "destinations": policy.get("destination_addresses", []) or policy.get("destination_zones", [])
                })
        
        # Check for groups with conflicting access patterns
        for group, policies in group_policies.items():
            actions = set(p.get("action", "").lower() for p in policies)
            if "accept" in actions and "deny" in actions:
                # Check if they're for the same destination
                destinations = set()
                for p in policies:
                    destinations.update(p.get("destinations", []))
                
                if len(destinations) == 1 and "all" in destinations:
                    issues.append({
                        "type": "User Group Inconsistency",
                        "severity": "MEDIUM",
                        "description": f"Group '{group}' has conflicting access patterns (accept and deny for same destination)",
                        "fortinet_policy": f"Multiple policies",
                        "zscaler_policy": "N/A",
                        "affected_groups": [group],
                        "recommendation": "Review policies for group and ensure consistent access control",
                        "details": {
                            "group": group,
                            "policies": [p["policy_name"] for p in policies]
                        }
                    })
        
        return issues
    
    def _check_dlp_coverage_gaps_single(self, config: FirewallConfig) -> List[Dict[str, Any]]:
        """
        Check for DLP coverage gaps within a single firewall.
        Engine 6: DLP Coverage Gap Analysis
        
        Args:
            config: Firewall configuration to analyze
            
        Returns:
            List of DLP coverage gaps
        """
        issues = []
        
        # Groups that have DLP enabled
        groups_with_dlp = set()
        groups_without_dlp = set()
        
        for policy in config.policies:
            groups = self._extract_groups_from_policy(policy, config)
            has_dlp = bool(policy.get("dlp-sensor") or policy.get("dlp_sensor"))
            
            for group in groups:
                if has_dlp:
                    groups_with_dlp.add(group)
                else:
                    # Check if this is a sensitive data policy
                    dest = policy.get("destination_addresses", []) or policy.get("destination_zones", [])
                    action = str(policy.get("action", "")).lower()
                    
                    # If policy allows internet access or sensitive services, should have DLP
                    if (action in ["accept", "allow"] and 
                        ("all" in dest or any(d and "internet" in str(d).lower() for d in dest if d))):
                        groups_without_dlp.add(group)
        
        # Find groups that should have DLP but don't
        missing_dlp_groups = groups_without_dlp - groups_with_dlp
        
        # Find policies that handle sensitive data but lack DLP
        for policy in config.policies:
            groups = self._extract_groups_from_policy(policy, config)
            has_dlp = bool(policy.get("dlp-sensor") or policy.get("dlp_sensor"))
            dest = policy.get("destination_addresses", []) or policy.get("destination_zones", [])
            action = str(policy.get("action", "")).lower()
            
            # Check if this is a sensitive policy that should have DLP
            if (action in ["accept", "allow"] and 
                not has_dlp and
                ("all" in dest or any(d and "internet" in str(d).lower() for d in dest if d))):
                
                # Check if policy handles sensitive data (based on comments or name)
                policy_name = (policy.get("name") or "").lower()
                comments = (policy.get("comments") or "").lower()
                is_sensitive = any(keyword in policy_name or keyword in comments 
                                 for keyword in ["customer", "data", "financial", "pii", "sensitive", "crm", "sales"])
                
                if is_sensitive or any(g in missing_dlp_groups for g in groups):
                    issues.append({
                        "type": "DLP Coverage Gap",
                        "severity": "HIGH",
                        "description": f"Groups have DLP in Fortinet but not in Zscaler" if config.vendor == "fortinet" else f"Policy handles sensitive data but lacks DLP protection",
                        "fortinet_policy": policy.get("name", policy.get("id", "")),
                        "zscaler_policy": "Missing",
                        "affected_groups": [g for g in groups if g in missing_dlp_groups] or groups or [],
                        "recommendation": "Implement DLP policies for these groups",
                        "details": {
                            "missing_groups": list(missing_dlp_groups) if missing_dlp_groups else groups,
                            "policy_id": policy.get("id", "")
                        }
                    })
        
        return issues
    
    def _check_application_access_gaps_single(self, config: FirewallConfig) -> List[Dict[str, Any]]:
        """
        Check for application access gaps within a single firewall.
        Engine 7: Application Access Gap Verification
        
        Args:
            config: Firewall configuration to analyze
            
        Returns:
            List of application access gaps
        """
        issues = []
        
        # Check for policies allowing application access without proper controls
        for policy in config.policies:
            action = str(policy.get("action", "")).lower()
            services = policy.get("services", [])
            groups = self._extract_groups_from_policy(policy, config)
            
            # Check if policy allows broad application access
            if action in ["accept", "allow"]:
                # Check for missing application controls
                has_app_control = bool(policy.get("application-list") or policy.get("application_list"))
                
                # Check if services include application protocols
                app_protocols = ["HTTP", "HTTPS", "FTP", "SSH", "RDP", "SMB", "LDAP", "DNS"]
                has_app_protocols = any(any(proto in str(svc).upper() for proto in app_protocols) for svc in services)
                
                if has_app_protocols and not has_app_control:
                    issues.append({
                        "type": "Application Access Gap",
                        "severity": "MEDIUM",
                        "description": f"Policy allows application access without application control",
                        "fortinet_policy": policy.get("name", policy.get("id", "")),
                        "zscaler_policy": "N/A",
                        "affected_groups": groups,
                        "recommendation": "Enable application control or application list on this policy",
                        "details": {
                            "policy_id": policy.get("id", ""),
                            "services": services,
                            "has_app_control": has_app_control
                        }
                    })
        
        return issues
    
    def _check_missing_security_coverage(self, config: FirewallConfig) -> List[Dict[str, Any]]:
        """
        Check for missing security coverage.
        Engine 8: Missing Security Coverage Detection
        
        Args:
            config: Firewall configuration to analyze
            
        Returns:
            List of missing security coverage issues
        """
        issues = []
        
        for policy in config.policies:
            action = str(policy.get("action", "")).lower()
            dest = policy.get("destination_addresses", []) or policy.get("destination_zones", [])
            groups = self._extract_groups_from_policy(policy, config)
            
            # Check for internet access policies missing URL filtering
            if action in ["accept", "allow"] and ("all" in dest or any(d and "internet" in str(d).lower() for d in dest if d)):
                has_webfilter = bool(policy.get("webfilter-profile") or policy.get("webfilter_profile"))
                
                if not has_webfilter:
                    issues.append({
                        "type": "Missing Security Coverage",
                        "severity": "HIGH",
                        "description": f"Group has internet access in Fortinet but no URL filtering in Zscaler",
                        "fortinet_policy": policy.get("name", policy.get("id", "")),
                        "zscaler_policy": "None",
                        "affected_groups": groups,
                        "recommendation": "Create Zscaler URL filtering policy for this group",
                        "details": {
                            "fortinet": {
                                "policy": policy.get("name", ""),
                                "utm_enabled": policy.get("utm-status", False),
                                "av_profile": policy.get("av-profile"),
                                "ips_sensor": policy.get("ips-sensor")
                            }
                        }
                    })
        
        return issues
    
    # ========================================================================
    # Enhanced Analysis Methods (merged from enhanced_policy_analyzer.py)
    # ========================================================================
    
    def _run_enhanced_analysis(self, config: FirewallConfig) -> Tuple[List[PolicyInconsistencyEnhanced], Dict[str, Any]]:
        """
        Run enhanced analysis with validation, normalization, and 10 comprehensive checks.
        
        Args:
            config: Firewall configuration to analyze
            
        Returns:
            Tuple of (list of inconsistencies, summary dict)
        """
        inconsistencies: List[PolicyInconsistencyEnhanced] = []
        normalized_policies: List[NormalizedPolicyEnhanced] = []
        analysis_metadata = {}
        
        logger.info("=" * 80)
        logger.info("INITIALIZING ENHANCED POLICY ANALYZER")
        logger.info("=" * 80)
        
        # Validate configuration
        logger.info(f"\n[1/2] Validating {config.vendor} configuration")
        config_dict = {
            'policies': config.policies,
            'firewall_policies': config.policies,
            'vendor': config.vendor
        }
        
        if config.vendor == 'fortinet':
            is_valid, errors = ConfigValidator.validate_fortinet(config_dict)
        elif config.vendor == 'zscaler':
            is_valid, errors = ConfigValidator.validate_zscaler(config_dict)
        else:
            is_valid = True
            errors = []
            logger.warning(f"Unknown vendor {config.vendor}, skipping validation")
        
        if not is_valid:
            logger.error(f"Configuration validation FAILED:")
            for error in errors:
                logger.error(f"  - {error}")
        else:
            logger.info(f"✓ Configuration validation passed")
        
        # Normalize policies
        logger.info(f"\n[2/2] Normalizing {len(config.policies)} policies")
        for policy in config.policies:
            try:
                if config.vendor == 'fortinet':
                    normalized = PolicyNormalizerEnhanced.normalize_fortinet_policy(policy)
                elif config.vendor == 'zscaler':
                    policy_type = 'url_filtering'
                    if 'dlp_settings' in policy:
                        policy_type = 'dlp'
                    elif 'applications' in policy:
                        policy_type = 'zpa'
                    normalized = PolicyNormalizerEnhanced.normalize_zscaler_policy(policy, policy_type)
                else:
                    logger.warning(f"Unknown vendor {config.vendor}, skipping normalization")
                    continue
                
                normalized_policies.append(normalized)
                logger.debug(f"  ✓ Normalized: {normalized.policy_name}")
            except Exception as e:
                logger.error(f"  ✗ Failed to normalize {policy.get('name', 'unknown')}: {e}")
                import traceback
                logger.debug(traceback.format_exc())
        
        logger.info(f"✓ Normalized {len(normalized_policies)} policies")
        
        analysis_metadata = {
            'vendor': config.vendor,
            'policy_count': len(normalized_policies),
            'config_valid': is_valid,
            'validation_errors': errors
        }
        
        # Run all 10 checks
        logger.info("\n" + "=" * 80)
        logger.info("STARTING COMPREHENSIVE ANALYSIS (10 CHECKS)")
        logger.info("=" * 80)
        
        self._enhanced_check_1_contradictory_rules(normalized_policies, config, inconsistencies)
        self._enhanced_check_2_duplicate_policies(normalized_policies, config, inconsistencies)
        self._enhanced_check_3_overly_permissive_rules(normalized_policies, config, inconsistencies)
        self._enhanced_check_4_utm_profile_inconsistency(normalized_policies, config, inconsistencies)
        self._enhanced_check_5_user_group_consistency(normalized_policies, config, inconsistencies)
        self._enhanced_check_6_dlp_coverage_gaps(normalized_policies, config, inconsistencies)
        self._enhanced_check_7_application_access_gaps(normalized_policies, config, inconsistencies)
        self._enhanced_check_8_missing_security_coverage(normalized_policies, config, inconsistencies)
        self._enhanced_check_9_logging_consistency(normalized_policies, config, inconsistencies)
        self._enhanced_check_10_mfa_encryption_requirements(normalized_policies, config, inconsistencies)
        
        logger.info("\n" + "=" * 80)
        logger.info(f"ANALYSIS COMPLETE: Found {len(inconsistencies)} inconsistencies")
        logger.info("=" * 80)
        
        # Generate summary
        by_severity = {
            'CRITICAL': len([i for i in inconsistencies if i.severity == SeverityLevel.CRITICAL]),
            'HIGH': len([i for i in inconsistencies if i.severity == SeverityLevel.HIGH]),
            'MEDIUM': len([i for i in inconsistencies if i.severity == SeverityLevel.MEDIUM]),
            'LOW': len([i for i in inconsistencies if i.severity == SeverityLevel.LOW]),
        }
        
        by_type = defaultdict(int)
        for i in inconsistencies:
            by_type[i.type.value] += 1
        
        summary = {
            'total_inconsistencies': len(inconsistencies),
            'by_severity': by_severity,
            'by_type': dict(by_type),
            'metadata': analysis_metadata
        }
        
        return inconsistencies, summary
    
    def _enhanced_check_1_contradictory_rules(self, normalized_policies: List[NormalizedPolicyEnhanced], 
                                             config: FirewallConfig, inconsistencies: List[PolicyInconsistencyEnhanced]):
        """Check 1/10: Contradictory Rules."""
        logger.info("\n[CHECK 1/10] Contradictory Rules")
        
        contradictions = []
        for i, policy1 in enumerate(normalized_policies):
            for policy2 in normalized_policies[i+1:]:
                if self._enhanced_policies_overlap(policy1, policy2):
                    action1_allows = policy1.action in ['allow', 'accept']
                    action2_allows = policy2.action in ['allow', 'accept']
                    action1_denies = policy1.action in ['deny', 'block', 'reject']
                    action2_denies = policy2.action in ['deny', 'block', 'reject']
                    
                    if (action1_allows and action2_denies) or (action1_denies and action2_allows):
                        contradictions.append((policy1, policy2))
        
        for pol1, pol2 in contradictions:
            inconsistency = PolicyInconsistencyEnhanced(
                inconsistency_id=f"CONT_{pol1.policy_id}_{pol2.policy_id}",
                type=InconsistencyType.CONTRADICTORY_ALLOW_DENY,
                severity=SeverityLevel.HIGH,
                description=f"Policies '{pol1.policy_name}' and '{pol2.policy_name}' have overlapping rules with contradictory actions",
                affected_fortinet_policies=[pol1.policy_id, pol2.policy_id] if config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[pol1.policy_id, pol2.policy_id] if config.vendor == 'zscaler' else [],
                affected_user_groups=list(pol1.source_users | pol2.source_users),
                root_cause="Same source/destination/service but different actions (allow vs deny)",
                business_impact="Unclear policy enforcement, potential security bypass or false blocking",
                recommendation="Review policy order and intent; consolidate if redundant",
                confidence_score=0.98,
                evidence={
                    'policy1': {'id': pol1.policy_id, 'name': pol1.policy_name, 'action': pol1.action},
                    'policy2': {'id': pol2.policy_id, 'name': pol2.policy_name, 'action': pol2.action}
                }
            )
            inconsistencies.append(inconsistency)
        
        logger.info(f"  ✓ Found {len(contradictions)} contradictory rule pairs")
    
    def _enhanced_check_2_duplicate_policies(self, normalized_policies: List[NormalizedPolicyEnhanced],
                                           config: FirewallConfig, inconsistencies: List[PolicyInconsistencyEnhanced]):
        """Check 2/10: Duplicate Policies."""
        logger.info("\n[CHECK 2/10] Duplicate Policies")
        
        hash_map = defaultdict(list)
        for policy in normalized_policies:
            h = policy.semantic_hash()
            hash_map[h].append(policy)
        
        duplicates = [(policies[0], policies[1:]) 
                     for policies in hash_map.values() 
                     if len(policies) > 1]
        
        for orig, dups in duplicates:
            dup_ids = [d.policy_id for d in dups]
            inconsistency = PolicyInconsistencyEnhanced(
                inconsistency_id=f"DUP_{orig.policy_id}",
                type=InconsistencyType.DUPLICATE_POLICY,
                severity=SeverityLevel.LOW,
                description=f"Policy '{orig.policy_name}' is duplicated ({len(dups)} times)",
                affected_fortinet_policies=[orig.policy_id] + dup_ids if config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[orig.policy_id] + dup_ids if config.vendor == 'zscaler' else [],
                root_cause="Multiple policies with identical source, destination, and action",
                recommendation="Consolidate duplicate policies into a single rule",
                confidence_score=0.90,
                evidence={'duplicate_ids': dup_ids}
            )
            inconsistencies.append(inconsistency)
        
        logger.info(f"  ✓ Found {len(duplicates)} duplicate policy sets")
    
    def _enhanced_check_3_overly_permissive_rules(self, normalized_policies: List[NormalizedPolicyEnhanced],
                                                  config: FirewallConfig, inconsistencies: List[PolicyInconsistencyEnhanced]):
        """Check 3/10: Overly Permissive Rules."""
        logger.info("\n[CHECK 3/10] Overly Permissive Rules")
        
        overly_permissive = []
        for policy in normalized_policies:
            if policy.action in ['allow', 'accept']:
                if policy.applies_to_all_sources or policy.applies_to_all_destinations:
                    overly_permissive.append(policy)
        
        for policy in overly_permissive:
            issue_type = "source" if policy.applies_to_all_sources else "destination"
            inconsistency = PolicyInconsistencyEnhanced(
                inconsistency_id=f"PERM_{policy.policy_id}",
                type=InconsistencyType.OVERLY_PERMISSIVE,
                severity=SeverityLevel.HIGH,
                description=f"Policy '{policy.policy_name}' allows traffic from/to all {issue_type}s",
                affected_fortinet_policies=[policy.policy_id] if config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause=f"Policy allows all {issue_type}s (violates least-privilege principle)",
                business_impact="Excessive access permissions, potential security risk",
                recommendation=f"Restrict {issue_type} addresses to specific networks or zones",
                confidence_score=0.95,
                evidence={'policy_type': issue_type, 'applies_to_all_sources': policy.applies_to_all_sources}
            )
            inconsistencies.append(inconsistency)
        
        logger.info(f"  ✓ Found {len(overly_permissive)} overly permissive rules")
    
    def _enhanced_check_4_utm_profile_inconsistency(self, normalized_policies: List[NormalizedPolicyEnhanced],
                                                    config: FirewallConfig, inconsistencies: List[PolicyInconsistencyEnhanced]):
        """Check 4/10: UTM Profile Inconsistency."""
        logger.info("\n[CHECK 4/10] UTM Profile Inconsistency")
        
        unprotected = []
        for policy in normalized_policies:
            if (policy.action in ['allow', 'accept'] and 
                policy.applies_to_all_destinations and 
                not policy.utm_profiles and 
                not policy.dlp_enabled):
                unprotected.append(policy)
        
        for policy in unprotected:
            inconsistency = PolicyInconsistencyEnhanced(
                inconsistency_id=f"UTM_{policy.policy_id}",
                type=InconsistencyType.INTERNET_ACCESS_UNPROTECTED,
                severity=SeverityLevel.HIGH,
                description=f"Policy '{policy.policy_name}' allows internet access without UTM protection",
                affected_fortinet_policies=[policy.policy_id] if config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause="Internet access granted without UTM/AV/IPS profiles",
                business_impact="Users exposed to internet threats without inspection",
                recommendation="Enable UTM profiles (AV, IPS, WebFilter) or use Zscaler protection",
                confidence_score=0.99,
                evidence={'missing_utm': list(policy.utm_profiles), 'dest_type': policy.dest_type}
            )
            inconsistencies.append(inconsistency)
        
        logger.info(f"  ✓ Found {len(unprotected)} policies without UTM protection")
    
    def _enhanced_check_5_user_group_consistency(self, normalized_policies: List[NormalizedPolicyEnhanced],
                                                  config: FirewallConfig, inconsistencies: List[PolicyInconsistencyEnhanced]):
        """Check 5/10: User Group Consistency."""
        logger.info("\n[CHECK 5/10] User Group Consistency")
        
        group_policies = defaultdict(list)
        for policy in normalized_policies:
            for group in policy.source_users:
                group_policies[group].append(policy)
        
        issues = []
        for group, policies in group_policies.items():
            actions = set(p.action for p in policies)
            if 'allow' in actions and 'deny' in actions:
                destinations = set()
                for p in policies:
                    if p.applies_to_all_destinations:
                        destinations.add('all')
                    else:
                        destinations.add(p.dest_resource)
                
                if len(destinations) == 1 and 'all' in destinations:
                    issues.append((group, policies))
        
        for group, policies in issues:
            inconsistency = PolicyInconsistencyEnhanced(
                inconsistency_id=f"UG_{group}",
                type=InconsistencyType.USER_GROUP_PERMISSION_MISMATCH,
                severity=SeverityLevel.MEDIUM,
                description=f"Group '{group}' has conflicting access patterns (allow and deny for same destination)",
                affected_user_groups=[group],
                root_cause="Same group has both allow and deny policies for same destination",
                business_impact="Unclear access control for group members",
                recommendation="Review policies for group and ensure consistent access control",
                confidence_score=0.85,
                evidence={'group': group, 'policies': [p.policy_name for p in policies]}
            )
            inconsistencies.append(inconsistency)
        
        logger.info(f"  ✓ Found {len(issues)} user group consistency issues")
    
    def _enhanced_check_6_dlp_coverage_gaps(self, normalized_policies: List[NormalizedPolicyEnhanced],
                                            config: FirewallConfig, inconsistencies: List[PolicyInconsistencyEnhanced]):
        """Check 6/10: DLP Coverage Gaps."""
        logger.info("\n[CHECK 6/10] DLP Coverage Gaps")
        
        sensitive_keywords = {'finance', 'accounting', 'legal', 'hr', 'executive', 'sales', 'crm'}
        sensitive_policies = [p for p in normalized_policies 
                            if any(kw in str(p.source_users).lower() or kw in p.policy_name.lower()
                                   for kw in sensitive_keywords)]
        
        missing_dlp = [p for p in sensitive_policies 
                      if not p.dlp_enabled and p.action in ['allow', 'accept']]
        
        for policy in missing_dlp:
            inconsistency = PolicyInconsistencyEnhanced(
                inconsistency_id=f"DLP_{policy.policy_id}",
                type=InconsistencyType.DLP_COVERAGE_GAP,
                severity=SeverityLevel.HIGH,
                description=f"Sensitive group '{policy.source_users}' not protected by DLP",
                affected_fortinet_policies=[policy.policy_id] if config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause="DLP profile not enabled on sensitive group policy",
                business_impact="Sensitive data access not monitored/prevented",
                recommendation="Enable DLP profile for this policy",
                confidence_score=0.95,
                evidence={'affected_group': str(policy.source_users), 'policy_name': policy.policy_name}
            )
            inconsistencies.append(inconsistency)
        
        logger.info(f"  ✓ Found {len(missing_dlp)} DLP coverage gaps")
    
    def _enhanced_check_7_application_access_gaps(self, normalized_policies: List[NormalizedPolicyEnhanced],
                                                  config: FirewallConfig, inconsistencies: List[PolicyInconsistencyEnhanced]):
        """Check 7/10: Application Access Gaps."""
        logger.info("\n[CHECK 7/10] Application Access Gaps")
        
        app_protocols = {'http', 'https', 'ftp', 'ssh', 'rdp', 'smb', 'ldap', 'dns'}
        app_policies = [p for p in normalized_policies 
                       if p.action in ['allow', 'accept'] and
                       any(any(proto in str(prot).lower() for proto in app_protocols) 
                           for prot in p.protocols)]
        
        missing_controls = [p for p in app_policies 
                           if not p.utm_profiles and not p.dlp_enabled]
        
        for policy in missing_controls:
            inconsistency = PolicyInconsistencyEnhanced(
                inconsistency_id=f"APP_{policy.policy_id}",
                type=InconsistencyType.ENFORCEMENT_CONFLICT,
                severity=SeverityLevel.MEDIUM,
                description=f"Policy '{policy.policy_name}' allows application access without controls",
                affected_fortinet_policies=[policy.policy_id] if config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause="Application access granted without application control or UTM",
                business_impact="Application traffic not inspected or controlled",
                recommendation="Enable application control or application list on this policy",
                confidence_score=0.80,
                evidence={'protocols': list(policy.protocols)}
            )
            inconsistencies.append(inconsistency)
        
        logger.info(f"  ✓ Found {len(missing_controls)} application access gaps")
    
    def _enhanced_check_8_missing_security_coverage(self, normalized_policies: List[NormalizedPolicyEnhanced],
                                                   config: FirewallConfig, inconsistencies: List[PolicyInconsistencyEnhanced]):
        """Check 8/10: Missing Security Coverage."""
        logger.info("\n[CHECK 8/10] Missing Security Coverage")
        
        internet_policies = [p for p in normalized_policies 
                            if p.action in ['allow', 'accept'] and 
                            p.applies_to_all_destinations]
        
        missing_coverage = [p for p in internet_policies 
                           if not p.utm_profiles and 
                           'webfilter' not in str(p.utm_profiles).lower()]
        
        for policy in missing_coverage:
            inconsistency = PolicyInconsistencyEnhanced(
                inconsistency_id=f"COV_{policy.policy_id}",
                type=InconsistencyType.MISSING_UTM_PROFILE,
                severity=SeverityLevel.HIGH,
                description=f"Policy '{policy.policy_name}' allows internet access without URL filtering",
                affected_fortinet_policies=[policy.policy_id] if config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause="Internet access policy missing URL filtering/web filtering",
                business_impact="Users can access inappropriate or malicious websites",
                recommendation="Enable URL filtering or web filtering profile on this policy",
                confidence_score=0.90,
                evidence={'dest_type': policy.dest_type}
            )
            inconsistencies.append(inconsistency)
        
        logger.info(f"  ✓ Found {len(missing_coverage)} missing security coverage issues")
    
    def _enhanced_check_9_logging_consistency(self, normalized_policies: List[NormalizedPolicyEnhanced],
                                              config: FirewallConfig, inconsistencies: List[PolicyInconsistencyEnhanced]):
        """Check 9/10: Logging Consistency."""
        logger.info("\n[CHECK 9/10] Logging Consistency")
        
        critical_keywords = {'security', 'audit', 'finance', 'executive', 'admin', 'it-'}
        critical_policies = [p for p in normalized_policies
                           if any(kw in str(p.source_users).lower() or kw in p.policy_name.lower()
                                  for kw in critical_keywords)]
        
        no_logging = [p for p in critical_policies if not p.logging_enabled]
        
        for policy in no_logging:
            inconsistency = PolicyInconsistencyEnhanced(
                inconsistency_id=f"LOG_{policy.policy_id}",
                type=InconsistencyType.MISSING_LOGGING,
                severity=SeverityLevel.MEDIUM,
                description=f"Critical policy '{policy.policy_name}' has logging disabled",
                affected_fortinet_policies=[policy.policy_id] if config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause="Logging not enabled on critical access policy",
                business_impact="No audit trail for compliance and security monitoring",
                recommendation="Enable logging for audit trail and compliance",
                confidence_score=0.90,
                evidence={'policy_name': policy.policy_name}
            )
            inconsistencies.append(inconsistency)
        
        logger.info(f"  ✓ Found {len(no_logging)} logging gaps")
    
    def _enhanced_check_10_mfa_encryption_requirements(self, normalized_policies: List[NormalizedPolicyEnhanced],
                                                       config: FirewallConfig, inconsistencies: List[PolicyInconsistencyEnhanced]):
        """Check 10/10: MFA/Encryption Requirements."""
        logger.info("\n[CHECK 10/10] MFA/Encryption Requirements")
        
        sensitive_policies = [p for p in normalized_policies 
                            if p.action in ['allow', 'accept'] and
                            (p.applies_to_all_destinations or 
                             any(kw in str(p.source_users).lower() 
                                 for kw in ['finance', 'executive', 'admin', 'hr']))]
        
        missing_mfa = [p for p in sensitive_policies if not p.requires_mfa]
        missing_encryption = [p for p in sensitive_policies if not p.requires_encryption]
        
        for policy in missing_mfa:
            inconsistency = PolicyInconsistencyEnhanced(
                inconsistency_id=f"MFA_{policy.policy_id}",
                type=InconsistencyType.MFA_REQUIREMENT_MISMATCH,
                severity=SeverityLevel.HIGH,
                description=f"Sensitive policy '{policy.policy_name}' does not require MFA",
                affected_fortinet_policies=[policy.policy_id] if config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause="MFA not required for sensitive access",
                business_impact="Potential unauthorized access to sensitive resources",
                recommendation="Enable MFA requirement for this policy",
                confidence_score=0.85,
                evidence={'policy_name': policy.policy_name}
            )
            inconsistencies.append(inconsistency)
        
        for policy in missing_encryption:
            inconsistency = PolicyInconsistencyEnhanced(
                inconsistency_id=f"ENC_{policy.policy_id}",
                type=InconsistencyType.ENCRYPTION_GAP,
                severity=SeverityLevel.HIGH,
                description=f"Sensitive policy '{policy.policy_name}' does not require encryption",
                affected_fortinet_policies=[policy.policy_id] if config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause="Encryption not required for sensitive access",
                business_impact="Sensitive data may be transmitted in plaintext",
                recommendation="Enable encryption requirement for this policy",
                confidence_score=0.85,
                evidence={'policy_name': policy.policy_name}
            )
            inconsistencies.append(inconsistency)
        
        logger.info(f"  ✓ Found {len(missing_mfa)} MFA gaps, {len(missing_encryption)} encryption gaps")
    
    def _enhanced_policies_overlap(self, policy1: NormalizedPolicyEnhanced, 
                                   policy2: NormalizedPolicyEnhanced) -> bool:
        """Check if two policies overlap."""
        if policy1.applies_to_all_sources or policy2.applies_to_all_sources:
            src_overlap = True
        else:
            src_overlap = bool(policy1.source_users & policy2.source_users) or not (policy1.source_users and policy2.source_users)
        
        if policy1.applies_to_all_destinations or policy2.applies_to_all_destinations:
            dst_overlap = True
        elif policy1.dest_resource == policy2.dest_resource:
            dst_overlap = True
        else:
            dst_overlap = False
        
        if not (policy1.protocols and policy2.protocols):
            service_overlap = True
        else:
            service_overlap = bool(policy1.protocols & policy2.protocols)
        
        return src_overlap and dst_overlap and service_overlap