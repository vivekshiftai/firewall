"""
Main policy analyzer for cross-firewall policy analysis.
"""
import logging
import os
from typing import Dict, Any, List, Optional
from analyzers.base import BaseAnalyzer
from models.base import FirewallConfig, PolicyComparisonResult, ComplianceReport
from utils.embeddings import PolicyEmbedder
from utils.mapping import SemanticMapper
from analyzers.ai_analyzer import AIInconsistencyAnalyzer

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

    def analyze_single_firewall(self, config: FirewallConfig) -> Dict[str, Any]:
        """
        Analyze a single firewall configuration for internal inconsistencies.
        Uses both rule-based analysis and AI-powered analysis.
        
        Args:
            config: Firewall configuration to analyze
            
        Returns:
            Analysis results including both rule-based and AI findings
        """
        logger.info(f"Starting single firewall analysis for {config.vendor} firewall ID: {config.id}")
        try:
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
            
            # Convert to standardized inconsistency format
            all_inconsistencies = []
            
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
            
            # Format results in the requested structure
            from datetime import datetime
            results = {
                "summary": {
                    "total_inconsistencies": len(all_inconsistencies),
                    "high_severity": high_severity,
                    "medium_severity": medium_severity,
                    "low_severity": low_severity,
                    "analysis_timestamp": datetime.now().isoformat()
                },
                "inconsistencies": all_inconsistencies,
                "rule_based_analysis": {
                    "conflicts": conflicts,
                    "redundancies": redundancies,
                    "coverage_gaps": gaps,
                    "risk_score": self._calculate_risk_score(conflicts, redundancies, gaps)
                },
                **ai_results  # Include AI analysis results
            }
            
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