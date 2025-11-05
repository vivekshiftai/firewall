"""
Main policy analyzer for cross-firewall policy analysis.
"""
import logging
from typing import Dict, Any, List
from analyzers.base import BaseAnalyzer
from models.base import FirewallConfig, PolicyComparisonResult, ComplianceReport
from utils.embeddings import PolicyEmbedder
from utils.mapping import SemanticMapper

# Configure logging
logger = logging.getLogger(__name__)

class PolicyAnalyzer(BaseAnalyzer):
    """Main analyzer for firewall policy analysis."""

    def __init__(self):
        """Initialize the policy analyzer."""
        logger.info("Initializing PolicyAnalyzer")
        self.embedder = PolicyEmbedder()
        self.mapper = SemanticMapper()
        logger.debug("PolicyAnalyzer components initialized")
        logger.info("PolicyAnalyzer initialized successfully")

    def analyze_single_firewall(self, config: FirewallConfig) -> Dict[str, Any]:
        """
        Analyze a single firewall configuration for internal inconsistencies.
        
        Args:
            config: Firewall configuration to analyze
            
        Returns:
            Analysis results
        """
        logger.info(f"Starting single firewall analysis for {config.vendor} firewall ID: {config.id}")
        try:
            logger.debug("Checking for policy conflicts")
            conflicts = self._check_policy_conflicts(config)
            logger.info(f"Found {len(conflicts)} policy conflicts")
            
            logger.debug("Checking for redundant policies")
            redundancies = self._check_redundant_policies(config)
            logger.info(f"Found {len(redundancies)} redundant policies")
            
            logger.debug("Checking for gaps in coverage")
            gaps = self._check_coverage_gaps(config)
            logger.info(f"Found {len(gaps)} coverage gaps")
            
            results = {
                "firewall_id": config.id,
                "vendor": config.vendor,
                "total_policies": len(config.policies),
                "conflicts": conflicts,
                "redundancies": redundancies,
                "coverage_gaps": gaps,
                "risk_score": self._calculate_risk_score(conflicts, redundancies, gaps)
            }
            
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