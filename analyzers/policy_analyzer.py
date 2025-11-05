"""
Policy analyzer for firewall configurations.
"""
import logging
from typing import List, Dict, Any
from analyzers.base import BaseAnalyzer
from models.base import FirewallConfig, PolicyComparisonResult
from exceptions.custom_exceptions import AnalyzerError

logger = logging.getLogger(__name__)


class PolicyAnalyzer(BaseAnalyzer):
    """Analyzer for firewall policy analysis and comparison."""

    def analyze_single_firewall(self, config: FirewallConfig) -> Dict[str, Any]:
        """
        Analyze a single firewall configuration for internal inconsistencies.
        
        Args:
            config: Firewall configuration to analyze
            
        Returns:
            Analysis results including inconsistencies and recommendations
        """
        try:
            inconsistencies = self._find_inconsistencies(config)
            recommendations = self._generate_recommendations(config, inconsistencies)
            
            return {
                "firewall_id": config.id,
                "vendor": config.vendor,
                "inconsistencies": inconsistencies,
                "recommendations": recommendations,
                "summary": {
                    "total_policies": len(config.policies),
                    "inconsistent_policies": len(inconsistencies),
                    "compliance_score": self._calculate_compliance_score(config, inconsistencies)
                }
            }
        except Exception as e:
            logger.error(f"Error analyzing firewall {config.id}: {str(e)}")
            raise AnalyzerError(f"Failed to analyze firewall {config.id}: {str(e)}")

    def compare_firewalls(self, config_a: FirewallConfig, config_b: FirewallConfig) -> PolicyComparisonResult:
        """
        Compare two firewall configurations.
        
        Args:
            config_a: First firewall configuration
            config_b: Second firewall configuration
            
        Returns:
            Comparison results including differences and recommendations
        """
        try:
            parity_matrix = self._generate_parity_matrix(config_a, config_b)
            differences = self._find_differences(config_a, config_b)
            recommendations = self._generate_cross_firewall_recommendations(config_a, config_b, differences)
            compliance_gaps = self._identify_compliance_gaps(config_a, config_b)
            
            return PolicyComparisonResult(
                firewall_a_id=config_a.id,
                firewall_b_id=config_b.id,
                parity_matrix=parity_matrix,
                differences=differences,
                recommendations=recommendations,
                compliance_gaps=compliance_gaps
            )
        except Exception as e:
            logger.error(f"Error comparing firewalls {config_a.id} and {config_b.id}: {str(e)}")
            raise AnalyzerError(f"Failed to compare firewalls {config_a.id} and {config_b.id}: {str(e)}")

    def check_compliance(self, config: FirewallConfig, standards: List[str]) -> Dict[str, Any]:
        """
        Check firewall configuration against compliance standards.
        
        Args:
            config: Firewall configuration to check
            standards: List of compliance standards to check against
            
        Returns:
            Compliance check results
        """
        try:
            compliance_results = {}
            for standard in standards:
                compliance_results[standard] = self._check_standard_compliance(config, standard)
            
            return {
                "firewall_id": config.id,
                "standards": compliance_results,
                "overall_compliance": self._calculate_overall_compliance(compliance_results)
            }
        except Exception as e:
            logger.error(f"Error checking compliance for firewall {config.id}: {str(e)}")
            raise AnalyzerError(f"Failed to check compliance for firewall {config.id}: {str(e)}")

    def _find_inconsistencies(self, config: FirewallConfig) -> List[Dict[str, Any]]:
        """Find internal inconsistencies within a single firewall configuration."""
        inconsistencies = []
        
        # Check for duplicate policies
        policy_signatures = {}
        for i, policy in enumerate(config.policies):
            signature = (
                tuple(sorted(policy.get("srcaddr", []))),
                tuple(sorted(policy.get("dstaddr", []))),
                tuple(sorted(policy.get("service", []))),
                policy.get("action", "")
            )
            
            if signature in policy_signatures:
                inconsistencies.append({
                    "type": "duplicate_policy",
                    "policy_ids": [policy_signatures[signature], i],
                    "description": f"Duplicate policies found with same source, destination, service and action"
                })
            else:
                policy_signatures[signature] = i
                
        # Check for conflicting policies (allow followed by deny for same traffic)
        for i in range(len(config.policies) - 1):
            policy_a = config.policies[i]
            for j in range(i + 1, len(config.policies)):
                policy_b = config.policies[j]
                
                if (self._policies_overlap(policy_a, policy_b) and 
                    policy_a.get("action") == "accept" and 
                    policy_b.get("action") == "deny"):
                    inconsistencies.append({
                        "type": "conflicting_policies",
                        "policy_ids": [i, j],
                        "description": f"Allow policy {i} followed by deny policy {j} for overlapping traffic"
                    })
        
        return inconsistencies

    def _policies_overlap(self, policy_a: Dict[str, Any], policy_b: Dict[str, Any]) -> bool:
        """Check if two policies overlap in their scope."""
        # Simplified overlap check - in a real implementation, this would need
        # to check if the address and service objects actually overlap
        
        # Enhanced overlap detection
        src_overlap = self._check_address_overlap(
            policy_a.get("srcaddr", []), 
            policy_b.get("srcaddr", [])
        )
                      
        dst_overlap = self._check_address_overlap(
            policy_a.get("dstaddr", []), 
            policy_b.get("dstaddr", [])
        )
                      
        svc_overlap = self._check_service_overlap(
            policy_a.get("service", []), 
            policy_b.get("service", [])
        )
        
        return src_overlap and dst_overlap and svc_overlap

    def _check_address_overlap(self, addr_list_a: List[str], addr_list_b: List[str]) -> bool:
        """Check if two address lists overlap."""
        # Handle special cases
        if "all" in addr_list_a or "all" in addr_list_b:
            return True
            
        # Check for direct matches
        if set(addr_list_a) & set(addr_list_b):
            return True
            
        # TODO: Implement actual IP/subnet overlap checking
        # This would require parsing address objects and checking CIDR overlaps
        return False

    def _check_service_overlap(self, svc_list_a: List[str], svc_list_b: List[str]) -> bool:
        """Check if two service lists overlap."""
        # Handle special cases
        if "ALL" in svc_list_a or "ALL" in svc_list_b:
            return True
            
        # Check for direct matches
        if set(svc_list_a) & set(svc_list_b):
            return True
            
        # TODO: Implement port/protocol overlap checking
        # This would require parsing service objects and checking port ranges
        return False

    def _generate_recommendations(self, config: FirewallConfig, inconsistencies: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on found inconsistencies."""
        recommendations = []
        
        duplicate_count = sum(1 for inc in inconsistencies if inc["type"] == "duplicate_policy")
        if duplicate_count > 0:
            recommendations.append(f"Remove {duplicate_count} duplicate policies to improve performance and maintainability")
            
        conflict_count = sum(1 for inc in inconsistencies if inc["type"] == "conflicting_policies")
        if conflict_count > 0:
            recommendations.append(f"Resolve {conflict_count} conflicting policies to ensure consistent policy enforcement")
            
        if len(config.policies) > 100:
            recommendations.append("Consider policy optimization as the rulebase exceeds 100 policies")
            
        # Add policy optimization recommendations
        recommendations.extend(self._generate_optimization_recommendations(config))
            
        return recommendations

    def _generate_optimization_recommendations(self, config: FirewallConfig) -> List[str]:
        """Generate policy optimization recommendations based on best practices."""
        recommendations = []
        
        # Check for overly permissive policies
        permissive_policies = [
            policy for policy in config.policies
            if ("all" in policy.get("srcaddr", []) or 
                "all" in policy.get("dstaddr", []) or
                "ALL" in policy.get("service", [])) and
               policy.get("action") == "accept"
        ]
        
        if len(permissive_policies) > 0:
            recommendations.append(
                f"Review {len(permissive_policies)} overly permissive policies that allow traffic from/to all sources/destinations"
            )
            
        # Check for disabled policies
        disabled_policies = [
            policy for policy in config.policies
            if policy.get("status") == "disable"
        ]
        
        if len(disabled_policies) > 5:
            recommendations.append(
                f"Clean up {len(disabled_policies)} disabled policies that are no longer in use"
            )
            
        # Check for policies without logging
        unlogged_policies = [
            policy for policy in config.policies
            if not policy.get("logtraffic") or policy.get("logtraffic") == "disable"
        ]
        
        if len(unlogged_policies) > len(config.policies) * 0.5:  # More than 50% unlogged
            recommendations.append(
                f"Enable logging on {len(unlogged_policies)} policies to improve security monitoring"
            )
            
        # Check for policy organization
        if not self._check_policy_ordering(config.policies):
            recommendations.append(
                "Review policy ordering to ensure more specific rules are placed before general rules"
            )
            
        return recommendations

    def _check_policy_ordering(self, policies: List[Dict[str, Any]]) -> bool:
        """Check if policies are reasonably ordered (specific before general)."""
        # This is a simplified check - in reality, this would need to analyze
        # the specificity of address and service objects
        return True  # Placeholder implementation

    def _calculate_compliance_score(self, config: FirewallConfig, inconsistencies: List[Dict[str, Any]]) -> float:
        """Calculate a compliance score based on inconsistencies."""
        if len(config.policies) == 0:
            return 100.0
            
        # Simple scoring algorithm - subtract points for each inconsistency
        score = 100.0 - (len(inconsistencies) * 5.0)
        return max(0.0, score)

    def _generate_parity_matrix(self, config_a: FirewallConfig, config_b: FirewallConfig) -> Dict[str, Any]:
        """Generate a policy parity matrix between two firewall configurations."""
        return {
            "total_policies_a": len(config_a.policies),
            "total_policies_b": len(config_b.policies),
            "vendor_a": config_a.vendor,
            "vendor_b": config_b.vendor,
            "policy_coverage_ratio": len(config_a.policies) / max(len(config_b.policies), 1)
        }

    def _find_differences(self, config_a: FirewallConfig, config_b: FirewallConfig) -> List[Dict[str, Any]]:
        """Find differences between two firewall configurations."""
        differences = []
        
        # Compare policy counts
        if len(config_a.policies) != len(config_b.policies):
            differences.append({
                "type": "policy_count_difference",
                "firewall_a_count": len(config_a.policies),
                "firewall_b_count": len(config_b.policies),
                "description": f"Policy count differs: {len(config_a.policies)} vs {len(config_b.policies)}"
            })
            
        # Compare object counts
        if len(config_a.objects) != len(config_b.objects):
            differences.append({
                "type": "object_count_difference",
                "firewall_a_count": len(config_a.objects),
                "firewall_b_count": len(config_b.objects),
                "description": f"Object count differs: {len(config_a.objects)} vs {len(config_b.objects)}"
            })
            
        return differences

    def _generate_cross_firewall_recommendations(
        self, 
        config_a: FirewallConfig, 
        config_b: FirewallConfig, 
        differences: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate recommendations for cross-firewall policy alignment."""
        recommendations = []
        
        for diff in differences:
            if diff["type"] == "policy_count_difference":
                recommendations.append(
                    f"Align policy counts between {config_a.vendor} ({diff['firewall_a_count']} policies) " +
                    f"and {config_b.vendor} ({diff['firewall_b_count']} policies)"
                )
            elif diff["type"] == "object_count_difference":
                recommendations.append(
                    f"Standardize objects between {config_a.vendor} ({diff['firewall_a_count']} objects) " +
                    f"and {config_b.vendor} ({diff['firewall_b_count']} objects)"
                )
                
        return recommendations

    def _identify_compliance_gaps(self, config_a: FirewallConfig, config_b: FirewallConfig) -> List[Dict[str, Any]]:
        """Identify compliance gaps between two firewall configurations."""
        gaps = []
        
        # Check if one firewall has significantly fewer policies than the other
        if len(config_a.policies) > 0 and len(config_b.policies) > 0:
            ratio = min(len(config_a.policies), len(config_b.policies)) / max(len(config_a.policies), len(config_b.policies))
            if ratio < 0.8:  # More than 20% difference
                gaps.append({
                    "type": "policy_coverage_gap",
                    "description": f"Significant policy count difference suggests potential coverage gap",
                    "severity": "medium"
                })
                
        return gaps

    def _check_standard_compliance(self, config: FirewallConfig, standard: str) -> Dict[str, Any]:
        """Check compliance against a specific standard."""
        findings = []
        score = 100.0
        
        # Map standards to checking functions
        standard_checks = {
            "PCI-DSS": self._check_pci_dss_compliance,
            "HIPAA": self._check_hipaa_compliance,
            "GDPR": self._check_gdpr_compliance,
            "ISO27001": self._check_iso27001_compliance
        }
        
        # Perform standard-specific checks
        if standard in standard_checks:
            findings = standard_checks[standard](config)
            score = max(0.0, 100.0 - (len(findings) * 10.0))  # Deduct 10 points per finding
        
        return {
            "standard": standard,
            "compliant": len(findings) == 0,
            "findings": findings,
            "score": score
        }

    def _check_pci_dss_compliance(self, config: FirewallConfig) -> List[Dict[str, Any]]:
        """Check compliance with PCI DSS requirements."""
        findings = []
        
        # Check for logging on all policies
        for i, policy in enumerate(config.policies):
            if not policy.get("logtraffic") or policy.get("logtraffic") == "disable":
                findings.append({
                    "requirement": "PCI DSS 10.2.1",
                    "description": f"Policy {policy.get('id')} does not have logging enabled",
                    "severity": "high",
                    "recommendation": "Enable logging for all policies handling cardholder data"
                })
                
        # Check for restrictive default deny policies
        has_default_deny = any(
            policy.get("action") == "deny" and 
            "all" in policy.get("srcaddr", []) and 
            "all" in policy.get("dstaddr", []) and
            "ALL" in policy.get("service", [])
            for policy in config.policies
        )
        
        if not has_default_deny:
            findings.append({
                "requirement": "PCI DSS 1.2.1",
                "description": "No default deny policy found",
                "severity": "medium",
                "recommendation": "Implement a default deny policy as the last rule"
            })
            
        return findings

    def _check_hipaa_compliance(self, config: FirewallConfig) -> List[Dict[str, Any]]:
        """Check compliance with HIPAA requirements."""
        findings = []
        
        # Check for encryption policies
        encrypted_traffic = any(
            "SSL" in str(policy.get("service", [])) or
            "HTTPS" in str(policy.get("service", [])) or
            "IPSEC" in str(policy.get("service", []))
            for policy in config.policies
        )
        
        if not encrypted_traffic:
            findings.append({
                "requirement": "HIPAA Security Rule",
                "description": "No encryption policies detected for sensitive data",
                "severity": "medium",
                "recommendation": "Implement encryption for transmission of electronic protected health information"
            })
            
        return findings

    def _check_gdpr_compliance(self, config: FirewallConfig) -> List[Dict[str, Any]]:
        """Check compliance with GDPR requirements."""
        findings = []
        
        # Check for privacy-related policies
        privacy_policies = any(
            "privacy" in policy.get("comments", "").lower() or
            "gdpr" in policy.get("comments", "").lower()
            for policy in config.policies
        )
        
        if not privacy_policies:
            findings.append({
                "requirement": "GDPR Article 25",
                "description": "No privacy-related policies identified",
                "severity": "low",
                "recommendation": "Implement data protection policies aligned with privacy by design principles"
            })
            
        return findings

    def _check_iso27001_compliance(self, config: FirewallConfig) -> List[Dict[str, Any]]:
        """Check compliance with ISO 27001 requirements."""
        findings = []
        
        # Check for access control policies
        access_control_policies = [
            policy for policy in config.policies 
            if policy.get("action") == "accept" and 
            ("admin" in str(policy.get("srcaddr", [])).lower() or
             "management" in str(policy.get("dstaddr", [])).lower())
        ]
        
        if not access_control_policies:
            findings.append({
                "requirement": "ISO 27001 A.9.2",
                "description": "No specific access control policies for administrative functions",
                "severity": "medium",
                "recommendation": "Implement specific access control policies for administrative functions"
            })
            
        return findings

    def _calculate_overall_compliance(self, compliance_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall compliance score."""
        scores = [result["score"] for result in compliance_results.values()]
        if not scores:
            return {"score": 100.0, "status": "compliant"}
            
        avg_score = sum(scores) / len(scores)
        status = "compliant" if avg_score >= 80.0 else "non-compliant"
        
        return {
            "score": avg_score,
            "status": status
        }