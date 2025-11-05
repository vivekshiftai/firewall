"""
Main policy analyzer for cross-firewall policy analysis.
"""
import logging
from typing import Dict, Any, List
from analyzers.base import BaseAnalyzer
from models.base import FirewallConfig, PolicyComparisonResult, ComplianceReport
from utils.embeddings import PolicyEmbedder
from utils.mapping import PolicyMapper

# Configure logging
logger = logging.getLogger(__name__)

class PolicyAnalyzer(BaseAnalyzer):
    """Main analyzer for firewall policy analysis."""

    def __init__(self):
        """Initialize the policy analyzer."""
        logger.info("Initializing PolicyAnalyzer")
        self.embedder = PolicyEmbedder()
        self.mapper = PolicyMapper()
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
            mapped_policies = self.mapper.map_policies(config_a.policies, config_b.policies)
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
