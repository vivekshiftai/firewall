"""
Multi-firewall analysis service.
"""
from typing import List, Dict, Any, Union
import uuid
from datetime import datetime
import json

from app.parsers.factory import ParserFactory
from app.analyzers.policy_analyzer import PolicyAnalyzer
from app.core.policy_matcher import PolicyMatcher
from app.core.coverage_analyzer import CoverageAnalyzer
from app.core.conflict_detector import ConflictDetector
from app.core.normalizers import NormalizationEngine
from app.core.report_generator import ReportGenerator
from app.vendors.abstract import ParsedConfig, NormalizedPolicy
from app.models.cross_firewall import (
    CrossFirewallAnalysisReport, 
    PolicyMatch, 
    PolicyParity, 
    CrossFirewallGap, 
    EnforcementCapabilityMatrix,
    SingleFirewallAnalysis,
    ComparisonResults
)
from app.models.base import FirewallConfig


class MultiFirewallAnalysisService:
    """Service for multi-firewall analysis operations."""

    def __init__(self):
        """Initialize all parsers, analyzers, normalizers, matchers."""
        self.parser_factory = ParserFactory()
        self.policy_analyzer = PolicyAnalyzer()
        self.policy_matcher = PolicyMatcher()
        self.coverage_analyzer = CoverageAnalyzer()
        self.conflict_detector = ConflictDetector()
        self.normalization_engine = NormalizationEngine()
        self.report_generator = ReportGenerator()
        
        # In-memory storage for analysis results (in a real app, this would be a database)
        self.analysis_storage = {}

    def run_complete_multi_firewall_analysis(
        self,
        firewall1_config: dict,
        firewall1_vendor: str,
        firewall2_config: dict,
        firewall2_vendor: str
    ) -> CrossFirewallAnalysisReport:
        """
        Run complete multi-firewall analysis.
        
        Args:
            firewall1_config: First firewall configuration
            firewall1_vendor: First firewall vendor
            firewall2_config: Second firewall configuration
            firewall2_vendor: Second firewall vendor
            
        Returns:
            Complete cross-firewall analysis report
        """
        try:
            # a. Parse both configs (vendor-specific parsers)
            parser1 = self.parser_factory.create_parser(firewall1_vendor)
            parsed_config1 = parser1.parse_config(firewall1_config)
            
            parser2 = self.parser_factory.create_parser(firewall2_vendor)
            parsed_config2 = parser2.parse_config(firewall2_config)
            
            # b. Analyze each for internal inconsistencies
            fortinet_inconsistencies = self.policy_analyzer.analyze_single_firewall(
                FirewallConfig(vendor=firewall1_vendor, config=firewall1_config)
            ).inconsistencies
            
            zscaler_inconsistencies = self.policy_analyzer.analyze_single_firewall(
                FirewallConfig(vendor=firewall2_vendor, config=firewall2_config)
            ).inconsistencies
            
            # c. Normalize policies from both
            normalized_config1 = self.normalization_engine.normalize_config(parsed_config1)
            normalized_config2 = self.normalization_engine.normalize_config(parsed_config2)
            
            fortinet_policies = [NormalizedPolicy(**policy) for policy in normalized_config1.policies]
            zscaler_policies = [NormalizedPolicy(**policy) for policy in normalized_config2.policies]
            
            # d. Match equivalent policies
            matches = self.policy_matcher.match_policies(fortinet_policies, zscaler_policies)
            
            # e. Find coverage gaps
            coverage = self.coverage_analyzer.analyze_coverage(matches, fortinet_policies, zscaler_policies)
            gaps = self.coverage_analyzer.find_coverage_gaps(matches)
            
            # f. Detect conflicts
            conflicts = self.conflict_detector.detect_conflicts(matches, fortinet_policies, zscaler_policies)
            
            # g. Build enforcement capability matrix
            capability_matrix = self.coverage_analyzer.build_enforcement_capability_matrix(
                parsed_config1, parsed_config2
            )
            
            # h. Generate recommendations
            temp_report = CrossFirewallAnalysisReport(
                analysis_id="temp",
                timestamp=datetime.utcnow(),
                fortinet_config_id=normalized_config1.config_id,
                zscaler_config_id=normalized_config2.config_id,
                fortinet_inconsistencies=fortinet_inconsistencies,
                zscaler_inconsistencies=zscaler_inconsistencies,
                policy_matches=matches,
                cross_firewall_gaps=conflicts,
                policy_parity=coverage,
                enforcement_matrix=capability_matrix,
                standardization_recommendations=[],
                overall_parity_score=coverage.parity_score
            )
            
            recommendations = self.report_generator.generate_standardization_recommendations(temp_report)
            
            # i. Save analysis to database
            analysis_id = str(uuid.uuid4())
            analysis_report = CrossFirewallAnalysisReport(
                analysis_id=analysis_id,
                timestamp=datetime.utcnow(),
                fortinet_config_id=normalized_config1.config_id,
                zscaler_config_id=normalized_config2.config_id,
                fortinet_inconsistencies=fortinet_inconsistencies,
                zscaler_inconsistencies=zscaler_inconsistencies,
                policy_matches=matches,
                cross_firewall_gaps=conflicts,
                policy_parity=coverage,
                enforcement_matrix=capability_matrix,
                standardization_recommendations=[rec["description"] for rec in recommendations],
                overall_parity_score=coverage.parity_score
            )
            
            # j. Return complete report
            self.save_multi_analysis(analysis_report)
            return analysis_report
            
        except Exception as e:
            raise Exception(f"Error in multi-firewall analysis: {str(e)}")

    def analyze_single_firewall(
        self,
        config: dict,
        vendor: str
    ) -> SingleFirewallAnalysis:
        """
        Analyze a single firewall for inconsistencies.
        
        Args:
            config: Firewall configuration
            vendor: Firewall vendor
            
        Returns:
            Single firewall analysis results
        """
        try:
            firewall_config = FirewallConfig(vendor=vendor, config=config)
            analysis_result = self.policy_analyzer.analyze_single_firewall(firewall_config)
            
            return SingleFirewallAnalysis(
                analysis_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                firewall_vendor=vendor,
                firewall_config_id="config_id_placeholder",
                inconsistencies=analysis_result.inconsistencies,
                total_policies=len(analysis_result.policies) if hasattr(analysis_result, 'policies') else 0,
                severity_distribution={}
            )
        except Exception as e:
            raise Exception(f"Error analyzing single firewall: {str(e)}")

    def compare_two_firewalls(
        self,
        policies1: List[NormalizedPolicy],
        policies2: List[NormalizedPolicy],
        vendor1: str,
        vendor2: str
    ) -> ComparisonResults:
        """
        Compare two firewalls.
        
        Args:
            policies1: First set of normalized policies
            policies2: Second set of normalized policies
            vendor1: First vendor name
            vendor2: Second vendor name
            
        Returns:
            Comparison results
        """
        try:
            matches = self.policy_matcher.match_policies(policies1, policies2)
            
            # Calculate coverage
            matched_policies = len([m for m in matches if m.match_type != "no_match"])
            coverage_1_to_2 = self.coverage_analyzer.calculate_coverage_percentage(
                len(policies1), matched_policies
            )
            coverage_2_to_1 = self.coverage_analyzer.calculate_coverage_percentage(
                len(policies2), matched_policies
            )
            
            return ComparisonResults(
                comparison_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                vendor1=vendor1,
                vendor2=vendor2,
                policy_matches=matches,
                coverage_percentage_1_to_2=coverage_1_to_2,
                coverage_percentage_2_to_1=coverage_2_to_1,
                total_matches=matched_policies,
                total_unmatched_1=len([m for m in matches if m.fortinet_policy_id and not m.zscaler_rule_id]),
                total_unmatched_2=len([m for m in matches if m.zscaler_rule_id and not m.fortinet_policy_id])
            )
        except Exception as e:
            raise Exception(f"Error comparing firewalls: {str(e)}")

    def generate_parity_metrics(
        self,
        comparison: ComparisonResults
    ) -> PolicyParity:
        """
        Generate parity metrics from comparison results.
        
        Args:
            comparison: Comparison results
            
        Returns:
            Policy parity metrics
        """
        try:
            # Calculate additional metrics
            gaps_count = comparison.total_unmatched_1 + comparison.total_unmatched_2
            conflicts_count = 0  # Would be calculated in a full implementation
            
            parity_score = self.coverage_analyzer.calculate_parity_score(
                comparison.coverage_percentage_1_to_2,
                comparison.coverage_percentage_2_to_1,
                gaps_count,
                conflicts_count
            )
            
            return PolicyParity(
                parity_id=str(uuid.uuid4()),
                total_policies_f1=0,  # Would be calculated in a full implementation
                total_policies_f2=0,  # Would be calculated in a full implementation
                matched_policies=comparison.total_matches,
                coverage_percentage_f1_to_f2=comparison.coverage_percentage_1_to_2,
                coverage_percentage_f2_to_f1=comparison.coverage_percentage_2_to_1,
                gaps_found=gaps_count,
                conflicts_found=conflicts_count,
                enforcement_gaps=0,  # Would be calculated in a full implementation
                parity_score=parity_score
            )
        except Exception as e:
            raise Exception(f"Error generating parity metrics: {str(e)}")

    def save_multi_analysis(
        self,
        analysis: CrossFirewallAnalysisReport
    ) -> str:
        """
        Save multi-firewall analysis to storage.
        
        Args:
            analysis: Analysis report to save
            
        Returns:
            Analysis ID
        """
        try:
            self.analysis_storage[analysis.analysis_id] = analysis
            return analysis.analysis_id
        except Exception as e:
            raise Exception(f"Error saving analysis: {str(e)}")

    def get_multi_analysis(
        self,
        analysis_id: str
    ) -> CrossFirewallAnalysisReport:
        """
        Get multi-firewall analysis by ID.
        
        Args:
            analysis_id: Analysis ID
            
        Returns:
            Cross-firewall analysis report
        """
        try:
            if analysis_id not in self.analysis_storage:
                raise Exception(f"Analysis not found: {analysis_id}")
                
            return self.analysis_storage[analysis_id]
        except Exception as e:
            raise Exception(f"Error retrieving analysis: {str(e)}")

    def list_multi_analyses(self) -> List[Dict]:
        """
        List all multi-firewall analyses.
        
        Returns:
            List of analysis summaries
        """
        try:
            analyses = []
            for analysis_id, analysis in self.analysis_storage.items():
                analyses.append({
                    "analysis_id": analysis_id,
                    "timestamp": analysis.timestamp.isoformat() if hasattr(analysis, 'timestamp') else "",
                    "fortinet_config_id": analysis.fortinet_config_id,
                    "zscaler_config_id": analysis.zscaler_config_id,
                    "overall_parity_score": analysis.overall_parity_score
                })
            return analyses
        except Exception as e:
            raise Exception(f"Error listing analyses: {str(e)}")

    def export_analysis(
        self,
        analysis_id: str,
        format: str,  # json, pdf, csv
        export_type: str  # comparison, mapping, full
    ) -> Union[str, bytes]:
        """
        Export analysis in specified format.
        
        Args:
            analysis_id: Analysis ID
            format: Export format (json, pdf, csv)
            export_type: Export type (comparison, mapping, full)
            
        Returns:
            Exported content as string or bytes
        """
        try:
            analysis = self.get_multi_analysis(analysis_id)
            
            if format.lower() == "json":
                return json.dumps(analysis.dict(), indent=2)
            elif format.lower() == "pdf":
                return self.report_generator.generate_pdf_multi_firewall(analysis)
            elif format.lower() == "csv":
                if export_type.lower() == "mapping":
                    return self.report_generator.generate_csv_policy_mappings(analysis.policy_matches)
                else:
                    raise Exception("CSV export only supported for mapping type")
            else:
                raise Exception(f"Unsupported export format: {format}")
        except Exception as e:
            raise Exception(f"Error exporting analysis: {str(e)}")

    def validate_vendor_config(
        self,
        config: dict,
        vendor: str
    ) -> Dict[str, Any]:
        """
        Validate vendor configuration against schema.
        
        Args:
            config: Configuration to validate
            vendor: Vendor name
            
        Returns:
            Validation result
        """
        try:
            parser = self.parser_factory.create_parser(vendor)
            firewall_config = parser.parse_config(config)
            is_valid = parser.validate_config(firewall_config)
            
            return {
                "valid": is_valid,
                "vendor": vendor,
                "errors": [] if is_valid else ["Configuration validation failed"]
            }
        except Exception as e:
            return {
                "valid": False,
                "vendor": vendor,
                "errors": [str(e)]
            }