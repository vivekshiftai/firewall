"""
Analysis service for cross-firewall policy analysis.
"""
from typing import List, Dict, Any
from datetime import datetime
import uuid

from app.vendors.abstract import NormalizedPolicy
from app.models.cross_firewall import ComparisonResults
from app.core.policy_matcher import PolicyMatcher
from app.core.semantic_policy_matcher import SemanticPolicyMatcher
from app.core.coverage_analyzer import CoverageAnalyzer
from app.core.conflict_detector import ConflictDetector


class AnalysisService:
    """Service layer for cross-firewall policy analysis."""
    
    def __init__(self):
        """Initialize the analysis service."""
        self.policy_matcher = PolicyMatcher()
        self.semantic_policy_matcher = SemanticPolicyMatcher()
        self.coverage_analyzer = CoverageAnalyzer()
        self.conflict_detector = ConflictDetector()

    def compare_firewalls(
        self,
        policies1: List[NormalizedPolicy],
        policies2: List[NormalizedPolicy],
        vendor1: str,
        vendor2: str,
        use_semantic_matching: bool = True
    ) -> ComparisonResults:
        """
        Compare two firewalls.
        
        Args:
            policies1: First set of normalized policies
            policies2: Second set of normalized policies
            vendor1: First vendor name
            vendor2: Second vendor name
            use_semantic_matching: Whether to use semantic matching or traditional matching
            
        Returns:
            Comparison results
        """
        try:
            # Match policies using selected approach
            if use_semantic_matching:
                matches = self.semantic_policy_matcher.match_policies(policies1, policies2)
            else:
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
                total_unmatched_2=len([m for m in matches if m.zscaler_rule_id and not m.fortinet_policy_id]),
                matching_approach="semantic" if use_semantic_matching else "traditional"
            )
        except Exception as e:
            raise Exception(f"Error comparing firewalls: {str(e)}")

    def find_policy_clusters(
        self,
        policies: List[NormalizedPolicy],
        similarity_threshold: float = 0.8
    ) -> List[List[NormalizedPolicy]]:
        """
        Cluster policies based on semantic similarity.
        
        Args:
            policies: List of policies to cluster
            similarity_threshold: Minimum similarity to consider policies in same cluster
            
        Returns:
            List of policy clusters
        """
        try:
            return self.semantic_policy_matcher.cluster_policies_by_semantic_similarity(
                policies, similarity_threshold
            )
        except Exception as e:
            raise Exception(f"Error clustering policies: {str(e)}")

    def find_similar_policies(
        self,
        target_policy: NormalizedPolicy,
        candidate_policies: List[NormalizedPolicy],
        threshold: float = 0.7
    ) -> List[tuple]:
        """
        Find policies that are semantically similar to a target policy.
        
        Args:
            target_policy: The policy to find matches for
            candidate_policies: List of policies to compare against
            threshold: Minimum similarity score to consider a match
            
        Returns:
            List of tuples (policy, similarity_score) for policies above threshold
        """
        try:
            return self.semantic_policy_matcher.find_semantically_similar_policies(
                target_policy, candidate_policies, threshold
            )
        except Exception as e:
            raise Exception(f"Error finding similar policies: {str(e)}")
