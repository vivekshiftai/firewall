"""
Semantic policy matcher using embedding-based similarity.
"""
from typing import List, Dict, Any
import numpy as np
from app.models.cross_firewall import PolicyMatch
from app.vendors.abstract import NormalizedPolicy
from utils.embeddings import AdvancedPolicyEmbedder


class SemanticPolicyMatcher:
    """Enhanced policy matcher using semantic embeddings for cross-vendor policy analysis."""
    
    def __init__(self):
        """Initialize the semantic policy matcher."""
        self.embedder = AdvancedPolicyEmbedder()

    def match_policies(
        self,
        fortinet_policies: List[NormalizedPolicy],
        zscaler_policies: List[NormalizedPolicy]
    ) -> List[PolicyMatch]:
        """
        Match Fortinet and Zscaler policies based on semantic similarity using embeddings.
        
        Args:
            fortinet_policies: List of normalized Fortinet policies
            zscaler_policies: List of normalized Zscaler policies
            
        Returns:
            List of policy matches with semantic similarity scores
        """
        matches = []
        
        # Calculate similarity matrix for all policy pairs
        similarity_matrix = self.embedder.calculate_batch_similarity(
            fortinet_policies, zscaler_policies
        )
        
        # For each Fortinet policy, find the best matching Zscaler policy
        for i, f_policy in enumerate(fortinet_policies):
            best_match_idx = None
            best_score = 0.0
            
            # Find the best match among Zscaler policies
            for j, z_policy in enumerate(zscaler_policies):
                similarity_score = similarity_matrix[i][j]
                
                # If this is the best match so far and above threshold
                if similarity_score > best_score and similarity_score >= 0.6:  # Lowered threshold for semantic matching
                    best_score = similarity_score
                    best_match_idx = j
            
            # Create PolicyMatch based on the best match found
            if best_match_idx is not None and best_score >= 0.6:
                best_match = zscaler_policies[best_match_idx]
                
                # Determine match type based on score
                if best_score >= 0.9:
                    match_type = "exact"
                elif best_score >= 0.75:
                    match_type = "semantic"
                elif best_score >= 0.6:
                    match_type = "partial"
                else:
                    match_type = "no_match"
                
                match = PolicyMatch(
                    fortinet_policy_id=f_policy.id,
                    zscaler_rule_id=best_match.id,
                    match_type=match_type,
                    confidence_score=float(best_score),
                    source_match=f"Semantic similarity: {best_score:.3f}",
                    dest_match="Computed using embedding-based analysis",
                    service_match="Computed using embedding-based analysis",
                    action_match="Computed using embedding-based analysis",
                    differences=self._identify_semantic_differences(f_policy, best_match)
                )
                matches.append(match)
            else:
                # No match found
                match = PolicyMatch(
                    fortinet_policy_id=f_policy.id,
                    zscaler_rule_id=None,
                    match_type="no_match",
                    confidence_score=0.0,
                    source_match="No semantically similar policy found",
                    dest_match="No semantically similar policy found",
                    service_match="No semantically similar policy found",
                    action_match="No semantically similar policy found",
                    differences=["Policy unique to Fortinet firewall or below similarity threshold"]
                )
                matches.append(match)
        
        # Also check for Zscaler policies that don't have Fortinet matches
        matched_zscaler_ids = {match.zscaler_rule_id for match in matches if match.zscaler_rule_id}
        for z_policy in zscaler_policies:
            if z_policy.id not in matched_zscaler_ids:
                match = PolicyMatch(
                    fortinet_policy_id=None,
                    zscaler_rule_id=z_policy.id,
                    match_type="no_match",
                    confidence_score=0.0,
                    source_match="No semantically similar policy found",
                    dest_match="No semantically similar policy found",
                    service_match="No semantically similar policy found",
                    action_match="No semantically similar policy found",
                    differences=["Policy unique to Zscaler firewall or below similarity threshold"]
                )
                matches.append(match)
        
        return matches

    def calculate_policy_similarity(
        self,
        policy1: NormalizedPolicy,
        policy2: NormalizedPolicy
    ) -> float:
        """
        Calculate semantic similarity score between two policies using embeddings.
        
        Args:
            policy1: First normalized policy
            policy2: Second normalized policy
            
        Returns:
            Semantic similarity score between 0 and 1
        """
        return self.embedder.calculate_semantic_similarity(policy1, policy2)

    def _identify_semantic_differences(self, policy1: NormalizedPolicy, policy2: NormalizedPolicy) -> List[str]:
        """
        Identify semantic differences between two policies based on their embeddings.
        
        Args:
            policy1: First policy
            policy2: Second policy
            
        Returns:
            List of semantic difference descriptions
        """
        differences = []
        
        # Calculate component-wise similarities
        source_similarity = self.embedder.calculate_semantic_similarity(
            NormalizedPolicy(
                id="temp1", name="temp1", 
                source_addresses=policy1.source_addresses,
                source_zones=policy1.source_zones
            ),
            NormalizedPolicy(
                id="temp2", name="temp2",
                source_addresses=policy2.source_addresses,
                source_zones=policy2.source_zones
            )
        )
        
        dest_similarity = self.embedder.calculate_semantic_similarity(
            NormalizedPolicy(
                id="temp1", name="temp1",
                destination_addresses=policy1.destination_addresses,
                destination_zones=policy1.destination_zones
            ),
            NormalizedPolicy(
                id="temp2", name="temp2",
                destination_addresses=policy2.destination_addresses,
                destination_zones=policy2.destination_zones
            )
        )
        
        service_similarity = self.embedder.calculate_semantic_similarity(
            NormalizedPolicy(
                id="temp1", name="temp1",
                services=policy1.services
            ),
            NormalizedPolicy(
                id="temp2", name="temp2",
                services=policy2.services
            )
        )
        
        # Add differences based on low similarity scores
        if source_similarity < 0.5:
            differences.append(f"Source entities have low semantic similarity ({source_similarity:.3f})")
            
        if dest_similarity < 0.5:
            differences.append(f"Destination entities have low semantic similarity ({dest_similarity:.3f})")
            
        if service_similarity < 0.5:
            differences.append(f"Services have low semantic similarity ({service_similarity:.3f})")
            
        # Check action equivalence
        if not self._are_actions_semantically_equivalent(policy1.action, policy2.action):
            differences.append(f"Actions are not semantically equivalent: {policy1.action} vs {policy2.action}")
            
        # If no specific differences found but overall similarity is low, add general difference
        if not differences and self.calculate_policy_similarity(policy1, policy2) < 0.7:
            differences.append("Policies have low overall semantic similarity")
            
        return differences

    def _are_actions_semantically_equivalent(self, action1: str, action2: str) -> bool:
        """
        Check if two actions are semantically equivalent.
        
        Args:
            action1: First action
            action2: Second action
            
        Returns:
            True if actions are semantically equivalent, False otherwise
        """
        action1_lower = action1.lower()
        action2_lower = action2.lower()
        
        # Direct matches
        if action1_lower == action2_lower:
            return True
            
        # Semantic equivalence mappings
        equivalent_actions = {
            "allow": ["accept", "permit"],
            "deny": ["reject", "drop", "block"],
            "redirect": ["allow"]  # Redirect is a form of allow with modification
        }
        
        # Check if actions are equivalent
        if action1_lower in equivalent_actions:
            if action2_lower in equivalent_actions[action1_lower]:
                return True
                
        if action2_lower in equivalent_actions:
            if action1_lower in equivalent_actions[action2_lower]:
                return True
                
        return False

    def find_semantically_similar_policies(
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
        similar_policies = []
        
        for candidate in candidate_policies:
            similarity = self.calculate_policy_similarity(target_policy, candidate)
            if similarity >= threshold:
                similar_policies.append((candidate, similarity))
                
        # Sort by similarity score descending
        similar_policies.sort(key=lambda x: x[1], reverse=True)
        return similar_policies

    def cluster_policies_by_semantic_similarity(
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
        if not policies:
            return []
            
        clusters = []
        used_policies = set()
        
        for i, policy in enumerate(policies):
            if i in used_policies:
                continue
                
            # Start a new cluster with this policy
            cluster = [policy]
            used_policies.add(i)
            
            # Find similar policies to add to this cluster
            for j, other_policy in enumerate(policies):
                if j in used_policies or i == j:
                    continue
                    
                similarity = self.calculate_policy_similarity(policy, other_policy)
                if similarity >= similarity_threshold:
                    cluster.append(other_policy)
                    used_policies.add(j)
            
            clusters.append(cluster)
            
        return clusters