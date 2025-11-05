"""
Cross-firewall policy matching engine.
"""
from typing import List, Dict, Any
from app.models.cross_firewall import PolicyMatch
from app.vendors.abstract import NormalizedPolicy


class PolicyMatcher:
    """Engine for matching policies across different firewall vendors."""

    def match_policies(
        self,
        fortinet_policies: List[NormalizedPolicy],
        zscaler_policies: List[NormalizedPolicy]
    ) -> List[PolicyMatch]:
        """
        Match Fortinet and Zscaler policies based on similarity.
        
        Args:
            fortinet_policies: List of normalized Fortinet policies
            zscaler_policies: List of normalized Zscaler policies
            
        Returns:
            List of policy matches
        """
        matches = []
        
        # For each Fortinet policy, find the best matching Zscaler policy
        for f_policy in fortinet_policies:
            best_match = None
            best_score = 0.0
            
            # Compare with each Zscaler policy
            for z_policy in zscaler_policies:
                similarity_score = self.calculate_policy_similarity(f_policy, z_policy)
                
                # If this is the best match so far and above threshold
                if similarity_score > best_score and similarity_score >= 0.7:
                    best_score = similarity_score
                    best_match = z_policy
            
            # Create PolicyMatch based on the best match found
            if best_match and best_score >= 0.7:
                # Determine match type based on score
                if best_score >= 0.95:
                    match_type = "exact"
                elif best_score >= 0.8:
                    match_type = "semantic"
                elif best_score >= 0.7:
                    match_type = "partial"
                else:
                    match_type = "no_match"
                
                # Calculate match details
                source_similarity = self.match_sources(f_policy.source_addresses, best_match.source_addresses)
                dest_similarity = self.match_destinations(f_policy.destination_addresses, best_match.destination_addresses)
                service_similarity = self.match_services(f_policy.services, best_match.services)
                actions_equivalent = self.are_actions_equivalent(f_policy.action, best_match.action)
                
                match = PolicyMatch(
                    fortinet_policy_id=f_policy.id,
                    zscaler_rule_id=best_match.id,
                    match_type=match_type,
                    confidence_score=best_score,
                    source_match=f"Source similarity: {source_similarity:.2f}",
                    dest_match=f"Destination similarity: {dest_similarity:.2f}",
                    service_match=f"Service similarity: {service_similarity:.2f}",
                    action_match=f"Actions equivalent: {actions_equivalent}",
                    differences=self._identify_differences(f_policy, best_match)
                )
                matches.append(match)
            else:
                # No match found
                match = PolicyMatch(
                    fortinet_policy_id=f_policy.id,
                    zscaler_rule_id=None,
                    match_type="no_match",
                    confidence_score=0.0,
                    source_match="No matching source",
                    dest_match="No matching destination",
                    service_match="No matching service",
                    action_match="No matching action",
                    differences=["Policy unique to Fortinet firewall"]
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
                    source_match="No matching source",
                    dest_match="No matching destination",
                    service_match="No matching service",
                    action_match="No matching action",
                    differences=["Policy unique to Zscaler firewall"]
                )
                matches.append(match)
        
        return matches

    def calculate_policy_similarity(
        self,
        policy1: NormalizedPolicy,
        policy2: NormalizedPolicy
    ) -> float:
        """
        Calculate similarity score between two policies.
        
        Scoring (0-1):
        - Source match (0.25 weight)
        - Dest match (0.25 weight)
        - Service match (0.25 weight)
        - Action match (0.25 weight)
        
        Args:
            policy1: First normalized policy
            policy2: Second normalized policy
            
        Returns:
            Similarity score between 0 and 1
        """
        # Calculate individual component scores
        source_score = self.match_sources(policy1.source_addresses, policy2.source_addresses)
        dest_score = self.match_destinations(policy1.destination_addresses, policy2.destination_addresses)
        service_score = self.match_services(policy1.services, policy2.services)
        action_score = 1.0 if self.are_actions_equivalent(policy1.action, policy2.action) else 0.0
        
        # Calculate weighted sum
        weighted_sum = (
            source_score * 0.25 +
            dest_score * 0.25 +
            service_score * 0.25 +
            action_score * 0.25
        )
        
        return weighted_sum

    def match_sources(self, sources1: List[str], sources2: List[str]) -> float:
        """
        Compare source entities and return similarity score.
        
        Args:
            sources1: List of source entities from first policy
            sources2: List of source entities from second policy
            
        Returns:
            Similarity score between 0 and 1
        """
        if not sources1 and not sources2:
            return 1.0  # Both empty, considered identical
        
        if not sources1 or not sources2:
            return 0.0  # One empty, no match
        
        # Convert to sets for easier comparison
        set1 = set(sources1)
        set2 = set(sources2)
        
        # Handle special cases
        if "all" in set1 or "any" in set1:
            set1 = {"0.0.0.0/0"}  # Treat "all" as full IP range
        if "all" in set2 or "any" in set2:
            set2 = {"0.0.0.0/0"}  # Treat "all" as full IP range
        
        # Calculate overlap
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        if union == 0:
            return 1.0  # Both empty sets
            
        return intersection / union

    def match_destinations(self, dests1: List[str], dests2: List[str]) -> float:
        """
        Compare destination entities and return similarity score.
        
        Args:
            dests1: List of destination entities from first policy
            dests2: List of destination entities from second policy
            
        Returns:
            Similarity score between 0 and 1
        """
        if not dests1 and not dests2:
            return 1.0  # Both empty, considered identical
        
        if not dests1 or not dests2:
            return 0.0  # One empty, no match
        
        # Convert to sets for easier comparison
        set1 = set(dests1)
        set2 = set(dests2)
        
        # Handle special cases
        if "all" in set1 or "any" in set1:
            set1 = {"0.0.0.0/0"}  # Treat "all" as full IP range
        if "all" in set2 or "any" in set2:
            set2 = {"0.0.0.0/0"}  # Treat "all" as full IP range
        
        # Calculate overlap
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        if union == 0:
            return 1.0  # Both empty sets
            
        return intersection / union

    def match_services(self, services1: List[str], services2: List[str]) -> float:
        """
        Compare services and return overlap percentage.
        
        Args:
            services1: List of services from first policy
            services2: List of services from second policy
            
        Returns:
            Overlap percentage between 0 and 1
        """
        if not services1 and not services2:
            return 1.0  # Both empty, considered identical
        
        if not services1 or not services2:
            return 0.0  # One empty, no match
        
        # Convert to sets for easier comparison
        set1 = set(services1)
        set2 = set(services2)
        
        # Handle special cases
        if "ALL" in set1 or "any" in set1:
            set1 = {"all_protocols"}  # Treat "ALL" as all protocols
        if "ALL" in set2 or "any" in set2:
            set2 = {"all_protocols"}  # Treat "ALL" as all protocols
        
        # Calculate overlap
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        if union == 0:
            return 1.0  # Both empty sets
            
        return intersection / union

    def are_actions_equivalent(self, action1: str, action2: str) -> bool:
        """
        Check if two actions are equivalent.
        
        Args:
            action1: First action
            action2: Second action
            
        Returns:
            True if actions are equivalent, False otherwise
        """
        action1_lower = action1.lower()
        action2_lower = action2.lower()
        
        # Direct matches
        if action1_lower == action2_lower:
            return True
            
        # Equivalent mappings
        equivalent_actions = {
            "allow": ["accept"],
            "deny": ["reject", "drop"],
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

    def find_unmatched_policies(
        self,
        all_policies: List[NormalizedPolicy],
        matches: List[PolicyMatch]
    ) -> List[NormalizedPolicy]:
        """
        Find policies with no matches.
        
        Args:
            all_policies: List of all normalized policies
            matches: List of policy matches
            
        Returns:
            List of unmatched policies
        """
        # Get IDs of matched policies
        matched_ids = set()
        for match in matches:
            if match.match_type != "no_match":
                if match.fortinet_policy_id:
                    matched_ids.add(match.fortinet_policy_id)
                if match.zscaler_rule_id:
                    matched_ids.add(match.zscaler_rule_id)
        
        # Find policies that are not matched
        unmatched_policies = []
        for policy in all_policies:
            if policy.id not in matched_ids:
                unmatched_policies.append(policy)
                
        return unmatched_policies

    def _identify_differences(self, policy1: NormalizedPolicy, policy2: NormalizedPolicy) -> List[str]:
        """
        Identify specific differences between two policies.
        
        Args:
            policy1: First policy
            policy2: Second policy
            
        Returns:
            List of difference descriptions
        """
        differences = []
        
        # Compare sources
        if set(policy1.source_addresses) != set(policy2.source_addresses):
            differences.append("Source addresses differ")
            
        # Compare destinations
        if set(policy1.destination_addresses) != set(policy2.destination_addresses):
            differences.append("Destination addresses differ")
            
        # Compare services
        if set(policy1.services) != set(policy2.services):
            differences.append("Services differ")
            
        # Compare actions
        if not self.are_actions_equivalent(policy1.action, policy2.action):
            differences.append("Actions differ")
            
        return differences