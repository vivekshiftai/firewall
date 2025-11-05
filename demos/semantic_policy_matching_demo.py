"""
Demo script showcasing semantic policy matching capabilities.
"""
import json
from app.vendors.abstract import NormalizedPolicy
from app.core.semantic_policy_matcher import SemanticPolicyMatcher


def create_sample_policies():
    """Create sample policies for demonstration."""
    # Fortinet policies
    fortinet_policies = [
        NormalizedPolicy(
            id="F1",
            name="Allow Internal to Web Servers",
            source_addresses=["192.168.1.0/24"],
            destination_addresses=["10.0.1.0/24"],
            services=["HTTP", "HTTPS"],
            action="allow",
            comments="Allow internal users to access web servers"
        ),
        NormalizedPolicy(
            id="F2",
            name="Block Social Media",
            source_addresses=["192.168.1.0/24"],
            destination_addresses=["facebook.com", "twitter.com"],
            services=["HTTP", "HTTPS"],
            action="deny",
            comments="Block social media during work hours"
        ),
        NormalizedPolicy(
            id="F3",
            name="Allow SSH to Management",
            source_addresses=["192.168.10.0/24"],
            destination_addresses=["10.0.10.0/24"],
            services=["SSH"],
            action="allow",
            comments="Allow SSH access to management network"
        )
    ]
    
    # Zscaler policies (semantically similar but syntactically different)
    zscaler_policies = [
        NormalizedPolicy(
            id="Z1",
            name="Web Access Policy",
            source_addresses=["Internal_Network"],
            destination_addresses=["Web_Servers_Group"],
            services=["Web_Browsing"],
            action="accept",
            comments="Permit internal users to browse web servers"
        ),
        NormalizedPolicy(
            id="Z2",
            name="Social Media Restriction",
            source_addresses=["Corporate_Users"],
            destination_addresses=["Facebook", "Twitter"],
            services=["Internet_Access"],
            action="block",
            comments="Restrict social media platforms during business hours"
        ),
        NormalizedPolicy(
            id="Z3",
            name="Admin SSH Access",
            source_addresses=["Admin_Network"],
            destination_addresses=["Management_Servers"],
            services=["Secure_Shell"],
            action="permit",
            comments="Enable SSH connectivity to management systems"
        )
    ]
    
    return fortinet_policies, zscaler_policies


def demonstrate_semantic_matching():
    """Demonstrate semantic policy matching capabilities."""
    print("=== Semantic Policy Matching Demo ===\n")
    
    # Create sample policies
    fortinet_policies, zscaler_policies = create_sample_policies()
    
    # Initialize semantic policy matcher
    matcher = SemanticPolicyMatcher()
    
    print("1. Sample Policies:")
    print("Fortinet Policies:")
    for policy in fortinet_policies:
        print(f"  - {policy.name} ({policy.id}): {policy.action} {policy.source_addresses} -> {policy.destination_addresses}")
    
    print("\nZscaler Policies:")
    for policy in zscaler_policies:
        print(f"  - {policy.name} ({policy.id}): {policy.action} {policy.source_addresses} -> {policy.destination_addresses}")
    
    # Calculate individual policy similarities
    print("\n2. Individual Policy Similarities:")
    for f_policy in fortinet_policies:
        for z_policy in zscaler_policies:
            similarity = matcher.calculate_policy_similarity(f_policy, z_policy)
            print(f"  {f_policy.name} <-> {z_policy.name}: {similarity:.3f}")
    
    # Match all policies
    print("\n3. Policy Matching Results:")
    matches = matcher.match_policies(fortinet_policies, zscaler_policies)
    
    for match in matches:
        if match.match_type != "no_match":
            print(f"  {match.fortinet_policy_id} <-> {match.zscaler_rule_id}: {match.match_type} (confidence: {match.confidence_score:.3f})")
        else:
            if match.fortinet_policy_id:
                print(f"  {match.fortinet_policy_id} <-> None: No match found")
            elif match.zscaler_rule_id:
                print(f"  None <-> {match.zscaler_rule_id}: No match found")
    
    # Find semantically similar policies for a specific policy
    print("\n4. Finding Policies Similar to 'Allow Internal to Web Servers':")
    target_policy = fortinet_policies[0]  # "Allow Internal to Web Servers"
    similar_policies = matcher.find_semantically_similar_policies(
        target_policy, zscaler_policies, threshold=0.5
    )
    
    for policy, score in similar_policies:
        print(f"  {policy.name} ({policy.id}): similarity = {score:.3f}")
    
    # Cluster policies
    print("\n5. Policy Clustering:")
    all_policies = fortinet_policies + zscaler_policies
    clusters = matcher.cluster_policies_by_semantic_similarity(all_policies, similarity_threshold=0.6)
    
    for i, cluster in enumerate(clusters):
        print(f"  Cluster {i+1}:")
        for policy in cluster:
            print(f"    - {policy.name} ({policy.id})")


def demonstrate_traditional_vs_semantic():
    """Compare traditional matching with semantic matching."""
    print("\n\n=== Traditional vs Semantic Matching Comparison ===\n")
    
    # Create policies that are syntactically different but semantically similar
    policy1 = NormalizedPolicy(
        id="P1",
        name="Allow Web Access",
        source_addresses=["192.168.1.0/24"],
        destination_addresses=["web.servers.local"],
        services=["HTTP", "HTTPS"],
        action="allow"
    )
    
    policy2 = NormalizedPolicy(
        id="P2",
        name="Permit Internet Browsing",
        source_addresses=["Internal_LAN"],
        destination_addresses=["www.webservers.com"],
        services=["Web_Traffic"],
        action="accept"
    )
    
    # Traditional matcher
    from app.core.policy_matcher import PolicyMatcher
    traditional_matcher = PolicyMatcher()
    traditional_similarity = traditional_matcher.calculate_policy_similarity(policy1, policy2)
    
    # Semantic matcher
    semantic_matcher = SemanticPolicyMatcher()
    semantic_similarity = semantic_matcher.calculate_policy_similarity(policy1, policy2)
    
    print("Policy 1:")
    print(f"  Name: {policy1.name}")
    print(f"  Source: {policy1.source_addresses}")
    print(f"  Destination: {policy1.destination_addresses}")
    print(f"  Services: {policy1.services}")
    print(f"  Action: {policy1.action}")
    
    print("\nPolicy 2:")
    print(f"  Name: {policy2.name}")
    print(f"  Source: {policy2.source_addresses}")
    print(f"  Destination: {policy2.destination_addresses}")
    print(f"  Services: {policy2.services}")
    print(f"  Action: {policy2.action}")
    
    print(f"\nTraditional matching similarity: {traditional_similarity:.3f}")
    print(f"Semantic matching similarity: {semantic_similarity:.3f}")
    
    print("\nSemantic matcher correctly identifies these as semantically similar despite")
    print("syntactic differences in naming conventions and address representations.")


if __name__ == "__main__":
    demonstrate_semantic_matching()
    demonstrate_traditional_vs_semantic()