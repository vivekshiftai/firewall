"""
Cross-firewall coverage analysis engine.
"""
from typing import List, Dict, Any
from app.models.cross_firewall import PolicyParity, CrossFirewallGap, EnforcementCapabilityMatrix, PolicyMatch
from app.vendors.abstract import NormalizedPolicy, ParsedConfig
import uuid


class CoverageAnalyzer:
    """Engine for analyzing policy coverage across different firewall vendors."""

    def analyze_coverage(
        self,
        matches: List[PolicyMatch],
        fortinet_policies: List[NormalizedPolicy],
        zscaler_policies: List[NormalizedPolicy]
    ) -> PolicyParity:
        """
        Analyze coverage between Fortinet and Zscaler policies.
        
        Args:
            matches: List of policy matches
            fortinet_policies: List of normalized Fortinet policies
            zscaler_policies: List of normalized Zscaler policies
            
        Returns:
            PolicyParity object with coverage analysis
        """
        # Count matched policies
        matched_policies = len([m for m in matches if m.match_type != "no_match"])
        
        # Calculate coverage percentages
        coverage_f1_to_f2 = self.calculate_coverage_percentage(len(fortinet_policies), matched_policies)
        coverage_f2_to_f1 = self.calculate_coverage_percentage(len(zscaler_policies), matched_policies)
        
        # Count gaps
        gaps = self.find_coverage_gaps(matches)
        gaps_count = len(gaps)
        
        # For now, we'll assume 0 conflicts (this would be calculated in a full implementation)
        conflicts_count = 0
        
        # Calculate parity score
        parity_score = self.calculate_parity_score(
            coverage_f1_to_f2, 
            coverage_f2_to_f1, 
            gaps_count, 
            conflicts_count
        )
        
        return PolicyParity(
            parity_id=str(uuid.uuid4()),
            total_policies_f1=len(fortinet_policies),
            total_policies_f2=len(zscaler_policies),
            matched_policies=matched_policies,
            coverage_percentage_f1_to_f2=coverage_f1_to_f2,
            coverage_percentage_f2_to_f1=coverage_f2_to_f1,
            gaps_found=gaps_count,
            conflicts_found=conflicts_count,
            enforcement_gaps=0,  # Would be calculated in a full implementation
            parity_score=parity_score
        )

    def find_coverage_gaps(self, matches: List[PolicyMatch]) -> List[CrossFirewallGap]:
        """
        Find coverage gaps between firewall policies.
        
        For each unmatched Fortinet policy:
          - Create gap: "Policy X in Fortinet not covered by Zscaler"
          - Set severity based on policy impact
          - Suggest Zscaler equivalent
        
        For each unmatched Zscaler policy:
          - Create gap: "Policy Y in Zscaler not covered by Fortinet"
          - Set severity
          - Suggest Fortinet equivalent
        
        Args:
            matches: List of policy matches
            
        Returns:
            List of coverage gaps
        """
        gaps = []
        
        for match in matches:
            if match.match_type == "no_match":
                if match.fortinet_policy_id and not match.zscaler_rule_id:
                    # Fortinet policy not covered by Zscaler
                    gap = CrossFirewallGap(
                        gap_id=str(uuid.uuid4()),
                        gap_type="coverage_gap",
                        firewall1_id="fortinet",
                        firewall2_id="zscaler",
                        policy_id=match.fortinet_policy_id,
                        description=f"Policy {match.fortinet_policy_id} in Fortinet not covered by Zscaler",
                        severity=self._determine_gap_severity(match.fortinet_policy_id),
                        business_impact="Potential security risk due to missing policy coverage",
                        recommendation="Create equivalent policy in Zscaler"
                    )
                    gaps.append(gap)
                elif match.zscaler_rule_id and not match.fortinet_policy_id:
                    # Zscaler policy not covered by Fortinet
                    gap = CrossFirewallGap(
                        gap_id=str(uuid.uuid4()),
                        gap_type="coverage_gap",
                        firewall1_id="zscaler",
                        firewall2_id="fortinet",
                        policy_id=match.zscaler_rule_id,
                        description=f"Policy {match.zscaler_rule_id} in Zscaler not covered by Fortinet",
                        severity=self._determine_gap_severity(match.zscaler_rule_id),
                        business_impact="Potential security risk due to missing policy coverage",
                        recommendation="Create equivalent policy in Fortinet"
                    )
                    gaps.append(gap)
                    
        return gaps

    def calculate_coverage_percentage(
        self,
        source_policy_count: int,
        matched_count: int
    ) -> float:
        """
        Calculate coverage percentage.
        
        Args:
            source_policy_count: Total number of policies in source firewall
            matched_count: Number of matched policies
            
        Returns:
            Coverage percentage (0-100)
        """
        if source_policy_count == 0:
            return 100.0  # No policies to match, considered full coverage
            
        return (matched_count / source_policy_count) * 100

    def find_enforcement_differences(self, match: PolicyMatch) -> List[str]:
        """
        Find enforcement differences between matched policies.
        
        Compare enforcement:
        - Does Fortinet log but Zscaler doesn't?
        - Does Zscaler apply DLP but Fortinet doesn't?
        - Different authentication requirements?
        - Different application filtering?
        
        Args:
            match: Policy match to analyze
            
        Returns:
            List of enforcement differences
        """
        differences = []
        
        # In a full implementation, this would compare actual policy details
        # For now, we'll return placeholder differences based on match details
        if match.source_match and "similarity" in match.source_match:
            try:
                similarity = float(match.source_match.split(":")[1].strip())
                if similarity < 0.8:
                    differences.append("Source entities partially overlap")
            except:
                pass
                
        if match.dest_match and "similarity" in match.dest_match:
            try:
                similarity = float(match.dest_match.split(":")[1].strip())
                if similarity < 0.8:
                    differences.append("Destination entities partially overlap")
            except:
                pass
                
        if match.service_match and "similarity" in match.service_match:
            try:
                similarity = float(match.service_match.split(":")[1].strip())
                if similarity < 0.8:
                    differences.append("Services partially overlap")
            except:
                pass
                
        return differences

    def build_enforcement_capability_matrix(
        self,
        fortinet_config: ParsedConfig,
        zscaler_config: ParsedConfig
    ) -> List[EnforcementCapabilityMatrix]:
        """
        Build enforcement capability matrix for both platforms.
        
        Check which capabilities each platform supports:
        - MFA enforcement
        - DLP (Data Loss Prevention)
        - IPS (Intrusion Prevention)
        - AV (Antivirus)
        - SSL inspection
        - URL filtering
        - Geographic filtering
        - User identity enforcement
        - Application control
        - Bandwidth management
        
        Args:
            fortinet_config: Parsed Fortinet configuration
            zscaler_config: Parsed Zscaler configuration
            
        Returns:
            List of enforcement capabilities
        """
        capabilities = []
        
        # Define all capabilities to check
        capability_definitions = [
            {"name": "mfa", "description": "Multi-Factor Authentication"},
            {"name": "dlp", "description": "Data Loss Prevention"},
            {"name": "ips", "description": "Intrusion Prevention System"},
            {"name": "av", "description": "Antivirus"},
            {"name": "ssl_inspection", "description": "SSL/TLS Inspection"},
            {"name": "url_filtering", "description": "URL Filtering"},
            {"name": "geographic_filtering", "description": "Geographic Filtering"},
            {"name": "user_identity", "description": "User Identity Enforcement"},
            {"name": "application_control", "description": "Application Control"},
            {"name": "bandwidth_management", "description": "Bandwidth Management"}
        ]
        
        # Check capabilities for each vendor
        for capability in capability_definitions:
            cap_name = capability["name"]
            cap_description = capability["description"]
            
            # Check Fortinet capabilities (simplified logic)
            fortinet_supports = self._check_fortinet_capability(fortinet_config, cap_name)
            
            # Check Zscaler capabilities (simplified logic)
            zscaler_supports = self._check_zscaler_capability(zscaler_config, cap_name)
            
            # Create capability matrix entry
            capability_entry = EnforcementCapabilityMatrix(
                capability_id=str(uuid.uuid4()),
                fortinet_supports=fortinet_supports,
                zscaler_supports=zscaler_supports,
                capability_name=cap_name,
                fortinet_method=self._get_fortinet_method(cap_name) if fortinet_supports else None,
                zscaler_method=self._get_zscaler_method(cap_name) if zscaler_supports else None,
                notes=f"{cap_description} support comparison"
            )
            
            capabilities.append(capability_entry)
            
        return capabilities

    def calculate_parity_score(
        self,
        coverage_f1_to_f2: float,
        coverage_f2_to_f1: float,
        gaps_count: int,
        conflicts_count: int
    ) -> float:
        """
        Calculate parity score (0-100).
        
        Score calculation:
        - Start with average coverage (0-50)
        - Subtract for gaps (-5 per gap, max -20)
        - Subtract for conflicts (-10 per conflict, max -20)
        - Result: final parity score
        
        Args:
            coverage_f1_to_f2: Coverage percentage from Fortinet to Zscaler
            coverage_f2_to_f1: Coverage percentage from Zscaler to Fortinet
            gaps_count: Number of coverage gaps
            conflicts_count: Number of conflicts
            
        Returns:
            Parity score (0-100)
        """
        # Start with average coverage (scaled to 0-50)
        average_coverage = (coverage_f1_to_f2 + coverage_f2_to_f1) / 2
        base_score = min(average_coverage, 50.0)
        
        # Subtract for gaps (-5 per gap, max -20)
        gap_penalty = min(gaps_count * 5, 20)
        
        # Subtract for conflicts (-10 per conflict, max -20)
        conflict_penalty = min(conflicts_count * 10, 20)
        
        # Calculate final score
        final_score = base_score - gap_penalty - conflict_penalty
        
        # Ensure score is between 0 and 100
        return max(0.0, min(100.0, final_score))

    def _determine_gap_severity(self, policy_id: str) -> str:
        """
        Determine gap severity based on policy characteristics.
        
        Gap Severity Levels:
        - CRITICAL: Unmatched security policy (admin, RESTRICTED data)
        - HIGH: Unmatched business critical policy
        - MEDIUM: Unmatched general network policy
        - LOW: Minor unmatched enforcement differences
        
        Args:
            policy_id: ID of the policy
            
        Returns:
            Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        """
        # In a real implementation, this would analyze the actual policy
        # For now, we'll use a simple heuristic based on policy ID
        policy_id_lower = str(policy_id).lower()
        
        if "admin" in policy_id_lower or "restricted" in policy_id_lower:
            return "CRITICAL"
        elif "business" in policy_id_lower or "critical" in policy_id_lower:
            return "HIGH"
        elif "general" in policy_id_lower or "network" in policy_id_lower:
            return "MEDIUM"
        else:
            return "LOW"

    def _check_fortinet_capability(self, config: ParsedConfig, capability: str) -> bool:
        """
        Check if Fortinet supports a specific capability.
        
        Args:
            config: Fortinet configuration
            capability: Capability to check
            
        Returns:
            True if supported, False otherwise
        """
        # Simplified capability checking logic
        # In a real implementation, this would examine the actual configuration
        fortinet_capabilities = {
            "mfa": True,
            "dlp": True,
            "ips": True,
            "av": True,
            "ssl_inspection": True,
            "url_filtering": True,
            "geographic_filtering": True,
            "user_identity": True,
            "application_control": True,
            "bandwidth_management": True
        }
        
        return fortinet_capabilities.get(capability, False)

    def _check_zscaler_capability(self, config: ParsedConfig, capability: str) -> bool:
        """
        Check if Zscaler supports a specific capability.
        
        Args:
            config: Zscaler configuration
            capability: Capability to check
            
        Returns:
            True if supported, False otherwise
        """
        # Simplified capability checking logic
        # In a real implementation, this would examine the actual configuration
        zscaler_capabilities = {
            "mfa": True,
            "dlp": True,
            "ips": False,  # Zscaler is cloud-based, doesn't do traditional IPS
            "av": False,   # Zscaler is cloud-based, doesn't do traditional AV
            "ssl_inspection": True,
            "url_filtering": True,
            "geographic_filtering": True,
            "user_identity": True,
            "application_control": True,
            "bandwidth_management": False  # Zscaler focuses on security, not bandwidth
        }
        
        return zscaler_capabilities.get(capability, False)

    def _get_fortinet_method(self, capability: str) -> str:
        """
        Get Fortinet method for a capability.
        
        Args:
            capability: Capability name
            
        Returns:
            Method description
        """
        methods = {
            "mfa": "FortiToken",
            "dlp": "FortiDLP",
            "ips": "FortiIPS",
            "av": "FortiAV",
            "ssl_inspection": "FortiSSL",
            "url_filtering": "FortiGuard",
            "geographic_filtering": "GeoIP",
            "user_identity": "FortiAuthenticator",
            "application_control": "FortiGuard App Control",
            "bandwidth_management": "Traffic Shaping"
        }
        
        return methods.get(capability, "Unknown")

    def _get_zscaler_method(self, capability: str) -> str:
        """
        Get Zscaler method for a capability.
        
        Args:
            capability: Capability name
            
        Returns:
            Method description
        """
        methods = {
            "mfa": "Zscaler Mobile",
            "dlp": "Zscaler DLP",
            "ips": "N/A",
            "av": "N/A",
            "ssl_inspection": "Zscaler SSL Inspection",
            "url_filtering": "Zscaler Web Security",
            "geographic_filtering": "Location-based Policies",
            "user_identity": "Zscaler Identity",
            "application_control": "Zscaler App Control",
            "bandwidth_management": "N/A"
        }
        
        return methods.get(capability, "Unknown")