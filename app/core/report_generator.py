"""
Multi-firewall report generator.
"""
from typing import List, Dict, Any
from app.models.cross_firewall import (
    CrossFirewallAnalysisReport, 
    PolicyMatch, 
    PolicyParity, 
    CrossFirewallGap, 
    EnforcementCapabilityMatrix
)
import csv
import io
from datetime import datetime


class ReportGenerator:
    """Generator for multi-firewall analysis reports."""

    def generate_cross_firewall_report(
        self,
        analysis: CrossFirewallAnalysisReport
    ) -> dict:
        """
        Generate a comprehensive cross-firewall report.
        
        Args:
            analysis: Cross-firewall analysis report
            
        Returns:
            Dictionary containing the full report
        """
        return {
            "executive_summary": self._generate_executive_summary(analysis),
            "firewall1_section": self._generate_firewall1_section(analysis),
            "firewall2_section": self._generate_firewall2_section(analysis),
            "cross_firewall_section": self._generate_cross_firewall_section(analysis),
            "policy_parity": self._generate_policy_parity_section(analysis),
            "enforcement_matrix": self._generate_enforcement_matrix_section(analysis),
            "standardization_recommendations": analysis.standardization_recommendations
        }

    def generate_policy_match_matrix(
        self,
        matches: List[PolicyMatch],
        all_fw1_policies: int,
        all_fw2_policies: int
    ) -> dict:
        """
        Generate a policy match matrix.
        
        Args:
            matches: List of policy matches
            all_fw1_policies: Total number of Fortinet policies
            all_fw2_policies: Total number of Zscaler policies
            
        Returns:
            Dictionary containing the match matrix
        """
        # Create a matrix showing which policies match
        match_matrix = []
        unmatched_fw1 = []
        unmatched_fw2 = []
        
        for match in matches:
            if match.match_type != "no_match":
                match_matrix.append({
                    "fortinet_policy_id": match.fortinet_policy_id,
                    "zscaler_rule_id": match.zscaler_rule_id,
                    "match_type": match.match_type,
                    "confidence": match.confidence_score,
                    "differences": match.differences
                })
            else:
                if match.fortinet_policy_id and not match.zscaler_rule_id:
                    unmatched_fw1.append(match.fortinet_policy_id)
                elif match.zscaler_rule_id and not match.fortinet_policy_id:
                    unmatched_fw2.append(match.zscaler_rule_id)
        
        return {
            "match_matrix": match_matrix,
            "unmatched_fortinet_policies": unmatched_fw1,
            "unmatched_zscaler_policies": unmatched_fw2,
            "fortinet_coverage": f"{(len(match_matrix) / all_fw1_policies * 100):.1f}%" if all_fw1_policies > 0 else "0%",
            "zscaler_coverage": f"{(len(match_matrix) / all_fw2_policies * 100):.1f}%" if all_fw2_policies > 0 else "0%"
        }

    def generate_coverage_report(
        self,
        coverage: PolicyParity,
        gaps: List[CrossFirewallGap]
    ) -> dict:
        """
        Generate a coverage report.
        
        Args:
            coverage: Policy parity information
            gaps: List of cross-firewall gaps
            
        Returns:
            Dictionary containing the coverage report
        """
        # Group gaps by severity
        gaps_by_severity = {}
        for gap in gaps:
            severity = gap.severity
            if severity not in gaps_by_severity:
                gaps_by_severity[severity] = []
            gaps_by_severity[severity].append({
                "gap_id": gap.gap_id,
                "description": gap.description,
                "business_impact": gap.business_impact,
                "recommendation": gap.recommendation
            })
        
        return {
            "fortinet_to_zscaler_coverage": f"{coverage.coverage_percentage_f1_to_f2:.1f}%",
            "zscaler_to_fortinet_coverage": f"{coverage.coverage_percentage_f2_to_f1:.1f}%",
            "total_gaps": coverage.gaps_found,
            "gaps_by_severity": gaps_by_severity,
            "detailed_gaps": [
                {
                    "gap_id": gap.gap_id,
                    "gap_type": gap.gap_type,
                    "policy_id": gap.policy_id,
                    "description": gap.description,
                    "severity": gap.severity,
                    "business_impact": gap.business_impact,
                    "recommendation": gap.recommendation
                }
                for gap in gaps
            ]
        }

    def generate_enforcement_comparison(
        self,
        capability_matrix: List[EnforcementCapabilityMatrix]
    ) -> dict:
        """
        Generate an enforcement comparison report.
        
        Args:
            capability_matrix: List of enforcement capabilities
            
        Returns:
            Dictionary containing the comparison table
        """
        comparison_table = []
        for capability in capability_matrix:
            comparison_table.append({
                "capability": capability.capability_name,
                "fortinet_supports": "Yes" if capability.fortinet_supports else "No",
                "zscaler_supports": "Yes" if capability.zscaler_supports else "No",
                "fortinet_method": capability.fortinet_method or "N/A",
                "zscaler_method": capability.zscaler_method or "N/A",
                "notes": capability.notes
            })
        
        return {
            "enforcement_comparison_table": comparison_table
        }

    def generate_conflict_report(
        self,
        conflicts: List[CrossFirewallGap]
    ) -> dict:
        """
        Generate a conflict report organized by type.
        
        Args:
            conflicts: List of cross-firewall conflicts
            
        Returns:
            Dictionary containing the conflict report
        """
        # Organize conflicts by type
        security_contradictions = []
        enforcement_differences = []
        priority_conflicts = []
        
        for conflict in conflicts:
            conflict_info = {
                "gap_id": conflict.gap_id,
                "policy_id": conflict.policy_id,
                "description": conflict.description,
                "severity": conflict.severity,
                "business_impact": conflict.business_impact,
                "recommendation": conflict.recommendation
            }
            
            if conflict.gap_type == "conflict":
                security_contradictions.append(conflict_info)
            elif conflict.gap_type == "enforcement_difference":
                enforcement_differences.append(conflict_info)
            elif conflict.gap_type == "priority_conflict":
                priority_conflicts.append(conflict_info)
        
        return {
            "security_contradictions": security_contradictions,
            "enforcement_differences": enforcement_differences,
            "priority_conflicts": priority_conflicts,
            "total_conflicts": len(conflicts),
            "recommendations_per_conflict": [
                {
                    "conflict_id": conflict.gap_id,
                    "conflict_description": conflict.description,
                    "recommendation": conflict.recommendation
                }
                for conflict in conflicts
            ]
        }

    def generate_standardization_recommendations(
        self,
        analysis: CrossFirewallAnalysisReport
    ) -> List[Dict]:
        """
        Generate standardization recommendations.
        
        Args:
            analysis: Cross-firewall analysis report
            
        Returns:
            List of recommendation dictionaries
        """
        recommendations = []
        
        # Add existing recommendations
        for i, rec in enumerate(analysis.standardization_recommendations):
            recommendations.append({
                "id": f"rec_{i+1}",
                "type": "general",
                "description": rec,
                "priority": "medium"
            })
        
        # Add policy unification recommendations
        for gap in analysis.cross_firewall_gaps:
            if gap.gap_type == "coverage_gap":
                recommendations.append({
                    "id": f"policy_unify_{gap.gap_id}",
                    "type": "policy_unification",
                    "description": f"Unify policy {gap.policy_id} between {gap.firewall1_id} and {gap.firewall2_id}",
                    "priority": gap.severity.lower()
                })
        
        # Add enforcement capability recommendations
        for capability in analysis.enforcement_matrix:
            if capability.fortinet_supports != capability.zscaler_supports:
                recommendations.append({
                    "id": f"capability_align_{capability.capability_id}",
                    "type": "capability_alignment",
                    "description": f"Align {capability.capability_name} support between platforms",
                    "priority": "high" if capability.capability_name in ["mfa", "dlp", "ips"] else "medium"
                })
        
        return recommendations

    def generate_pdf_multi_firewall(
        self,
        analysis: CrossFirewallAnalysisReport
    ) -> bytes:
        """
        Generate a professional PDF report.
        
        Args:
            analysis: Cross-firewall analysis report
            
        Returns:
            PDF content as bytes
        """
        # This is a placeholder implementation
        # In a real implementation, this would use a PDF library like ReportLab or WeasyPrint
        pdf_content = f"""
        Cross-Firewall Analysis Report
        Generated: {datetime.utcnow().isoformat()}
        
        Executive Summary:
        {self._generate_executive_summary(analysis)}
        
        Detailed analysis sections would follow...
        """
        
        # Return as bytes (placeholder)
        return pdf_content.encode('utf-8')

    def generate_csv_policy_mappings(
        self,
        matches: List[PolicyMatch]
    ) -> str:
        """
        Generate CSV format policy mappings.
        
        Args:
            matches: List of policy matches
            
        Returns:
            CSV formatted string
        """
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "Fortinet_ID", 
            "Fortinet_Name", 
            "Zscaler_ID", 
            "Zscaler_Name", 
            "Match_Type", 
            "Confidence", 
            "Differences"
        ])
        
        # Write data rows
        for match in matches:
            # In a real implementation, we would have access to policy names
            # For now, we'll use IDs as names
            writer.writerow([
                match.fortinet_policy_id or "",
                match.fortinet_policy_id or "",
                match.zscaler_rule_id or "",
                match.zscaler_rule_id or "",
                match.match_type,
                f"{match.confidence_score:.2f}",
                "; ".join(match.differences) if match.differences else ""
            ])
        
        return output.getvalue()

    def _generate_executive_summary(self, analysis: CrossFirewallAnalysisReport) -> str:
        """Generate executive summary."""
        return f"""
        Cross-Firewall Policy Analysis Report
        ====================================
        
        Analysis ID: {analysis.analysis_id}
        Timestamp: {analysis.timestamp}
        
        This report provides a comprehensive analysis of policy alignment between 
        Fortinet and Zscaler firewall configurations. Key findings include:
        
        - Overall Policy Parity Score: {analysis.overall_parity_score:.1f}/100
        - Total Policy Matches: {len(analysis.policy_matches)}
        - Coverage Gaps Identified: {len(analysis.cross_firewall_gaps)}
        - Critical Issues: {len([g for g in analysis.cross_firewall_gaps if g.severity == 'CRITICAL'])}
        
        Recommendations for improving policy consistency and security posture 
        are provided in the final section of this report.
        """

    def _generate_firewall1_section(self, analysis: CrossFirewallAnalysisReport) -> dict:
        """Generate Fortinet firewall section."""
        return {
            "firewall_id": analysis.fortinet_config_id,
            "inconsistencies_found": len(analysis.fortinet_inconsistencies),
            "inconsistencies": [
                {
                    "type": inc.type,
                    "severity": inc.severity,
                    "description": inc.description
                }
                for inc in analysis.fortinet_inconsistencies
            ]
        }

    def _generate_firewall2_section(self, analysis: CrossFirewallAnalysisReport) -> dict:
        """Generate Zscaler firewall section."""
        return {
            "firewall_id": analysis.zscaler_config_id,
            "inconsistencies_found": len(analysis.zscaler_inconsistencies),
            "inconsistencies": [
                {
                    "type": inc.type,
                    "severity": inc.severity,
                    "description": inc.description
                }
                for inc in analysis.zscaler_inconsistencies
            ]
        }

    def _generate_cross_firewall_section(self, analysis: CrossFirewallAnalysisReport) -> dict:
        """Generate cross-firewall comparison section."""
        return {
            "total_matches": len(analysis.policy_matches),
            "exact_matches": len([m for m in analysis.policy_matches if m.match_type == "exact"]),
            "semantic_matches": len([m for m in analysis.policy_matches if m.match_type == "semantic"]),
            "partial_matches": len([m for m in analysis.policy_matches if m.match_type == "partial"]),
            "unmatched_policies": len([m for m in analysis.policy_matches if m.match_type == "no_match"])
        }

    def _generate_policy_parity_section(self, analysis: CrossFirewallAnalysisReport) -> dict:
        """Generate policy parity section."""
        return {
            "parity_score": analysis.policy_parity.parity_score,
            "fortinet_total_policies": analysis.policy_parity.total_policies_f1,
            "zscaler_total_policies": analysis.policy_parity.total_policies_f2,
            "matched_policies": analysis.policy_parity.matched_policies,
            "coverage_fortinet_to_zscaler": f"{analysis.policy_parity.coverage_percentage_f1_to_f2:.1f}%",
            "coverage_zscaler_to_fortinet": f"{analysis.policy_parity.coverage_percentage_f2_to_f1:.1f}%"
        }

    def _generate_enforcement_matrix_section(self, analysis: CrossFirewallAnalysisReport) -> dict:
        """Generate enforcement matrix section."""
        capabilities = []
        for capability in analysis.enforcement_matrix:
            capabilities.append({
                "capability": capability.capability_name,
                "fortinet": "✓" if capability.fortinet_supports else "✗",
                "zscaler": "✓" if capability.zscaler_supports else "✗",
                "notes": capability.notes
            })
        
        return {
            "capabilities": capabilities
        }