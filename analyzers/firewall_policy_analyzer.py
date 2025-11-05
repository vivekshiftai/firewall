#!/usr/bin/env python3
"""
Firewall Policy Inconsistency Detection Framework
Author: Network Security Team
Version: 1.0
Description: Detects inconsistencies between Fortinet and Zscaler policies
"""

import json
import csv
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
from enum import Enum
import re


class InconsistencyType(Enum):
    """Types of policy inconsistencies"""
    USER_GROUP_MISMATCH = "User Group Access Mismatch"
    SERVICE_PORT_CONFLICT = "Service/Port Conflict"
    DUPLICATE_POLICY = "Duplicate or Overlapping Policy"
    MISSING_COVERAGE = "Missing Security Coverage"
    DLP_COVERAGE_GAP = "DLP Coverage Gap"
    CONTRADICTORY_ACTION = "Contradictory Allow/Deny"
    UTM_PROFILE_MISMATCH = "UTM Profile Inconsistency"
    NAT_ROUTING_CONFLICT = "NAT/Routing Conflict"
    APPLICATION_ACCESS_GAP = "Application Access Gap"
    OVERLY_PERMISSIVE = "Overly Permissive Rule"


@dataclass
class Inconsistency:
    """Represents a detected policy inconsistency"""
    type: InconsistencyType
    severity: str  # "HIGH", "MEDIUM", "LOW"
    description: str
    fortinet_policy: str
    zscaler_policy: str
    affected_groups: List[str]
    recommendation: str
    details: Dict


class PolicyAnalyzer:
    """Main policy analysis engine"""

    def __init__(self, fortinet_policies_file: str, zscaler_policies_file: str):
        self.fortinet_policies = self._load_json(fortinet_policies_file)
        self.zscaler_policies = self._load_json(zscaler_policies_file)
        self.inconsistencies: List[Inconsistency] = []

    def _load_json(self, filepath: str) -> Dict:
        """Load JSON policy files"""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: File {filepath} not found")
            return {}

    def analyze_all(self) -> List[Inconsistency]:
        """Run all inconsistency checks"""
        print("\n" + "="*80)
        print("FIREWALL POLICY INCONSISTENCY ANALYSIS")
        print("="*80 + "\n")

        self.check_user_group_access_consistency()
        self.check_internet_access_policy_alignment()
        self.check_dlp_coverage_gaps()
        self.check_application_access_gaps()
        self.check_utm_profile_consistency()
        self.check_overly_permissive_rules()
        self.check_duplicate_policies()
        self.check_contradictory_rules()

        return self.inconsistencies

    def check_user_group_access_consistency(self):
        """Check if user groups have consistent access across both firewalls"""
        print("\n[1/8] Checking user group access consistency...")

        # Extract user groups from Fortinet policies
        fortinet_groups = {}
        for policy in self.fortinet_policies.get('firewall_policies', []):
            for group in policy.get('user_groups', []):
                if group not in fortinet_groups:
                    fortinet_groups[group] = []
                fortinet_groups[group].append({
                    'policy': policy['name'],
                    'action': policy['action'],
                    'services': policy.get('services', []),
                    'destinations': policy.get('destination_addresses', [])
                })

        # Extract user groups from Zscaler URL policies
        zscaler_groups = {}
        for policy in self.zscaler_policies.get('zia_url_filtering_policies', []):
            for group in policy.get('apply_to_groups', []):
                if group not in zscaler_groups:
                    zscaler_groups[group] = []
                zscaler_groups[group].append({
                    'policy': policy['policy_name'],
                    'blocked_categories': policy.get('blocked_categories', []),
                    'ssl_inspection': policy.get('ssl_inspection', 'none')
                })

        # Compare groups between systems
        fortinet_only = set(fortinet_groups.keys()) - set(zscaler_groups.keys())
        zscaler_only = set(zscaler_groups.keys()) - set(fortinet_groups.keys())

        if fortinet_only:
            self.inconsistencies.append(Inconsistency(
                type=InconsistencyType.USER_GROUP_MISMATCH,
                severity="MEDIUM",
                description=f"User groups exist in Fortinet but not in Zscaler",
                fortinet_policy="Multiple",
                zscaler_policy="None",
                affected_groups=list(fortinet_only),
                recommendation="Add missing user groups to Zscaler or verify group names",
                details={'groups': list(fortinet_only)}
            ))

        if zscaler_only:
            self.inconsistencies.append(Inconsistency(
                type=InconsistencyType.USER_GROUP_MISMATCH,
                severity="MEDIUM",
                description=f"User groups exist in Zscaler but not in Fortinet",
                fortinet_policy="None",
                zscaler_policy="Multiple",
                affected_groups=list(zscaler_only),
                recommendation="Add missing user groups to Fortinet or verify group names",
                details={'groups': list(zscaler_only)}
            ))

        print(f"   ✓ Found {len(fortinet_only)} Fortinet-only groups, {len(zscaler_only)} Zscaler-only groups")

    def check_internet_access_policy_alignment(self):
        """Check if internet access policies are aligned"""
        print("\n[2/8] Checking internet access policy alignment...")

        # Map Fortinet policies with internet access (destination: all, port1)
        fortinet_internet = {}
        for policy in self.fortinet_policies.get('firewall_policies', []):
            if 'all' in policy.get('destination_addresses', []) and policy['action'] == 'accept':
                for group in policy.get('user_groups', []):
                    fortinet_internet[group] = {
                        'policy': policy['name'],
                        'utm_enabled': policy.get('utm_status', False),
                        'av_profile': policy.get('av_profile'),
                        'ips_sensor': policy.get('ips_sensor')
                    }

        # Map Zscaler URL filtering policies
        zscaler_internet = {}
        for policy in self.zscaler_policies.get('zia_url_filtering_policies', []):
            for group in policy.get('apply_to_groups', []):
                zscaler_internet[group] = {
                    'policy': policy['policy_name'],
                    'ssl_inspection': policy.get('ssl_inspection')
                }

        # Find groups with internet in Fortinet but no Zscaler policy
        for group in fortinet_internet:
            if group not in zscaler_internet:
                self.inconsistencies.append(Inconsistency(
                    type=InconsistencyType.MISSING_COVERAGE,
                    severity="HIGH",
                    description=f"Group '{group}' has internet access in Fortinet but no URL filtering in Zscaler",
                    fortinet_policy=fortinet_internet[group]['policy'],
                    zscaler_policy="None",
                    affected_groups=[group],
                    recommendation="Create Zscaler URL filtering policy for this group",
                    details={'fortinet': fortinet_internet[group]}
                ))

        print(f"   ✓ Identified {sum(1 for i in self.inconsistencies if i.type == InconsistencyType.MISSING_COVERAGE)} coverage gaps")

    def check_dlp_coverage_gaps(self):
        """Check for DLP coverage inconsistencies"""
        print("\n[3/8] Checking DLP coverage gaps...")

        # Groups that should have DLP based on Fortinet policies
        fortinet_dlp_groups = set()
        for policy in self.fortinet_policies.get('firewall_policies', []):
            if policy.get('dlp_sensor'):
                fortinet_dlp_groups.update(policy.get('user_groups', []))

        # Groups covered by Zscaler DLP
        zscaler_dlp_groups = set()
        for policy in self.zscaler_policies.get('zia_dlp_policies', []):
            zscaler_dlp_groups.update(policy.get('apply_to_groups', []))

        # Find gaps
        dlp_gaps = fortinet_dlp_groups - zscaler_dlp_groups

        if dlp_gaps:
            self.inconsistencies.append(Inconsistency(
                type=InconsistencyType.DLP_COVERAGE_GAP,
                severity="HIGH",
                description="Groups have DLP in Fortinet but not in Zscaler",
                fortinet_policy="Multiple DLP policies",
                zscaler_policy="Missing",
                affected_groups=list(dlp_gaps),
                recommendation="Implement Zscaler DLP policies for these groups",
                details={'missing_groups': list(dlp_gaps)}
            ))

        print(f"   ✓ Found {len(dlp_gaps)} groups with DLP gaps")

    def check_application_access_gaps(self):
        """Check for application access inconsistencies"""
        print("\n[4/8] Checking application access gaps...")

        # Extract groups accessing specific applications in Fortinet
        fortinet_app_access = {}
        for policy in self.fortinet_policies.get('firewall_policies', []):
            if policy['action'] == 'accept':
                apps = policy.get('destination_addresses', [])
                for group in policy.get('user_groups', []):
                    if group not in fortinet_app_access:
                        fortinet_app_access[group] = set()
                    fortinet_app_access[group].update(apps)

        # Extract ZPA access policies
        zpa_app_access = {}
        for policy in self.zscaler_policies.get('zpa_access_policies', []):
            if policy['action'] == 'allow':
                for group in policy.get('user_groups', []):
                    if group not in zpa_app_access:
                        zpa_app_access[group] = set()
                    zpa_app_access[group].update(policy.get('applications', []))

        # Compare critical groups
        critical_groups = ['Finance-Controllers', 'Accounting-Team', 'IT-Security-Team']

        for group in critical_groups:
            fortinet_apps = fortinet_app_access.get(group, set())
            zpa_apps = zpa_app_access.get(group, set())

            if fortinet_apps and not zpa_apps:
                self.inconsistencies.append(Inconsistency(
                    type=InconsistencyType.APPLICATION_ACCESS_GAP,
                    severity="MEDIUM",
                    description=f"Group '{group}' has app access in Fortinet but not in ZPA",
                    fortinet_policy="Multiple",
                    zscaler_policy="None",
                    affected_groups=[group],
                    recommendation="Create ZPA access policy for this group",
                    details={'fortinet_apps': list(fortinet_apps)}
                ))

        print(f"   ✓ Checked {len(critical_groups)} critical groups")

    def check_utm_profile_consistency(self):
        """Check UTM profile application consistency"""
        print("\n[5/8] Checking UTM profile consistency...")

        # Find policies with internet access but no UTM
        vulnerable_policies = []
        for policy in self.fortinet_policies.get('firewall_policies', []):
            if (policy['action'] == 'accept' and 
                'all' in policy.get('destination_addresses', []) and 
                not policy.get('utm_status', False)):
                vulnerable_policies.append(policy)

        if vulnerable_policies:
            for policy in vulnerable_policies:
                self.inconsistencies.append(Inconsistency(
                    type=InconsistencyType.UTM_PROFILE_MISMATCH,
                    severity="HIGH",
                    description=f"Policy allows internet access without UTM protection",
                    fortinet_policy=policy['name'],
                    zscaler_policy="N/A",
                    affected_groups=policy.get('user_groups', []),
                    recommendation="Enable UTM profiles (AV, IPS, Web Filtering) on this policy",
                    details={'policy_id': policy['policy_id']}
                ))

        print(f"   ✓ Found {len(vulnerable_policies)} policies without UTM")

    def check_overly_permissive_rules(self):
        """Detect overly permissive firewall rules"""
        print("\n[6/8] Checking for overly permissive rules...")

        overly_permissive = []
        for policy in self.fortinet_policies.get('firewall_policies', []):
            # Check for "ALL" services with broad access
            if (policy['action'] == 'accept' and 
                'ALL' in policy.get('services', []) and 
                'all' in policy.get('destination_addresses', [])):
                overly_permissive.append(policy)

        for policy in overly_permissive:
            self.inconsistencies.append(Inconsistency(
                type=InconsistencyType.OVERLY_PERMISSIVE,
                severity="MEDIUM",
                description=f"Policy allows ALL services to ALL destinations",
                fortinet_policy=policy['name'],
                zscaler_policy="N/A",
                affected_groups=policy.get('user_groups', []),
                recommendation="Restrict services to only required protocols",
                details={
                    'policy_id': policy['policy_id'],
                    'services': policy.get('services', []),
                    'destinations': policy.get('destination_addresses', [])
                }
            ))

        print(f"   ✓ Found {len(overly_permissive)} overly permissive rules")

    def check_duplicate_policies(self):
        """Detect duplicate or overlapping policies"""
        print("\n[7/8] Checking for duplicate policies...")

        policies = self.fortinet_policies.get('firewall_policies', [])
        duplicates = []

        for i, policy1 in enumerate(policies):
            for policy2 in policies[i+1:]:
                # Check if policies have same source, destination, and service
                if (set(policy1.get('source_addresses', [])) == set(policy2.get('source_addresses', [])) and
                    set(policy1.get('destination_addresses', [])) == set(policy2.get('destination_addresses', [])) and
                    set(policy1.get('services', [])) == set(policy2.get('services', []))):
                    duplicates.append((policy1, policy2))

        for pol1, pol2 in duplicates:
            self.inconsistencies.append(Inconsistency(
                type=InconsistencyType.DUPLICATE_POLICY,
                severity="LOW",
                description=f"Policies have identical source, destination, and services",
                fortinet_policy=f"{pol1['name']} & {pol2['name']}",
                zscaler_policy="N/A",
                affected_groups=[],
                recommendation="Consolidate duplicate policies or verify intent",
                details={'policy1_id': pol1['policy_id'], 'policy2_id': pol2['policy_id']}
            ))

        print(f"   ✓ Found {len(duplicates)} duplicate policy pairs")

    def check_contradictory_rules(self):
        """Detect contradictory allow/deny rules"""
        print("\n[8/8] Checking for contradictory rules...")

        policies = self.fortinet_policies.get('firewall_policies', [])
        contradictions = []

        for i, policy1 in enumerate(policies):
            for policy2 in policies[i+1:]:
                # Check for same source/dest but different actions
                if (set(policy1.get('source_addresses', [])) == set(policy2.get('source_addresses', [])) and
                    set(policy1.get('destination_addresses', [])) == set(policy2.get('destination_addresses', [])) and
                    policy1['action'] != policy2['action']):
                    contradictions.append((policy1, policy2))

        for pol1, pol2 in contradictions:
            self.inconsistencies.append(Inconsistency(
                type=InconsistencyType.CONTRADICTORY_ACTION,
                severity="HIGH",
                description=f"Policies have same traffic but contradictory actions",
                fortinet_policy=f"{pol1['name']} & {pol2['name']}",
                zscaler_policy="N/A",
                affected_groups=[],
                recommendation="Review policy order and consolidate conflicting rules",
                details={
                    'policy1': {'id': pol1['policy_id'], 'action': pol1['action']},
                    'policy2': {'id': pol2['policy_id'], 'action': pol2['action']}
                }
            ))

        print(f"   ✓ Found {len(contradictions)} contradictory rule pairs")

    def generate_report(self, output_file: str = "policy_inconsistencies_report.json"):
        """Generate detailed inconsistency report"""
        print("\n" + "="*80)
        print("GENERATING INCONSISTENCY REPORT")
        print("="*80 + "\n")

        # Group by severity
        high = [i for i in self.inconsistencies if i.severity == "HIGH"]
        medium = [i for i in self.inconsistencies if i.severity == "MEDIUM"]
        low = [i for i in self.inconsistencies if i.severity == "LOW"]

        report = {
            "summary": {
                "total_inconsistencies": len(self.inconsistencies),
                "high_severity": len(high),
                "medium_severity": len(medium),
                "low_severity": len(low),
                "analysis_timestamp": "2025-11-05T15:09:00+05:30"
            },
            "inconsistencies": [
                {
                    "type": i.type.value,
                    "severity": i.severity,
                    "description": i.description,
                    "fortinet_policy": i.fortinet_policy,
                    "zscaler_policy": i.zscaler_policy,
                    "affected_groups": i.affected_groups,
                    "recommendation": i.recommendation,
                    "details": i.details
                }
                for i in self.inconsistencies
            ]
        }

        # Save JSON report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        # Save CSV summary
        csv_file = output_file.replace('.json', '.csv')
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Severity', 'Type', 'Description', 'Fortinet Policy', 'Zscaler Policy', 'Recommendation'])
            for i in self.inconsistencies:
                writer.writerow([
                    i.severity,
                    i.type.value,
                    i.description,
                    i.fortinet_policy,
                    i.zscaler_policy,
                    i.recommendation
                ])

        print(f"✓ JSON Report saved: {output_file}")
        print(f"✓ CSV Report saved: {csv_file}")
        print(f"\nSummary:")
        print(f"  - HIGH severity: {len(high)}")
        print(f"  - MEDIUM severity: {len(medium)}")
        print(f"  - LOW severity: {len(low)}")
        print(f"  - TOTAL: {len(self.inconsistencies)}")

        return report


def main():
    """Main execution function"""
    # Initialize analyzer
    analyzer = PolicyAnalyzer(
        fortinet_policies_file='firewall_policies.json',
        zscaler_policies_file='zscaler_policies.json'
    )

    # Run all checks
    inconsistencies = analyzer.analyze_all()

    # Generate report
    report = analyzer.generate_report()

    print("\n" + "="*80)
    print("ANALYSIS COMPLETE")
    print("="*80)


if __name__ == "__main__":
    main()
