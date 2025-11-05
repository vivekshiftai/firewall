"""
Enhanced policy analyzer with improved data validation, normalization, and analysis.
Implements 10 comprehensive checks with better error handling and logging.
"""
import logging
import json
from typing import Dict, Any, List, Set, Tuple
from collections import defaultdict
from app.core.config_validator import ConfigValidator
from app.core.enhanced_normalizer import EnhancedPolicyNormalizer, EnhancedNormalizedPolicy
from app.core.enhanced_inconsistency import EnhancedPolicyInconsistency, EnhancedInconsistencyType, SeverityLevel
from models.base import FirewallConfig

logger = logging.getLogger(__name__)


class EnhancedPolicyAnalyzer:
    """Production-grade policy analyzer with enhanced validation and analysis."""
    
    def __init__(self, config: FirewallConfig):
        """
        Initialize enhanced policy analyzer.
        
        Args:
            config: Firewall configuration to analyze
        """
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.inconsistencies: List[EnhancedPolicyInconsistency] = []
        self.normalized_policies: List[EnhancedNormalizedPolicy] = []
        self.analysis_metadata = {}
        
        self.logger.info("=" * 80)
        self.logger.info("INITIALIZING ENHANCED POLICY ANALYZER")
        self.logger.info("=" * 80)
        
        # Validate and normalize policies
        self._validate_and_normalize()
    
    def _validate_and_normalize(self):
        """Validate configuration structure and normalize policies."""
        self.logger.info(f"\n[1/2] Validating {self.config.vendor} configuration")
        
        # Convert FirewallConfig to dict for validation
        config_dict = {
            'firewall_policies': self.config.policies,
            'vendor': self.config.vendor
        }
        
        # Validate structure
        if self.config.vendor == 'fortinet':
            is_valid, errors = ConfigValidator.validate_fortinet(config_dict)
        elif self.config.vendor == 'zscaler':
            is_valid, errors = ConfigValidator.validate_zscaler(config_dict)
        else:
            is_valid = True
            errors = []
            self.logger.warning(f"Unknown vendor {self.config.vendor}, skipping validation")
        
        if not is_valid:
            self.logger.error(f"Configuration validation FAILED:")
            for error in errors:
                self.logger.error(f"  - {error}")
        else:
            self.logger.info(f"✓ Configuration validation passed")
        
        # Normalize policies
        self.logger.info(f"\n[2/2] Normalizing {len(self.config.policies)} policies")
        for policy in self.config.policies:
            try:
                if self.config.vendor == 'fortinet':
                    normalized = EnhancedPolicyNormalizer.normalize_fortinet_policy(policy)
                elif self.config.vendor == 'zscaler':
                    # Determine policy type
                    policy_type = 'url_filtering'
                    if 'dlp_settings' in policy:
                        policy_type = 'dlp'
                    elif 'applications' in policy:
                        policy_type = 'zpa'
                    normalized = EnhancedPolicyNormalizer.normalize_zscaler_policy(policy, policy_type)
                else:
                    self.logger.warning(f"Unknown vendor {self.config.vendor}, skipping normalization")
                    continue
                
                self.normalized_policies.append(normalized)
                self.logger.debug(f"  ✓ Normalized: {normalized.policy_name}")
            except Exception as e:
                self.logger.error(f"  ✗ Failed to normalize {policy.get('name', 'unknown')}: {e}")
                import traceback
                self.logger.debug(traceback.format_exc())
        
        self.logger.info(f"✓ Normalized {len(self.normalized_policies)} policies")
        
        # Store metadata
        self.analysis_metadata = {
            'vendor': self.config.vendor,
            'policy_count': len(self.normalized_policies),
            'config_valid': is_valid,
            'validation_errors': errors
        }
    
    def analyze_all(self) -> List[EnhancedPolicyInconsistency]:
        """
        Run all 10 comprehensive analysis checks.
        
        Returns:
            List of all inconsistencies found
        """
        self.logger.info("\n" + "=" * 80)
        self.logger.info("STARTING COMPREHENSIVE ANALYSIS (10 CHECKS)")
        self.logger.info("=" * 80)
        
        # Run all 10 checks
        self._check_1_contradictory_rules()
        self._check_2_duplicate_policies()
        self._check_3_overly_permissive_rules()
        self._check_4_utm_profile_inconsistency()
        self._check_5_user_group_consistency()
        self._check_6_dlp_coverage_gaps()
        self._check_7_application_access_gaps()
        self._check_8_missing_security_coverage()
        self._check_9_logging_consistency()
        self._check_10_mfa_encryption_requirements()
        
        self.logger.info("\n" + "=" * 80)
        self.logger.info(f"ANALYSIS COMPLETE: Found {len(self.inconsistencies)} inconsistencies")
        self.logger.info("=" * 80)
        
        return self.inconsistencies
    
    def _check_1_contradictory_rules(self):
        """Check 1/10: Contradictory Rules - overlapping rules with opposite actions."""
        self.logger.info("\n[CHECK 1/10] Contradictory Rules")
        
        contradictions = []
        for i, policy1 in enumerate(self.normalized_policies):
            for policy2 in self.normalized_policies[i+1:]:
                if self._policies_overlap(policy1, policy2):
                    action1_allows = policy1.action in ['allow', 'accept']
                    action2_allows = policy2.action in ['allow', 'accept']
                    action1_denies = policy1.action in ['deny', 'block', 'reject']
                    action2_denies = policy2.action in ['deny', 'block', 'reject']
                    
                    if (action1_allows and action2_denies) or (action1_denies and action2_allows):
                        contradictions.append((policy1, policy2))
        
        for pol1, pol2 in contradictions:
            inconsistency = EnhancedPolicyInconsistency(
                inconsistency_id=f"CONT_{pol1.policy_id}_{pol2.policy_id}",
                type=EnhancedInconsistencyType.CONTRADICTORY_ALLOW_DENY,
                severity=SeverityLevel.HIGH,
                description=f"Policies '{pol1.policy_name}' and '{pol2.policy_name}' have overlapping rules with contradictory actions",
                affected_fortinet_policies=[pol1.policy_id, pol2.policy_id] if self.config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[pol1.policy_id, pol2.policy_id] if self.config.vendor == 'zscaler' else [],
                affected_user_groups=list(pol1.source_users | pol2.source_users),
                root_cause="Same source/destination/service but different actions (allow vs deny)",
                business_impact="Unclear policy enforcement, potential security bypass or false blocking",
                recommendation="Review policy order and intent; consolidate if redundant",
                confidence_score=0.98,
                evidence={
                    'policy1': {'id': pol1.policy_id, 'name': pol1.policy_name, 'action': pol1.action},
                    'policy2': {'id': pol2.policy_id, 'name': pol2.policy_name, 'action': pol2.action}
                }
            )
            self.inconsistencies.append(inconsistency)
        
        self.logger.info(f"  ✓ Found {len(contradictions)} contradictory rule pairs")
    
    def _check_2_duplicate_policies(self):
        """Check 2/10: Duplicate Policies - identical or subsumed policies."""
        self.logger.info("\n[CHECK 2/10] Duplicate Policies")
        
        # Find policies with same semantic hash
        hash_map = defaultdict(list)
        for policy in self.normalized_policies:
            h = policy.semantic_hash()
            hash_map[h].append(policy)
        
        duplicates = [(policies[0], policies[1:]) 
                     for policies in hash_map.values() 
                     if len(policies) > 1]
        
        for orig, dups in duplicates:
            dup_ids = [d.policy_id for d in dups]
            inconsistency = EnhancedPolicyInconsistency(
                inconsistency_id=f"DUP_{orig.policy_id}",
                type=EnhancedInconsistencyType.DUPLICATE_POLICY,
                severity=SeverityLevel.LOW,
                description=f"Policy '{orig.policy_name}' is duplicated ({len(dups)} times)",
                affected_fortinet_policies=[orig.policy_id] + dup_ids if self.config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[orig.policy_id] + dup_ids if self.config.vendor == 'zscaler' else [],
                root_cause="Multiple policies with identical source, destination, and action",
                recommendation="Consolidate duplicate policies into a single rule",
                confidence_score=0.90,
                evidence={'duplicate_ids': dup_ids}
            )
            self.inconsistencies.append(inconsistency)
        
        self.logger.info(f"  ✓ Found {len(duplicates)} duplicate policy sets")
    
    def _check_3_overly_permissive_rules(self):
        """Check 3/10: Overly Permissive Rules - policies allowing all sources/destinations."""
        self.logger.info("\n[CHECK 3/10] Overly Permissive Rules")
        
        overly_permissive = []
        for policy in self.normalized_policies:
            if policy.action in ['allow', 'accept']:
                if policy.applies_to_all_sources or policy.applies_to_all_destinations:
                    overly_permissive.append(policy)
        
        for policy in overly_permissive:
            issue_type = "source" if policy.applies_to_all_sources else "destination"
            inconsistency = EnhancedPolicyInconsistency(
                inconsistency_id=f"PERM_{policy.policy_id}",
                type=EnhancedInconsistencyType.OVERLY_PERMISSIVE,
                severity=SeverityLevel.HIGH,
                description=f"Policy '{policy.policy_name}' allows traffic from/to all {issue_type}s",
                affected_fortinet_policies=[policy.policy_id] if self.config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if self.config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause=f"Policy allows all {issue_type}s (violates least-privilege principle)",
                business_impact="Excessive access permissions, potential security risk",
                recommendation=f"Restrict {issue_type} addresses to specific networks or zones",
                confidence_score=0.95,
                evidence={'policy_type': issue_type, 'applies_to_all_sources': policy.applies_to_all_sources}
            )
            self.inconsistencies.append(inconsistency)
        
        self.logger.info(f"  ✓ Found {len(overly_permissive)} overly permissive rules")
    
    def _check_4_utm_profile_inconsistency(self):
        """Check 4/10: UTM Profile Inconsistency - internet policies without UTM protection."""
        self.logger.info("\n[CHECK 4/10] UTM Profile Inconsistency")
        
        unprotected = []
        for policy in self.normalized_policies:
            if (policy.action in ['allow', 'accept'] and 
                policy.applies_to_all_destinations and 
                not policy.utm_profiles and 
                not policy.dlp_enabled):
                unprotected.append(policy)
        
        for policy in unprotected:
            inconsistency = EnhancedPolicyInconsistency(
                inconsistency_id=f"UTM_{policy.policy_id}",
                type=EnhancedInconsistencyType.INTERNET_ACCESS_UNPROTECTED,
                severity=SeverityLevel.HIGH,
                description=f"Policy '{policy.policy_name}' allows internet access without UTM protection",
                affected_fortinet_policies=[policy.policy_id] if self.config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if self.config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause="Internet access granted without UTM/AV/IPS profiles",
                business_impact="Users exposed to internet threats without inspection",
                recommendation="Enable UTM profiles (AV, IPS, WebFilter) or use Zscaler protection",
                confidence_score=0.99,
                evidence={'missing_utm': list(policy.utm_profiles), 'dest_type': policy.dest_type}
            )
            self.inconsistencies.append(inconsistency)
        
        self.logger.info(f"  ✓ Found {len(unprotected)} policies without UTM protection")
    
    def _check_5_user_group_consistency(self):
        """Check 5/10: User Group Consistency - groups with conflicting access patterns."""
        self.logger.info("\n[CHECK 5/10] User Group Consistency")
        
        group_policies = defaultdict(list)
        for policy in self.normalized_policies:
            for group in policy.source_users:
                group_policies[group].append(policy)
        
        issues = []
        for group, policies in group_policies.items():
            actions = set(p.action for p in policies)
            if 'allow' in actions and 'deny' in actions:
                # Check if they're for the same destination
                destinations = set()
                for p in policies:
                    if p.applies_to_all_destinations:
                        destinations.add('all')
                    else:
                        destinations.add(p.dest_resource)
                
                if len(destinations) == 1 and 'all' in destinations:
                    issues.append((group, policies))
        
        for group, policies in issues:
            inconsistency = EnhancedPolicyInconsistency(
                inconsistency_id=f"UG_{group}",
                type=EnhancedInconsistencyType.USER_GROUP_PERMISSION_MISMATCH,
                severity=SeverityLevel.MEDIUM,
                description=f"Group '{group}' has conflicting access patterns (allow and deny for same destination)",
                affected_user_groups=[group],
                root_cause="Same group has both allow and deny policies for same destination",
                business_impact="Unclear access control for group members",
                recommendation="Review policies for group and ensure consistent access control",
                confidence_score=0.85,
                evidence={'group': group, 'policies': [p.policy_name for p in policies]}
            )
            self.inconsistencies.append(inconsistency)
        
        self.logger.info(f"  ✓ Found {len(issues)} user group consistency issues")
    
    def _check_6_dlp_coverage_gaps(self):
        """Check 6/10: DLP Coverage Gaps - sensitive groups without DLP protection."""
        self.logger.info("\n[CHECK 6/10] DLP Coverage Gaps")
        
        sensitive_keywords = {'finance', 'accounting', 'legal', 'hr', 'executive', 'sales', 'crm'}
        sensitive_policies = [p for p in self.normalized_policies 
                            if any(kw in str(p.source_users).lower() or kw in p.policy_name.lower()
                                   for kw in sensitive_keywords)]
        
        missing_dlp = [p for p in sensitive_policies 
                      if not p.dlp_enabled and p.action in ['allow', 'accept']]
        
        for policy in missing_dlp:
            inconsistency = EnhancedPolicyInconsistency(
                inconsistency_id=f"DLP_{policy.policy_id}",
                type=EnhancedInconsistencyType.DLP_COVERAGE_GAP,
                severity=SeverityLevel.HIGH,
                description=f"Sensitive group '{policy.source_users}' not protected by DLP",
                affected_fortinet_policies=[policy.policy_id] if self.config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if self.config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause="DLP profile not enabled on sensitive group policy",
                business_impact="Sensitive data access not monitored/prevented",
                recommendation="Enable DLP profile for this policy",
                confidence_score=0.95,
                evidence={'affected_group': str(policy.source_users), 'policy_name': policy.policy_name}
            )
            self.inconsistencies.append(inconsistency)
        
        self.logger.info(f"  ✓ Found {len(missing_dlp)} DLP coverage gaps")
    
    def _check_7_application_access_gaps(self):
        """Check 7/10: Application Access Gaps - policies allowing app access without controls."""
        self.logger.info("\n[CHECK 7/10] Application Access Gaps")
        
        app_protocols = {'http', 'https', 'ftp', 'ssh', 'rdp', 'smb', 'ldap', 'dns'}
        app_policies = [p for p in self.normalized_policies 
                       if p.action in ['allow', 'accept'] and
                       any(any(proto in str(prot).lower() for proto in app_protocols) 
                           for prot in p.protocols)]
        
        missing_controls = [p for p in app_policies 
                           if not p.utm_profiles and not p.dlp_enabled]
        
        for policy in missing_controls:
            inconsistency = EnhancedPolicyInconsistency(
                inconsistency_id=f"APP_{policy.policy_id}",
                type=EnhancedInconsistencyType.ENFORCEMENT_CONFLICT,
                severity=SeverityLevel.MEDIUM,
                description=f"Policy '{policy.policy_name}' allows application access without controls",
                affected_fortinet_policies=[policy.policy_id] if self.config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if self.config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause="Application access granted without application control or UTM",
                business_impact="Application traffic not inspected or controlled",
                recommendation="Enable application control or application list on this policy",
                confidence_score=0.80,
                evidence={'protocols': list(policy.protocols)}
            )
            self.inconsistencies.append(inconsistency)
        
        self.logger.info(f"  ✓ Found {len(missing_controls)} application access gaps")
    
    def _check_8_missing_security_coverage(self):
        """Check 8/10: Missing Security Coverage - internet policies missing URL filtering."""
        self.logger.info("\n[CHECK 8/10] Missing Security Coverage")
        
        internet_policies = [p for p in self.normalized_policies 
                            if p.action in ['allow', 'accept'] and 
                            p.applies_to_all_destinations]
        
        missing_coverage = [p for p in internet_policies 
                           if not p.utm_profiles and 
                           'webfilter' not in str(p.utm_profiles).lower()]
        
        for policy in missing_coverage:
            inconsistency = EnhancedPolicyInconsistency(
                inconsistency_id=f"COV_{policy.policy_id}",
                type=EnhancedInconsistencyType.MISSING_UTM_PROFILE,
                severity=SeverityLevel.HIGH,
                description=f"Policy '{policy.policy_name}' allows internet access without URL filtering",
                affected_fortinet_policies=[policy.policy_id] if self.config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if self.config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause="Internet access policy missing URL filtering/web filtering",
                business_impact="Users can access inappropriate or malicious websites",
                recommendation="Enable URL filtering or web filtering profile on this policy",
                confidence_score=0.90,
                evidence={'dest_type': policy.dest_type}
            )
            self.inconsistencies.append(inconsistency)
        
        self.logger.info(f"  ✓ Found {len(missing_coverage)} missing security coverage issues")
    
    def _check_9_logging_consistency(self):
        """Check 9/10: Logging Consistency - critical policies without logging."""
        self.logger.info("\n[CHECK 9/10] Logging Consistency")
        
        critical_keywords = {'security', 'audit', 'finance', 'executive', 'admin', 'it-'}
        critical_policies = [p for p in self.normalized_policies
                           if any(kw in str(p.source_users).lower() or kw in p.policy_name.lower()
                                  for kw in critical_keywords)]
        
        no_logging = [p for p in critical_policies if not p.logging_enabled]
        
        for policy in no_logging:
            inconsistency = EnhancedPolicyInconsistency(
                inconsistency_id=f"LOG_{policy.policy_id}",
                type=EnhancedInconsistencyType.MISSING_LOGGING,
                severity=SeverityLevel.MEDIUM,
                description=f"Critical policy '{policy.policy_name}' has logging disabled",
                affected_fortinet_policies=[policy.policy_id] if self.config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if self.config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause="Logging not enabled on critical access policy",
                business_impact="No audit trail for compliance and security monitoring",
                recommendation="Enable logging for audit trail and compliance",
                confidence_score=0.90,
                evidence={'policy_name': policy.policy_name}
            )
            self.inconsistencies.append(inconsistency)
        
        self.logger.info(f"  ✓ Found {len(no_logging)} logging gaps")
    
    def _check_10_mfa_encryption_requirements(self):
        """Check 10/10: MFA/Encryption Requirements - sensitive access without MFA/encryption."""
        self.logger.info("\n[CHECK 10/10] MFA/Encryption Requirements")
        
        sensitive_policies = [p for p in self.normalized_policies 
                            if p.action in ['allow', 'accept'] and
                            (p.applies_to_all_destinations or 
                             any(kw in str(p.source_users).lower() 
                                 for kw in ['finance', 'executive', 'admin', 'hr']))]
        
        missing_mfa = [p for p in sensitive_policies if not p.requires_mfa]
        missing_encryption = [p for p in sensitive_policies if not p.requires_encryption]
        
        for policy in missing_mfa:
            inconsistency = EnhancedPolicyInconsistency(
                inconsistency_id=f"MFA_{policy.policy_id}",
                type=EnhancedInconsistencyType.MFA_REQUIREMENT_MISMATCH,
                severity=SeverityLevel.HIGH,
                description=f"Sensitive policy '{policy.policy_name}' does not require MFA",
                affected_fortinet_policies=[policy.policy_id] if self.config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if self.config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause="MFA not required for sensitive access",
                business_impact="Potential unauthorized access to sensitive resources",
                recommendation="Enable MFA requirement for this policy",
                confidence_score=0.85,
                evidence={'policy_name': policy.policy_name}
            )
            self.inconsistencies.append(inconsistency)
        
        for policy in missing_encryption:
            inconsistency = EnhancedPolicyInconsistency(
                inconsistency_id=f"ENC_{policy.policy_id}",
                type=EnhancedInconsistencyType.ENCRYPTION_GAP,
                severity=SeverityLevel.HIGH,
                description=f"Sensitive policy '{policy.policy_name}' does not require encryption",
                affected_fortinet_policies=[policy.policy_id] if self.config.vendor == 'fortinet' else [],
                affected_zscaler_policies=[policy.policy_id] if self.config.vendor == 'zscaler' else [],
                affected_user_groups=list(policy.source_users),
                root_cause="Encryption not required for sensitive access",
                business_impact="Sensitive data may be transmitted in plaintext",
                recommendation="Enable encryption requirement for this policy",
                confidence_score=0.85,
                evidence={'policy_name': policy.policy_name}
            )
            self.inconsistencies.append(inconsistency)
        
        self.logger.info(f"  ✓ Found {len(missing_mfa)} MFA gaps, {len(missing_encryption)} encryption gaps")
    
    def _policies_overlap(self, policy1: EnhancedNormalizedPolicy, 
                          policy2: EnhancedNormalizedPolicy) -> bool:
        """
        Check if two policies overlap in their traffic matching criteria.
        
        Args:
            policy1: First normalized policy
            policy2: Second normalized policy
            
        Returns:
            True if policies overlap
        """
        # Source overlap
        if policy1.applies_to_all_sources or policy2.applies_to_all_sources:
            src_overlap = True
        else:
            src_overlap = bool(policy1.source_users & policy2.source_users) or not (policy1.source_users and policy2.source_users)
        
        # Destination overlap
        if policy1.applies_to_all_destinations or policy2.applies_to_all_destinations:
            dst_overlap = True
        elif policy1.dest_resource == policy2.dest_resource:
            dst_overlap = True
        else:
            dst_overlap = False
        
        # Service/protocol overlap
        if not (policy1.protocols and policy2.protocols):
            service_overlap = True
        else:
            service_overlap = bool(policy1.protocols & policy2.protocols)
        
        return src_overlap and dst_overlap and service_overlap
    
    def calculate_policy_similarity(self, policy1: EnhancedNormalizedPolicy, 
                                   policy2: EnhancedNormalizedPolicy) -> float:
        """
        Calculate semantic similarity between two policies.
        Uses weighted scoring: users 30%, destination 30%, action 20%, type 20%.
        
        Args:
            policy1: First normalized policy
            policy2: Second normalized policy
            
        Returns:
            Similarity score from 0.0 to 1.0
        """
        scores = []
        weights = []
        
        # Source user match (0.3 weight)
        if policy1.source_users and policy2.source_users:
            user_overlap = len(policy1.source_users & policy2.source_users) / \
                          max(len(policy1.source_users | policy2.source_users), 1)
        else:
            user_overlap = 1.0 if not (policy1.source_users or policy2.source_users) else 0.0
        scores.append(user_overlap)
        weights.append(0.3)
        
        # Destination match (0.3 weight)
        if policy1.applies_to_all_destinations == policy2.applies_to_all_destinations:
            dest_match = 1.0 if policy1.applies_to_all_destinations else \
                        (1.0 if policy1.dest_resource == policy2.dest_resource else 0.5)
        else:
            dest_match = 0.0
        scores.append(dest_match)
        weights.append(0.3)
        
        # Action match (0.2 weight)
        action_match = 1.0 if policy1.action == policy2.action else 0.0
        scores.append(action_match)
        weights.append(0.2)
        
        # Type match (0.2 weight)
        type_match = 1.0 if policy1.dest_type == policy2.dest_type else 0.5
        scores.append(type_match)
        weights.append(0.2)
        
        # Calculate weighted average
        total_weight = sum(weights)
        weighted_score = sum(s * w for s, w in zip(scores, weights)) / total_weight
        
        return weighted_score
    
    def get_results_summary(self) -> Dict[str, Any]:
        """
        Get summary of analysis results.
        
        Returns:
            Dictionary with summary statistics
        """
        by_severity = {
            'CRITICAL': len([i for i in self.inconsistencies if i.severity == SeverityLevel.CRITICAL]),
            'HIGH': len([i for i in self.inconsistencies if i.severity == SeverityLevel.HIGH]),
            'MEDIUM': len([i for i in self.inconsistencies if i.severity == SeverityLevel.MEDIUM]),
            'LOW': len([i for i in self.inconsistencies if i.severity == SeverityLevel.LOW]),
        }
        
        by_type = defaultdict(int)
        for i in self.inconsistencies:
            by_type[i.type.value] += 1
        
        return {
            'total_inconsistencies': len(self.inconsistencies),
            'by_severity': by_severity,
            'by_type': dict(by_type),
            'metadata': self.analysis_metadata
        }

