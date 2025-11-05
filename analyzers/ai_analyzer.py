"""
AI-powered policy analyzer using OpenAI GPT for inconsistency detection.
"""
import logging
import os
import json
from typing import Dict, Any, List, Optional
from openai import OpenAI
from models.base import FirewallConfig

# Configure logging
logger = logging.getLogger(__name__)

class AIInconsistencyAnalyzer:
    """AI-powered analyzer for detecting firewall policy inconsistencies using OpenAI GPT."""
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-5"):
        """
        Initialize the AI analyzer.
        
        Args:
            api_key: OpenAI API key (if None, will try to get from OPENAI_API_KEY env var)
            model: OpenAI model to use (default: gpt-5, can use gpt-4o, gpt-4-turbo, gpt-3.5-turbo)
                   GPT-5 uses responses.create() API, other models use chat.completions.create()
        """
        logger.info("Initializing AI Inconsistency Analyzer")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        
        # Use GPT-5 if specified, otherwise use provided model
        if model == "gpt-5":
            self.model = "gpt-5"  # Use GPT-5 when available
            logger.info("Using GPT-5 model for AI analysis")
        else:
            self.model = model
        
        if not self.api_key:
            logger.warning("OpenAI API key not found. AI analysis will be disabled.")
            logger.warning("Set OPENAI_API_KEY environment variable or pass api_key parameter")
            self.client = None
        else:
            self.client = OpenAI(api_key=self.api_key)
            logger.info(f"OpenAI client initialized with model: {self.model}")
        
        logger.info("AI Inconsistency Analyzer initialized successfully")
    
    def analyze_with_ai(self, config: FirewallConfig) -> Dict[str, Any]:
        """
        Analyze firewall policies using AI to detect inconsistencies.
        
        Args:
            config: Firewall configuration to analyze
            
        Returns:
            AI analysis results including inconsistencies found
        """
        logger.info(f"analyze_with_ai called: client exists={self.client is not None}, api_key exists={self.api_key is not None}")
        
        if not self.client:
            logger.warning("OpenAI client not available. Skipping AI analysis.")
            logger.warning(f"API key status: api_key={self.api_key is not None}")
            return {
                "ai_analysis": {
                    "enabled": False,
                    "message": "OpenAI API key not configured",
                    "api_key_available": self.api_key is not None,
                    "client_available": False
                }
            }
        
        logger.info(f"Starting AI analysis for {config.vendor} firewall with {len(config.policies)} policies")
        
        try:
            # Prepare policies for AI analysis
            policies_text = self._format_policies_for_ai(config.policies)
            
            # Create prompt for AI analysis
            prompt = self._create_analysis_prompt(config, policies_text)
            
            # Call OpenAI API
            logger.debug(f"Sending request to OpenAI API using {self.model}")
            
            # Use GPT-5 API structure if using GPT-5, otherwise use chat completions API
            if self.model == "gpt-5":
                try:
                    # GPT-5 uses responses.create() with different structure
                    logger.info("Using GPT-5 API (responses.create)")
                    combined_prompt = f"{self._get_system_prompt()}\n\n{prompt}"
                    
                    response = self.client.responses.create(
                        model="gpt-5",
                        input=combined_prompt,
                        reasoning={"effort": "high"},  # High effort for detailed analysis
                        text={"verbosity": "high"}  # High verbosity for comprehensive responses
                    )
                    
                    # GPT-5 returns output_text directly
                    response_text = response.output_text
                    ai_response = json.loads(response_text)
                    
                except Exception as model_error:
                    # If GPT-5 API is not available, fallback to gpt-4o with chat completions
                    logger.warning(f"GPT-5 API not available ({str(model_error)}), falling back to gpt-4o")
                    self.model = "gpt-4o"
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {
                                "role": "system",
                                "content": self._get_system_prompt()
                            },
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ],
                        temperature=0.3,
                        response_format={"type": "json_object"}
                    )
                    ai_response = json.loads(response.choices[0].message.content)
            else:
                # Use standard chat completions API for other models
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": self._get_system_prompt()
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    temperature=0.3,
                    response_format={"type": "json_object"}
                )
                ai_response = json.loads(response.choices[0].message.content)
            logger.info("AI analysis completed successfully")
            
            # Convert AI findings to inconsistency format
            ai_findings = ai_response.get("findings", [])
            logger.info(f"AI found {len(ai_findings)} issues")
            
            # Format AI findings to match the inconsistency structure
            formatted_findings = []
            for finding in ai_findings:
                formatted_findings.append({
                    "type": finding.get("type", "Unknown"),
                    "severity": finding.get("severity", "MEDIUM"),
                    "description": finding.get("description", ""),
                    "fortinet_policy": finding.get("fortinet_policy", "Unknown"),
                    "zscaler_policy": finding.get("zscaler_policy", "N/A"),
                    "affected_groups": finding.get("affected_groups", []),
                    "recommendation": finding.get("recommendation", ""),
                    "details": finding.get("details", {})
                })
            
            return {
                "ai_analysis": {
                    "enabled": True,
                    "model": self.model,
                    "findings": formatted_findings,
                    "summary": ai_response.get("summary", ""),
                    "recommendations": ai_response.get("recommendations", []),
                    "risk_assessment": ai_response.get("risk_assessment", {})
                }
            }
            
        except Exception as e:
            logger.error(f"Error during AI analysis: {str(e)}")
            return {
                "ai_analysis": {
                    "enabled": True,
                    "error": str(e),
                    "message": "AI analysis failed"
                }
            }
    
    def _format_policies_for_ai(self, policies: List[Dict[str, Any]]) -> str:
        """
        Format policies into a readable text format for AI analysis.
        
        Args:
            policies: List of policy dictionaries
            
        Returns:
            Formatted string of policies
        """
        formatted = []
        for i, policy in enumerate(policies, 1):
            policy_text = f"Policy {i} (ID: {policy.get('id', 'unknown')}):\n"
            policy_text += f"  Name: {policy.get('name', 'N/A')}\n"
            policy_text += f"  Source Zones: {', '.join(policy.get('source_zones', []) or policy.get('source_addresses', []))}\n"
            policy_text += f"  Destination Zones: {', '.join(policy.get('destination_zones', []) or policy.get('destination_addresses', []))}\n"
            policy_text += f"  Services: {', '.join(policy.get('services', []))}\n"
            policy_text += f"  Action: {policy.get('action', 'N/A')}\n"
            policy_text += f"  Enabled: {policy.get('enabled', True)}\n"
            
            # Add groups/user information
            groups = policy.get('groups', [])
            if groups:
                if isinstance(groups, str):
                    policy_text += f"  Groups: {groups}\n"
                else:
                    policy_text += f"  Groups: {', '.join(str(g) for g in groups)}\n"
            
            # Add UTM profile information
            utm_status = policy.get('utm-status', False) or policy.get('utm_enabled', False)
            policy_text += f"  UTM Enabled: {utm_status}\n"
            if policy.get('av-profile') or policy.get('av_profile'):
                policy_text += f"  AV Profile: {policy.get('av-profile') or policy.get('av_profile')}\n"
            if policy.get('ips-sensor') or policy.get('ips_sensor'):
                policy_text += f"  IPS Sensor: {policy.get('ips-sensor') or policy.get('ips_sensor')}\n"
            if policy.get('webfilter-profile') or policy.get('webfilter_profile'):
                policy_text += f"  Web Filter Profile: {policy.get('webfilter-profile') or policy.get('webfilter_profile')}\n"
            if policy.get('dlp-sensor') or policy.get('dlp_sensor'):
                policy_text += f"  DLP Sensor: {policy.get('dlp-sensor') or policy.get('dlp_sensor')}\n"
            
            # Add NAT information
            if policy.get('nat'):
                policy_text += f"  NAT: {policy.get('nat')}\n"
            
            # Add logging
            if policy.get('logtraffic') or policy.get('log_traffic'):
                policy_text += f"  Log Traffic: {policy.get('logtraffic') or policy.get('log_traffic')}\n"
            
            if policy.get('comments'):
                policy_text += f"  Comments: {policy.get('comments')}\n"
            
            formatted.append(policy_text)
        
        return "\n".join(formatted)
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for AI analysis."""
        return """You are an expert firewall policy analyst specializing in Fortinet and Zscaler security platforms. Your task is to analyze firewall policies and identify 8 types of inconsistencies:

1. **Contradictory Rule**: Policies that overlap but have conflicting actions (e.g., one allows and one denies the same traffic)
2. **Duplicate Policy**: Duplicate or identical policies that serve the same purpose
3. **Overly Permissive Rule**: Policies allowing "ALL" sources/destinations/services (violates least-privilege)
4. **UTM Profile Inconsistency**: Internet-facing policies without UTM protection (AV, IPS, Web Filter)
5. **Missing Security Coverage**: Policies that lack appropriate security controls
6. **DLP Coverage Gap**: Groups with DLP in policies but missing DLP enforcement
7. **User Group Inconsistency**: Policies referencing groups that may not exist or are inconsistent
8. **Application Access Gap**: Policies allowing application access without proper controls

Return your analysis as a JSON object with this EXACT structure:
{
  "summary": "Brief summary of findings",
  "findings": [
    {
      "type": "Contradictory Rule|Duplicate Policy|Overly Permissive Rule|UTM Profile Inconsistency|Missing Security Coverage|DLP Coverage Gap|User Group Inconsistency|Application Access Gap",
      "severity": "HIGH|MEDIUM|LOW",
      "description": "Detailed description of the issue",
      "fortinet_policy": "Policy name or ID",
      "zscaler_policy": "N/A (for single firewall) or policy name",
      "affected_groups": ["Group1", "Group2"],
      "recommendation": "How to fix this issue",
      "details": {
        "policy_id": "policy_id",
        "additional_info": "any relevant details"
      }
    }
  ],
  "recommendations": [
    "General recommendation 1",
    "General recommendation 2"
  ],
  "risk_assessment": {
    "overall_risk": "HIGH|MEDIUM|LOW",
    "risk_score": 0.0-1.0,
    "critical_issues": 0,
    "medium_issues": 0,
    "low_issues": 0
  }
}

IMPORTANT: 
- Use the EXACT type names listed above
- Always include "affected_groups" array (extract from policy groups field)
- Set "zscaler_policy" to "N/A" for single firewall analysis
- Include specific policy names/IDs in "fortinet_policy" field
- Provide actionable recommendations"""
    
    def _create_analysis_prompt(self, config: FirewallConfig, policies_text: str) -> str:
        """
        Create the analysis prompt for AI.
        
        Args:
            config: Firewall configuration
            policies_text: Formatted policies text
            
        Returns:
            Complete prompt string
        """
        prompt = f"""Analyze the following firewall configuration for {config.vendor} firewall (ID: {config.id}).

Firewall Configuration:
- Vendor: {config.vendor}
- Version: {config.version}
- Total Policies: {len(config.policies)}

Policies to Analyze:
{policies_text}

Please analyze these policies and identify:
1. Any conflicts between policies (overlapping rules with opposite actions)
2. Redundant or duplicate policies
3. Security gaps (overly permissive rules)
4. Logical issues or missing required information
5. Coverage gaps (missing security controls)

Return your analysis in the JSON format specified in the system prompt."""
        
        return prompt
    
    def analyze_policy_batch(self, policies: List[Dict[str, Any]], batch_size: int = 10) -> Dict[str, Any]:
        """
        Analyze policies in batches to handle large configurations.
        
        Args:
            policies: List of policies to analyze
            batch_size: Number of policies to analyze per batch
            
        Returns:
            Combined analysis results
        """
        if not self.client:
            return {"ai_analysis": {"enabled": False, "message": "OpenAI API key not configured"}}
        
        logger.info(f"Analyzing {len(policies)} policies in batches of {batch_size}")
        
        all_findings = []
        all_recommendations = []
        
        for i in range(0, len(policies), batch_size):
            batch = policies[i:i + batch_size]
            logger.debug(f"Analyzing batch {i // batch_size + 1} ({len(batch)} policies)")
            
            # Create a temporary config for this batch
            batch_config = FirewallConfig(
                id=f"batch-{i // batch_size + 1}",
                vendor="unknown",
                version="unknown",
                policies=batch
            )
            
            batch_result = self.analyze_with_ai(batch_config)
            
            if batch_result.get("ai_analysis", {}).get("enabled"):
                all_findings.extend(batch_result["ai_analysis"].get("findings", []))
                all_recommendations.extend(batch_result["ai_analysis"].get("recommendations", []))
        
        # Combine results
        return {
            "ai_analysis": {
                "enabled": True,
                "model": self.model,
                "findings": all_findings,
                "recommendations": list(set(all_recommendations)),  # Remove duplicates
                "total_findings": len(all_findings)
            }
        }
    
    def analyze_inconsistencies(self, inconsistencies: List[Dict[str, Any]], vendor: str = "fortinet") -> Dict[str, Any]:
        """
        Analyze inconsistent policies found by rule-based checks using AI.
        Sends inconsistencies to AI for detailed analysis by type, severity, reason, and solution.
        
        Args:
            inconsistencies: List of inconsistency dictionaries (from enhanced checks)
            vendor: Vendor name (fortinet or zscaler)
            
        Returns:
            AI analysis results with structured analysis for each inconsistency
        """
        if not self.client:
            logger.warning("OpenAI client not available. Skipping AI inconsistency analysis.")
            return {
                "ai_analysis": {
                    "enabled": False,
                    "message": "OpenAI API key not configured"
                }
            }
        
        if not inconsistencies:
            logger.info("No inconsistencies to analyze with AI")
            return {
                "ai_analysis": {
                    "enabled": True,
                    "message": "No inconsistencies found to analyze",
                    "analyzed_count": 0
                }
            }
        
        logger.info(f"Analyzing {len(inconsistencies)} inconsistencies with AI (model: {self.model})")
        
        try:
            # Format inconsistencies for AI analysis
            inconsistencies_text = self._format_inconsistencies_for_ai(inconsistencies, vendor)
            
            # Create prompt for AI analysis
            prompt = self._create_inconsistency_analysis_prompt(inconsistencies_text, vendor, len(inconsistencies))
            
            # Call OpenAI API
            logger.debug(f"Sending {len(inconsistencies)} inconsistencies to OpenAI API for analysis using {self.model}")
            
            # Use GPT-5 API structure if using GPT-5, otherwise use chat completions API
            if self.model == "gpt-5":
                try:
                    # GPT-5 uses responses.create() with different structure
                    logger.info("Using GPT-5 API (responses.create)")
                    combined_prompt = f"{self._get_inconsistency_system_prompt()}\n\n{prompt}"
                    
                    response = self.client.responses.create(
                        model="gpt-5",
                        input=combined_prompt,
                        reasoning={"effort": "high"},  # High effort for detailed analysis
                        text={"verbosity": "high"}  # High verbosity for comprehensive responses
                    )
                    
                    # GPT-5 returns output_text directly
                    response_text = response.output_text
                    ai_response = json.loads(response_text)
                    
                except Exception as model_error:
                    # If GPT-5 API is not available, fallback to gpt-4o with chat completions
                    logger.warning(f"GPT-5 API not available ({str(model_error)}), falling back to gpt-4o")
                    self.model = "gpt-4o"
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {
                                "role": "system",
                                "content": self._get_inconsistency_system_prompt()
                            },
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ],
                        temperature=0.2,
                        response_format={"type": "json_object"}
                    )
                    ai_response = json.loads(response.choices[0].message.content)
            else:
                # Use standard chat completions API for other models
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": self._get_inconsistency_system_prompt()
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    temperature=0.2,
                    response_format={"type": "json_object"}
                )
                ai_response = json.loads(response.choices[0].message.content)
            logger.info(f"AI analysis completed successfully. Analyzed {len(ai_response.get('analyzed_inconsistencies', []))} inconsistencies")
            
            return {
                "ai_analysis": {
                    "enabled": True,
                    "model": self.model,
                    "analyzed_count": len(ai_response.get('analyzed_inconsistencies', [])),
                    "analyzed_inconsistencies": ai_response.get('analyzed_inconsistencies', []),
                    "summary": ai_response.get("summary", ""),
                    "overall_assessment": ai_response.get("overall_assessment", {}),
                    "priority_recommendations": ai_response.get("priority_recommendations", [])
                }
            }
            
        except Exception as e:
            logger.error(f"Error during AI inconsistency analysis: {str(e)}")
            import traceback
            logger.debug(traceback.format_exc())
            return {
                "ai_analysis": {
                    "enabled": True,
                    "error": str(e),
                    "message": "AI inconsistency analysis failed"
                }
            }
    
    def _format_inconsistencies_for_ai(self, inconsistencies: List[Dict[str, Any]], vendor: str) -> str:
        """
        Format inconsistencies into a readable text format for AI analysis.
        
        Args:
            inconsistencies: List of inconsistency dictionaries
            vendor: Vendor name
            
        Returns:
            Formatted string of inconsistencies
        """
        formatted = []
        for idx, inconsistency in enumerate(inconsistencies, 1):
            inc_text = f"\n=== Inconsistency {idx} ===\n"
            inc_text += f"Inconsistency ID: {inconsistency.get('inconsistency_id', f'INC_{idx}')}\n"
            inc_text += f"Type: {inconsistency.get('type', 'Unknown')}\n"
            inc_text += f"Severity: {inconsistency.get('severity', 'MEDIUM')}\n"
            inc_text += f"Description: {inconsistency.get('description', 'N/A')}\n"
            
            # Affected policies
            if vendor == 'fortinet':
                affected_policies = inconsistency.get('affected_fortinet_policies', [])
                if affected_policies:
                    inc_text += f"Affected Fortinet Policies: {', '.join(str(p) for p in affected_policies)}\n"
            elif vendor == 'zscaler':
                affected_policies = inconsistency.get('affected_zscaler_policies', [])
                if affected_policies:
                    inc_text += f"Affected Zscaler Policies: {', '.join(str(p) for p in affected_policies)}\n"
            
            # Affected user groups
            affected_groups = inconsistency.get('affected_user_groups', [])
            if affected_groups:
                inc_text += f"Affected User Groups: {', '.join(str(g) for g in affected_groups)}\n"
            
            # Root cause
            root_cause = inconsistency.get('root_cause', '')
            if root_cause:
                inc_text += f"Root Cause: {root_cause}\n"
            
            # Business impact
            business_impact = inconsistency.get('business_impact', '')
            if business_impact:
                inc_text += f"Business Impact: {business_impact}\n"
            
            # Current recommendation
            recommendation = inconsistency.get('recommendation', '')
            if recommendation:
                inc_text += f"Current Recommendation: {recommendation}\n"
            
            # Remediation steps
            remediation_steps = inconsistency.get('remediation_steps', [])
            if remediation_steps:
                inc_text += f"Remediation Steps: {len(remediation_steps)} steps provided\n"
                for step_idx, step in enumerate(remediation_steps, 1):
                    inc_text += f"  {step_idx}. {step}\n"
            
            # Evidence
            evidence = inconsistency.get('evidence', {})
            if evidence:
                inc_text += f"Evidence: {json.dumps(evidence, indent=2)}\n"
            
            # Confidence score
            confidence = inconsistency.get('confidence_score', 0.0)
            inc_text += f"Confidence Score: {confidence:.2f}\n"
            
            formatted.append(inc_text)
        
        return "\n".join(formatted)
    
    def _get_inconsistency_system_prompt(self) -> str:
        """Get the system prompt for AI inconsistency analysis."""
        return """You are an expert firewall policy analyst with 20+ years of experience in network security, firewall management, and security policy analysis. Your expertise covers Fortinet FortiGate, Zscaler, and other major firewall platforms.

Your task is to analyze firewall policy inconsistencies that have been detected by automated rule-based checks. For each inconsistency, you need to provide:

1. **Detailed Type Analysis**: Classify the inconsistency type more precisely
2. **Severity Assessment**: Assess the severity level (CRITICAL, HIGH, MEDIUM, LOW) with justification
3. **Root Cause Analysis**: Provide deep technical analysis of WHY this inconsistency occurred
4. **Solution Strategy**: Provide detailed, actionable steps on HOW to resolve this issue

Return your analysis as a JSON object with this EXACT structure:
{
  "summary": "Brief overall summary of all inconsistencies analyzed",
  "analyzed_inconsistencies": [
    {
      "inconsistency_id": "original inconsistency ID",
      "type": {
        "category": "Contradictory Rules|Duplicate Policies|Security Gaps|Configuration Issues|Compliance Issues",
        "detailed_type": "More specific type description",
        "explanation": "Why this type classification is accurate"
      },
      "severity": {
        "level": "CRITICAL|HIGH|MEDIUM|LOW",
        "justification": "Detailed explanation of why this severity level is appropriate",
        "risk_score": 0.0-1.0,
        "factors": ["Factor 1", "Factor 2", "Factor 3"]
      },
      "root_cause": {
        "primary_cause": "Main technical reason why this inconsistency exists",
        "contributing_factors": ["Factor 1", "Factor 2"],
        "technical_details": "Deep technical explanation",
        "common_patterns": "Is this a common mistake? What patterns indicate this?"
      },
      "solution": {
        "immediate_actions": [
          "Step 1: Immediate action to take",
          "Step 2: Next immediate action"
        ],
        "detailed_steps": [
          "Step 1: Detailed resolution step",
          "Step 2: Next step with specific commands/config changes",
          "Step 3: Verification step"
        ],
        "verification": "How to verify the fix is working",
        "prevention": "How to prevent this issue in the future",
        "estimated_complexity": "LOW|MEDIUM|HIGH",
        "estimated_time": "Time estimate to fix"
      },
      "priority": {
        "priority_level": 1-10,
        "urgency": "IMMEDIATE|HIGH|MEDIUM|LOW",
        "reason": "Why this priority level"
      }
    }
  ],
  "overall_assessment": {
    "total_critical": 0,
    "total_high": 0,
    "total_medium": 0,
    "total_low": 0,
    "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
    "overall_risk_score": 0.0-1.0,
    "key_concerns": ["Concern 1", "Concern 2"]
  },
  "priority_recommendations": [
    {
      "priority": 1,
      "recommendation": "Most critical recommendation",
      "reason": "Why this is the top priority"
    }
  ]
}

IMPORTANT:
- Be thorough and technical in your analysis
- Provide actionable, specific solutions
- Consider real-world firewall management scenarios
- Include specific commands or configuration examples where applicable
- Assess business and security impact
- Provide verification steps for each solution"""
    
    def _create_inconsistency_analysis_prompt(self, inconsistencies_text: str, vendor: str, count: int) -> str:
        """
        Create the analysis prompt for AI inconsistency analysis.
        
        Args:
            inconsistencies_text: Formatted inconsistencies text
            vendor: Vendor name
            count: Number of inconsistencies
            
        Returns:
            Complete prompt string
        """
        prompt = f"""Analyze the following {count} firewall policy inconsistencies detected in a {vendor.upper()} firewall configuration.

These inconsistencies were detected by automated rule-based analysis. Your task is to provide deep technical analysis for each one, including:

1. **Type Analysis**: More detailed classification of the inconsistency type
2. **Severity Assessment**: Assess the severity with detailed justification
3. **Root Cause Analysis**: Deep technical analysis of WHY this occurred
4. **Solution Strategy**: Detailed, actionable steps on HOW to resolve it

For each inconsistency, provide:
- Detailed type classification and explanation
- Severity assessment with justification
- Root cause analysis (technical details)
- Step-by-step solution with verification
- Priority ranking

Inconsistencies to Analyze:
{inconsistencies_text}

Please analyze each inconsistency thoroughly and provide structured analysis as specified in the system prompt. Focus on:
- Technical accuracy
- Actionable solutions
- Real-world firewall management scenarios
- Security and business impact
- Verification methods

Return your analysis in the JSON format specified in the system prompt."""
        
        return prompt

