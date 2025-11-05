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
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-3.5-turbo"):
        """
        Initialize the AI analyzer.
        
        Args:
            api_key: OpenAI API key (if None, will try to get from OPENAI_API_KEY env var)
            model: OpenAI model to use (default: gpt-3.5-turbo, can use gpt-4o or gpt-4-turbo)
        """
        logger.info("Initializing AI Inconsistency Analyzer")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        
        if not self.api_key:
            logger.warning("OpenAI API key not found. AI analysis will be disabled.")
            logger.warning("Set OPENAI_API_KEY environment variable or pass api_key parameter")
            self.client = None
        else:
            self.client = OpenAI(api_key=self.api_key)
            logger.info(f"OpenAI client initialized with model: {model}")
        
        self.model = model
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
            logger.debug("Sending request to OpenAI API")
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
                temperature=0.3,  # Lower temperature for more consistent analysis
                response_format={"type": "json_object"}  # Request JSON response
            )
            
            # Parse AI response
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

