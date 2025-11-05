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
        if not self.client:
            logger.warning("OpenAI client not available. Skipping AI analysis.")
            return {
                "ai_analysis": {
                    "enabled": False,
                    "message": "OpenAI API key not configured"
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
            
            return {
                "ai_analysis": {
                    "enabled": True,
                    "model": self.model,
                    "findings": ai_response.get("findings", []),
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
            if policy.get('comments'):
                policy_text += f"  Comments: {policy.get('comments')}\n"
            formatted.append(policy_text)
        
        return "\n".join(formatted)
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for AI analysis."""
        return """You are an expert firewall policy analyst. Your task is to analyze firewall policies and identify inconsistencies, conflicts, redundancies, and security issues.

Analyze the provided firewall policies and identify:
1. **Conflicts**: Policies that overlap but have conflicting actions (e.g., one allows and one denies the same traffic)
2. **Redundancies**: Duplicate or identical policies that serve the same purpose
3. **Security Gaps**: Overly permissive policies (e.g., allowing traffic from/to "all")
4. **Logical Issues**: Policies that don't make sense or have missing required fields
5. **Coverage Gaps**: Missing security controls or incomplete policy coverage

Return your analysis as a JSON object with this structure:
{
  "summary": "Brief summary of findings",
  "findings": [
    {
      "type": "conflict|redundancy|security_gap|logical_issue|coverage_gap",
      "severity": "HIGH|MEDIUM|LOW",
      "policy_ids": ["policy_id1", "policy_id2"],
      "description": "Detailed description of the issue",
      "recommendation": "How to fix this issue"
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
}"""
    
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

