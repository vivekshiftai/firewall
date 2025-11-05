"""
AI-powered policy analyzer using OpenAI GPT for inconsistency detection.
"""
import logging
import os
import json
import time
from typing import Dict, Any, List, Optional, Callable
from openai import OpenAI
from models.base import FirewallConfig

# Configure logging first
logger = logging.getLogger(__name__)

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    # Load .env file from current directory or parent directories
    env_loaded = load_dotenv()
    if env_loaded:
        logger.debug("Successfully loaded .env file")
    else:
        logger.debug("No .env file found or already loaded")
except ImportError:
    # dotenv not installed, try to install it or continue without it
    logger.warning("python-dotenv not installed. Install it with: pip install python-dotenv")
    logger.warning("Continuing without .env file support")
except Exception as e:
    logger.warning(f"Error loading .env file: {e}")

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
        
        # Load API key from environment or parameter
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if self.api_key:
            logger.info(f"OpenAI API key found: {self.api_key[:10]}...{self.api_key[-4:] if len(self.api_key) > 14 else '***'}")
        else:
            logger.warning("OpenAI API key not found in environment variables or parameter")
            logger.warning("Make sure OPENAI_API_KEY is set in .env file or environment")
        
        # Set model - default to GPT-5, but allow override via parameter or env var
        env_model = os.getenv("OPENAI_MODEL")
        if env_model:
            logger.info(f"Found OPENAI_MODEL in environment: {env_model}")
            self.model = env_model
        elif model:
            self.model = model
        else:
            self.model = "gpt-5"  # Default to GPT-5
        
        logger.info(f"Using OpenAI model: {self.model}")
        
        if not self.api_key:
            logger.warning("OpenAI API key not found. AI analysis will be disabled.")
            logger.warning("Set OPENAI_API_KEY environment variable or pass api_key parameter")
            self.client = None
        else:
            self.client = OpenAI(api_key=self.api_key)
            logger.info(f"OpenAI client initialized with model: {self.model}")
        
        logger.info("AI Inconsistency Analyzer initialized successfully")
    
    def _retry_with_timeout(self, func: Callable, max_retries: int = 3, timeout_seconds: int = 180, 
                           retry_delay: int = 60, operation_name: str = "API call") -> Any:
        """
        Retry mechanism with timeout handling.
        
        Args:
            func: Function to execute with retry
            max_retries: Maximum number of retry attempts (default: 3)
            timeout_seconds: Timeout in seconds before considering request failed (default: 180 = 3 minutes)
            retry_delay: Delay between retries in seconds (default: 60 = 1 minute)
            operation_name: Name of operation for logging
            
        Returns:
            Result from function call
            
        Raises:
            Exception: If all retries fail or timeout occurs
        """
        last_exception = None
        
        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Attempt {attempt}/{max_retries} for {operation_name} (timeout: {timeout_seconds}s)")
                start_time = time.time()
                
                # Execute the function
                result = func()
                
                elapsed_time = time.time() - start_time
                logger.info(f"{operation_name} completed successfully in {elapsed_time:.2f} seconds")
                return result
                
            except Exception as e:
                last_exception = e
                error_str = str(e).lower()
                elapsed_time = time.time() - start_time if 'start_time' in locals() else 0
                
                # Check if it's a timeout error
                is_timeout = (
                    "timeout" in error_str or
                    "timed out" in error_str or
                    "connection" in error_str or
                    elapsed_time >= timeout_seconds
                )
                
                if is_timeout:
                    logger.warning(f"{operation_name} timed out or connection error after {elapsed_time:.2f} seconds: {str(e)}")
                else:
                    logger.warning(f"{operation_name} failed with error: {str(e)}")
                
                # If this was the last attempt, don't retry
                if attempt >= max_retries:
                    logger.error(f"{operation_name} failed after {max_retries} attempts")
                    break
                
                # Wait before retrying (3 minutes = 180 seconds as requested)
                wait_time = timeout_seconds if is_timeout else retry_delay
                logger.info(f"Waiting {wait_time} seconds before retry {attempt + 1}/{max_retries}...")
                time.sleep(wait_time)
        
        # If we get here, all retries failed
        raise last_exception if last_exception else Exception(f"{operation_name} failed after {max_retries} attempts")
    
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
                    
                    # Use retry mechanism with 3 minute timeout
                    def call_gpt5_responses_analyze():
                        return self.client.responses.create(
                            model="gpt-5",
                            input=combined_prompt,
                            reasoning={"effort": "high"},  # High effort for detailed analysis
                            text={"verbosity": "high"}  # High verbosity for comprehensive responses
                        )
                    
                    response = self._retry_with_timeout(
                        call_gpt5_responses_analyze,
                        max_retries=3,
                        timeout_seconds=180,  # 3 minutes timeout
                        retry_delay=180,  # Wait 3 minutes before retry
                        operation_name="GPT-5 responses.create() (analyze_with_ai)"
                    )
                    
                    # GPT-5 returns output_text directly
                    response_text = response.output_text
                    ai_response = json.loads(response_text)
                    
                except Exception as model_error:
                    # If GPT-5 responses.create() API is not available, try GPT-5 with chat completions
                    logger.warning(f"GPT-5 responses.create() API not available ({str(model_error)})")
                    logger.info("Attempting to use GPT-5 with chat completions API instead...")
                    
                    try:
                        # Try GPT-5 with chat completions API
                        def call_gpt5_chat_analyze():
                            return self.client.chat.completions.create(
                                model="gpt-5",
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
                        
                        response = self._retry_with_timeout(
                            call_gpt5_chat_analyze,
                            max_retries=3,
                            timeout_seconds=180,  # 3 minutes timeout
                            retry_delay=180,  # Wait 3 minutes before retry
                            operation_name="GPT-5 chat completions (analyze_with_ai)"
                        )
                        ai_response = json.loads(response.choices[0].message.content)
                        logger.info("Successfully used GPT-5 with chat completions API")
                    except Exception as gpt5_chat_error:
                        # If GPT-5 with chat completions also fails, fallback to gpt-4o as last resort
                        logger.warning(f"GPT-5 with chat completions also failed ({str(gpt5_chat_error)})")
                        logger.warning("Falling back to gpt-4o as last resort")
                        self.model = "gpt-4o"
                        
                        def call_gpt4o_fallback():
                            return self.client.chat.completions.create(
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
                        
                        response = self._retry_with_timeout(
                            call_gpt4o_fallback,
                            max_retries=3,
                            timeout_seconds=180,  # 3 minutes timeout
                            retry_delay=180,  # Wait 3 minutes before retry
                            operation_name="GPT-4o fallback (analyze_with_ai)"
                        )
                        ai_response = json.loads(response.choices[0].message.content)
            else:
                # Use standard chat completions API for other models
                def call_chat_completions_analyze():
                    return self.client.chat.completions.create(
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
                
                response = self._retry_with_timeout(
                    call_chat_completions_analyze,
                    max_retries=3,
                    timeout_seconds=180,  # 3 minutes timeout
                    retry_delay=180,  # Wait 3 minutes before retry
                    operation_name=f"Chat completions ({self.model}) (analyze_with_ai)"
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
    
    def _analyze_inconsistencies_batched(self, inconsistencies: List[Dict[str, Any]], vendor: str, batch_size: int) -> Dict[str, Any]:
        """
        Analyze inconsistencies in batches to handle large numbers.
        
        Args:
            inconsistencies: List of inconsistency dictionaries
            vendor: Vendor name
            batch_size: Number of inconsistencies per batch
            
        Returns:
            Combined AI analysis results
        """
        logger.info(f"Analyzing {len(inconsistencies)} inconsistencies in batches of {batch_size}")
        
        all_analyzed_inconsistencies = []
        all_priority_recommendations = []
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0
        
        # Process in batches
        for batch_idx in range(0, len(inconsistencies), batch_size):
            batch = inconsistencies[batch_idx:batch_idx + batch_size]
            batch_num = batch_idx // batch_size + 1
            total_batches = (len(inconsistencies) + batch_size - 1) // batch_size
            
            logger.info(f"Processing batch {batch_num}/{total_batches} ({len(batch)} inconsistencies)")
            
            try:
                # Analyze this batch (force_batch=False to prevent recursion)
                batch_result = self.analyze_inconsistencies(batch, vendor, force_batch=False)
                
                if batch_result.get("ai_analysis", {}).get("enabled"):
                    analyzed = batch_result["ai_analysis"].get("analyzed_inconsistencies", [])
                    all_analyzed_inconsistencies.extend(analyzed)
                    
                    # Collect priority recommendations
                    priority_recs = batch_result["ai_analysis"].get("priority_recommendations", [])
                    all_priority_recommendations.extend(priority_recs)
                    
                    # Count severities from this batch
                    for inc in analyzed:
                        severity = inc.get("severity", {}).get("level", "MEDIUM")
                        if severity == "CRITICAL":
                            total_critical += 1
                        elif severity == "HIGH":
                            total_high += 1
                        elif severity == "MEDIUM":
                            total_medium += 1
                        elif severity == "LOW":
                            total_low += 1
                    
                    logger.info(f"  Batch {batch_num}: Analyzed {len(analyzed)} inconsistencies")
                else:
                    logger.warning(f"  Batch {batch_num}: AI analysis failed or was disabled")
                    
            except Exception as e:
                logger.error(f"Error analyzing batch {batch_num}: {str(e)}")
                import traceback
                logger.debug(traceback.format_exc())
                continue
        
        # Combine results
        overall_risk = "HIGH" if total_critical > 0 or total_high > 5 else \
                      "MEDIUM" if total_high > 0 or total_medium > 10 else "LOW"
        
        overall_risk_score = min(1.0, (total_critical * 0.4 + total_high * 0.3 + total_medium * 0.2 + total_low * 0.1) / max(len(inconsistencies), 1))
        
        # Deduplicate and prioritize recommendations
        unique_recommendations = {}
        for rec in all_priority_recommendations:
            priority = rec.get("priority", 999)
            if priority not in unique_recommendations:
                unique_recommendations[priority] = rec
        
        sorted_recommendations = sorted(unique_recommendations.values(), key=lambda x: x.get("priority", 999))
        
        return {
            "ai_analysis": {
                "enabled": True,
                "model": self.model,
                "analyzed_count": len(all_analyzed_inconsistencies),
                "analyzed_inconsistencies": all_analyzed_inconsistencies,
                "summary": f"Analyzed {len(all_analyzed_inconsistencies)} inconsistencies across {total_batches} batches",
                "overall_assessment": {
                    "total_critical": total_critical,
                    "total_high": total_high,
                    "total_medium": total_medium,
                    "total_low": total_low,
                    "overall_risk": overall_risk,
                    "overall_risk_score": overall_risk_score,
                    "key_concerns": [
                        f"{total_critical} critical issues",
                        f"{total_high} high severity issues"
                    ] if (total_critical > 0 or total_high > 0) else ["No critical issues found"]
                },
                "priority_recommendations": sorted_recommendations[:10]  # Top 10 recommendations
            }
        }
    
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
    
    def analyze_inconsistencies(self, inconsistencies: List[Dict[str, Any]], vendor: str = "fortinet", force_batch: bool = False) -> Dict[str, Any]:
        """
        Analyze inconsistent policies found by rule-based checks using AI.
        Sends inconsistencies to AI for detailed analysis by type, severity, reason, and solution.
        
        Args:
            inconsistencies: List of inconsistency dictionaries (from enhanced checks)
            vendor: Vendor name (fortinet or zscaler)
            force_batch: If True, force batching even for small lists (used internally)
            
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
        
        # For GPT-5, send ALL inconsistencies at once - GPT-5 has 128k token context window
        # For other models, use batching if needed
        if self.model == "gpt-5":
            # GPT-5 has 128k token context window - can handle all inconsistencies at once
            logger.info(f"GPT-5 detected (128k context window): Sending all {len(inconsistencies)} inconsistencies in one request")
            # No batching for GPT-5 - it will handle everything with its 128k context
        elif self.model == "gpt-4o":
            # GPT-4o can also handle large batches, but use batching as safety measure
            batch_size = 100  # Large batch size for GPT-4o
            if force_batch or len(inconsistencies) > batch_size:
                logger.info(f"Batching {len(inconsistencies)} inconsistencies into batches of {batch_size} for GPT-4o")
                return self._analyze_inconsistencies_batched(inconsistencies, vendor, batch_size)
        else:
            # Other models (like gpt-3.5-turbo) need smaller batches
            batch_size = 5
            if force_batch or len(inconsistencies) > batch_size:
                logger.info(f"Batching {len(inconsistencies)} inconsistencies into batches of {batch_size} for {self.model}")
                return self._analyze_inconsistencies_batched(inconsistencies, vendor, batch_size)
        
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
                    
                    # Use retry mechanism with 3 minute timeout
                    def call_gpt5_responses():
                        return self.client.responses.create(
                            model="gpt-5",
                            input=combined_prompt,
                            reasoning={"effort": "high"},  # High effort for detailed analysis
                            text={"verbosity": "high"}  # High verbosity for comprehensive responses
                        )
                    
                    response = self._retry_with_timeout(
                        call_gpt5_responses,
                        max_retries=3,
                        timeout_seconds=180,  # 3 minutes timeout
                        retry_delay=180,  # Wait 3 minutes before retry
                        operation_name="GPT-5 responses.create()"
                    )
                    
                    # GPT-5 returns output_text directly
                    response_text = response.output_text
                    ai_response = json.loads(response_text)
                    
                except Exception as model_error:
                    error_str = str(model_error)
                    # Check if it's a context length error
                    if "context_length" in error_str.lower() or "maximum context length" in error_str.lower():
                        # Even GPT-5's 128k context has limits - if we hit it, batch is needed
                        logger.warning(f"Context length exceeded for {len(inconsistencies)} inconsistencies with GPT-5 (128k limit)")
                        logger.info(f"GPT-5 128k context limit reached - batching {len(inconsistencies)} inconsistencies into smaller batches")
                        # Use very large batches for GPT-5 even when batching (128k tokens is huge)
                        batch_size = 500  # Very large batches for GPT-5 (128k context allows ~500+ inconsistencies)
                        return self._analyze_inconsistencies_batched(inconsistencies, vendor, batch_size)
                    # If GPT-5 API is not available, try to use gpt-4o as fallback
                    # But first log the error and try to use GPT-5 with chat completions API as alternative
                    logger.warning(f"GPT-5 responses.create() API not available ({str(model_error)})")
                    logger.info("Attempting to use GPT-5 with chat completions API instead...")
                    
                    # Try GPT-5 with chat completions API (some OpenAI clients might support this)
                    try:
                        def call_gpt5_chat():
                            return self.client.chat.completions.create(
                                model="gpt-5",  # Try GPT-5 with chat completions
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
                        
                        response = self._retry_with_timeout(
                            call_gpt5_chat,
                            max_retries=3,
                            timeout_seconds=180,  # 3 minutes timeout
                            retry_delay=180,  # Wait 3 minutes before retry
                            operation_name="GPT-5 chat completions"
                        )
                        ai_response = json.loads(response.choices[0].message.content)
                        logger.info("Successfully used GPT-5 with chat completions API")
                    except Exception as gpt5_chat_error:
                        # If GPT-5 with chat completions also fails, fallback to gpt-4o as last resort
                        logger.warning(f"GPT-5 with chat completions also failed ({str(gpt5_chat_error)})")
                        logger.warning("Falling back to gpt-4o as last resort")
                        self.model = "gpt-4o"
                        try:
                            def call_gpt4o_fallback_inconsistencies():
                                return self.client.chat.completions.create(
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
                            
                            response = self._retry_with_timeout(
                                call_gpt4o_fallback_inconsistencies,
                                max_retries=3,
                                timeout_seconds=180,  # 3 minutes timeout
                                retry_delay=180,  # Wait 3 minutes before retry
                                operation_name="GPT-4o fallback (analyze_inconsistencies)"
                            )
                            ai_response = json.loads(response.choices[0].message.content)
                        except Exception as fallback_error:
                            error_str_fallback = str(fallback_error)
                            # Check if fallback also has context length error
                            if "context_length" in error_str_fallback.lower() or "maximum context length" in error_str_fallback.lower():
                                logger.warning(f"Context length exceeded even with gpt-4o, batching {len(inconsistencies)} inconsistencies")
                                batch_size = 30
                                return self._analyze_inconsistencies_batched(inconsistencies, vendor, batch_size)
                            else:
                                raise  # Re-raise if it's not a context length error
            else:
                # Use standard chat completions API for other models
                try:
                    def call_chat_completions():
                        return self.client.chat.completions.create(
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
                    
                    response = self._retry_with_timeout(
                        call_chat_completions,
                        max_retries=3,
                        timeout_seconds=180,  # 3 minutes timeout
                        retry_delay=180,  # Wait 3 minutes before retry
                        operation_name=f"Chat completions ({self.model})"
                    )
                    ai_response = json.loads(response.choices[0].message.content)
                except Exception as api_error:
                    error_str = str(api_error)
                    # Check if it's a context length error
                    if "context_length" in error_str.lower() or "maximum context length" in error_str.lower():
                        logger.warning(f"Context length exceeded for {len(inconsistencies)} inconsistencies with model {self.model}")
                        logger.info(f"Automatically batching {len(inconsistencies)} inconsistencies to handle context limit")
                        # Automatically batch if context length is exceeded
                        if self.model == "gpt-5":
                            batch_size = 500  # Very large batches for GPT-5 (128k context window)
                        elif self.model == "gpt-4o":
                            batch_size = 50  # Medium batches for GPT-4o (128k context)
                        else:
                            batch_size = 5  # Small batches for other models (16k context)
                        return self._analyze_inconsistencies_batched(inconsistencies, vendor, batch_size)
                    else:
                        raise  # Re-raise if it's not a context length error
            
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
        For GPT-5, includes full details. For other models, uses compact format.
        
        Args:
            inconsistencies: List of inconsistency dictionaries
            vendor: Vendor name
            
        Returns:
            Formatted string of inconsistencies
        """
        formatted = []
        for idx, inconsistency in enumerate(inconsistencies, 1):
            inc_text = f"\n=== Inconsistency {idx} ===\n"
            inc_text += f"ID: {inconsistency.get('inconsistency_id', f'INC_{idx}')}\n"
            inc_text += f"Type: {inconsistency.get('type', 'Unknown')}\n"
            inc_text += f"Severity: {inconsistency.get('severity', 'MEDIUM')}\n"
            inc_text += f"Description: {inconsistency.get('description', 'N/A')}\n"
            
            # Affected policies - include all for GPT-5 (no truncation needed)
            if vendor == 'fortinet':
                affected_policies = inconsistency.get('affected_fortinet_policies', [])
                if affected_policies:
                    policy_list = ', '.join(str(p) for p in affected_policies)
                    inc_text += f"Affected Fortinet Policies ({len(affected_policies)}): {policy_list}\n"
            elif vendor == 'zscaler':
                affected_policies = inconsistency.get('affected_zscaler_policies', [])
                if affected_policies:
                    policy_list = ', '.join(str(p) for p in affected_policies)
                    inc_text += f"Affected Zscaler Policies ({len(affected_policies)}): {policy_list}\n"
            
            # Affected user groups - include all for GPT-5
            affected_groups = inconsistency.get('affected_user_groups', [])
            if affected_groups:
                group_list = ', '.join(str(g) for g in affected_groups)
                inc_text += f"Affected User Groups ({len(affected_groups)}): {group_list}\n"
            
            # Root cause - include full text for GPT-5
            root_cause = inconsistency.get('root_cause', '')
            if root_cause:
                inc_text += f"Root Cause: {root_cause}\n"
            
            # Business impact - include full text for GPT-5
            business_impact = inconsistency.get('business_impact', '')
            if business_impact:
                inc_text += f"Business Impact: {business_impact}\n"
            
            # Current recommendation - include full text for GPT-5
            recommendation = inconsistency.get('recommendation', '')
            if recommendation:
                inc_text += f"Current Recommendation: {recommendation}\n"
            
            # Remediation steps - include all for GPT-5
            remediation_steps = inconsistency.get('remediation_steps', [])
            if remediation_steps:
                inc_text += f"Remediation Steps ({len(remediation_steps)} total):\n"
                for step_idx, step in enumerate(remediation_steps, 1):
                    inc_text += f"  {step_idx}. {step}\n"
            
            # Evidence - include full evidence for GPT-5
            evidence = inconsistency.get('evidence', {})
            if evidence:
                inc_text += f"Evidence: {json.dumps(evidence, indent=2)}\n"
            
            # Confidence score
            confidence = inconsistency.get('confidence_score', 0.0)
            inc_text += f"Confidence: {confidence:.2f}\n"
            
            formatted.append(inc_text)
        
        return "\n".join(formatted)
    
    def _get_inconsistency_system_prompt(self) -> str:
        """Get the system prompt for AI inconsistency analysis."""
        return """You are an expert firewall policy analyst with 20+ years of experience in network security, firewall management, and security policy analysis. Your expertise covers Fortinet FortiGate, Zscaler, and other major firewall platforms.

You have access to a 128k token context window, allowing you to analyze large numbers of inconsistencies comprehensively in a single analysis.

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
        prompt = f"""You are analyzing ALL {count} firewall policy inconsistencies detected in a {vendor.upper()} firewall configuration.

**IMPORTANT**: You are analyzing ALL {count} inconsistencies together in one comprehensive analysis. This allows you to:
- Identify patterns and relationships between inconsistencies
- Prioritize based on cross-cutting concerns
- Provide comprehensive recommendations that address multiple issues
- Understand the overall security posture and systemic issues

**INCONSISTENCIES TO ANALYZE**:
{inconsistencies_text}

**YOUR TASK**:
For EACH of the {count} inconsistencies above, provide detailed analysis including:

1. **Type Classification**: Precise category and detailed type with explanation
2. **Severity Assessment**: CRITICAL/HIGH/MEDIUM/LOW with detailed justification
3. **Root Cause Analysis**: Deep technical analysis of WHY this occurred
4. **Solution Strategy**: Step-by-step resolution with verification

**SPECIAL CONSIDERATIONS**:
- Look for patterns across inconsistencies (e.g., multiple policies missing UTM, same user groups affected, recurring configuration issues)
- Prioritize inconsistencies that affect security or compliance
- Consider dependencies between inconsistencies
- Provide actionable, specific solutions with commands/config examples where applicable
- Assess business and security impact for each
- Include verification steps for each solution

**FOCUS AREAS**:
- Security implications (exposure, data leakage, access control)
- Business impact (operational disruption, compliance violations)
- Compliance issues (regulatory requirements, audit trails)
- Operational risks (performance, maintenance complexity)
- Logical issues (contradictions, overlaps, missing information)
- Coverage gaps (missing security controls, incomplete protection)

**OUTPUT REQUIREMENTS**:
- Analyze ALL {count} inconsistencies - each must have a corresponding entry in the "analyzed_inconsistencies" array
- Be thorough, technical, and provide comprehensive analysis for each inconsistency
- Provide structured analysis as specified in the system prompt
- Focus on technical accuracy and actionable solutions
- Consider real-world firewall management scenarios
- Security and business impact
- Verification methods

Return your analysis in the JSON format specified in the system prompt."""
        
        return prompt

