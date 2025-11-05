"""
Main API routes for cross-firewall policy analysis.
"""
import logging
import os
import re
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from typing import Dict, Any
import json

from parsers.factory import ParserFactory
from analyzers.policy_analyzer import PolicyAnalyzer

# Configure logging
logger = logging.getLogger(__name__)


def _fix_json_syntax(json_str: str) -> str:
    """
    Fix common JSON syntax errors.
    
    Args:
        json_str: JSON string to fix
        
    Returns:
        Fixed JSON string
    """
    # Fix missing commas between objects: } { -> }, {
    json_str = re.sub(r'}\s*{', '}, {', json_str)
    
    # Fix missing commas before closing brackets: } ] -> }, ]
    json_str = re.sub(r'}\s*\]', '}]', json_str)
    
    # Fix missing commas after values before next object: "value" { -> "value", {
    json_str = re.sub(r'"\s*{', '", {', json_str)
    
    # Fix trailing commas before closing brackets/braces
    json_str = re.sub(r',\s*}', '}', json_str)
    json_str = re.sub(r',\s*]', ']', json_str)
    
    return json_str


def _aggressive_json_fix(json_str: str) -> str:
    """
    Aggressively fix JSON syntax errors.
    
    Args:
        json_str: JSON string to fix
        
    Returns:
        Fixed JSON string
    """
    # First, try to extract array from object
    if json_str.strip().startswith('{') and '[' in json_str:
        first_bracket = json_str.find('[')
        last_bracket = json_str.rfind(']')
        if first_bracket != -1 and last_bracket != -1:
            json_str = json_str[first_bracket:last_bracket + 1]
    
    # Fix missing commas between objects (more aggressive)
    # Pattern: } followed by whitespace and { -> }, {
    json_str = re.sub(r'}\s*\n\s*{', '},\n{', json_str)
    json_str = re.sub(r'}\s*{', '}, {', json_str)
    
    # Fix missing commas after strings before objects
    json_str = re.sub(r'"\s*\n\s*{', '",\n{', json_str)
    json_str = re.sub(r'"\s*{', '", {', json_str)
    
    # Fix missing commas after numbers before objects
    json_str = re.sub(r'(\d)\s*{', r'\1, {', json_str)
    
    # Fix missing commas after booleans before objects
    json_str = re.sub(r'(true|false)\s*{', r'\1, {', json_str)
    
    # Fix missing commas after null before objects
    json_str = re.sub(r'null\s*{', 'null, {', json_str)
    
    # Fix missing commas after closing braces before objects
    json_str = re.sub(r'}\s*\n\s*{', '},\n{', json_str)
    
    # Remove trailing commas
    json_str = re.sub(r',\s*}', '}', json_str)
    json_str = re.sub(r',\s*]', ']', json_str)
    
    # Fix missing commas after closing braces (before next object in array)
    json_str = re.sub(r'}\s*\n\s*{', '},\n{', json_str)
    
    return json_str

router = APIRouter(prefix="/api/v1")

# Initialize components
logger.info("Initializing application components")
# Get OpenAI API key from environment variable
openai_api_key = os.getenv("OPENAI_API_KEY")
openai_model = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")  # Default to gpt-3.5-turbo

logger.info(f"Checking for OpenAI API key: {'FOUND' if openai_api_key else 'NOT FOUND'}")
if openai_api_key:
    logger.info(f"OpenAI API key found in environment variable (length: {len(openai_api_key)} chars)")
    logger.info(f"Using OpenAI model: {openai_model}")
else:
    logger.warning("=" * 80)
    logger.warning("OPENAI_API_KEY not found in environment. AI analysis will be DISABLED.")
    logger.warning("To enable AI analysis, set the OPENAI_API_KEY environment variable:")
    logger.warning("  export OPENAI_API_KEY='your-api-key-here'")
    logger.warning("=" * 80)

analyzer = PolicyAnalyzer(
    use_ai=True,
    openai_api_key=openai_api_key,
    openai_model=openai_model
)

# Log AI analyzer status
if hasattr(analyzer, 'ai_analyzer') and analyzer.ai_analyzer:
    if hasattr(analyzer.ai_analyzer, 'client') and analyzer.ai_analyzer.client:
        logger.info("✓ AI analyzer is READY and will be used for analysis")
    else:
        logger.warning("✗ AI analyzer exists but OpenAI client is NOT available")
else:
    logger.warning("✗ AI analyzer is NOT available - AI analysis will be skipped")

logger.info("Application components initialized successfully")

@router.post("/analyze-firewall")
async def analyze_firewall(vendor: str = Form(...), config_file: UploadFile = File(...)) -> Dict[str, Any]:
    """
    Parse a firewall configuration file and analyze it for inconsistencies.
    
    This endpoint:
    1. Parses the uploaded firewall configuration JSON
    2. Validates the configuration
    3. Analyzes for inconsistencies using:
       - Rule-based analysis (conflicts, redundancies, coverage gaps)
       - AI-powered analysis using OpenAI GPT-3.5 Turbo (if API key is configured)
    4. Returns the combined analysis results
    
    Args:
        vendor: The firewall vendor (fortinet, zscaler, etc.)
        config_file: The configuration file to parse and analyze
        
    Returns:
        Analysis results including:
        - Parsed configuration summary
        - Rule-based analysis (conflicts, redundancies, coverage gaps, risk score)
        - AI-powered analysis (findings, recommendations, risk assessment)
        
    Environment Variables:
        OPENAI_API_KEY: OpenAI API key for AI-powered analysis (required for AI analysis)
        OPENAI_MODEL: OpenAI model to use (default: gpt-3.5-turbo, optional)
        
    Note:
        - The API key is automatically fetched from the OPENAI_API_KEY environment variable
        - If OPENAI_API_KEY is not set, only rule-based analysis will be performed
        - You can override the model by setting OPENAI_MODEL environment variable
    """
    logger.info(f"Starting firewall analysis for vendor: {vendor}")
    try:
        # Read the uploaded file
        logger.debug(f"Reading uploaded file: {config_file.filename}")
        contents = await config_file.read()
        
        # Parse JSON content - handle standard JSON formats
        logger.debug("Parsing JSON content")
        contents_str = contents.decode('utf-8') if isinstance(contents, bytes) else contents
        
        # Parse JSON - expects standard valid JSON format
        try:
            config_data = json.loads(contents_str)
            logger.debug("JSON parsing successful")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON format: {str(e)}")
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid JSON format. Please ensure your JSON is valid. Error: {str(e)}"
            )
        
        # Handle different JSON structures (standard formats)
        # Format 1: Direct array of policies: [{...}, {...}]
        if isinstance(config_data, list):
            logger.info("Received JSON array format")
            # Already in correct format
        
        # Format 2: Object with 'policies' key: {"policies": [{...}, {...}]} or {"device": {...}, "policies": [...]}
        elif isinstance(config_data, dict):
            # Check for common keys that contain arrays
            for key in ['policies', 'rules', 'config', 'data', 'items', 'objects', 'firewall_policies']:
                if key in config_data and isinstance(config_data[key], list):
                    logger.info(f"Extracted array from object key: '{key}'")
                    config_data = config_data[key]
                    break
            else:
                # If no array found in common keys, check single key
                if len(config_data) == 1:
                    for key, value in config_data.items():
                        if isinstance(value, list):
                            logger.info(f"Extracted array from single-key object: '{key}'")
                            config_data = value
                            break
                        elif isinstance(value, dict):
                            # Check nested structure (e.g., {"device": {...}, "policies": [...]})
                            for nested_key in ['policies', 'rules', 'config', 'data']:
                                if nested_key in value and isinstance(value[nested_key], list):
                                    logger.info(f"Extracted array from nested object: '{key}.{nested_key}'")
                                    config_data = value[nested_key]
                                    break
                            if isinstance(config_data, list):
                                break
                
                # If still a dict, check if all values are objects (convert to list)
                if isinstance(config_data, dict):
                    if all(isinstance(v, dict) for v in config_data.values()):
                        config_data = list(config_data.values())
                        logger.info("Converted dict of objects to list")
                    else:
                        # Single object, wrap in array
                        config_data = [config_data]
                        logger.info("Wrapped single object in array")
        
        # Ensure we have a list at the end
        if not isinstance(config_data, list):
            config_data = [config_data]
            logger.info("Wrapped data in array")
        
        logger.info(f"Successfully parsed JSON content with {len(config_data) if isinstance(config_data, list) else 'N/A'} items")
        
        # Create appropriate parser
        logger.debug(f"Creating parser for vendor: {vendor}")
        parser = ParserFactory.create_parser(vendor.lower())
        logger.info(f"Parser created successfully for vendor: {vendor}")
        
        # Parse the configuration
        logger.debug("Parsing configuration data")
        firewall_config = parser.parse(config_data)
        logger.info(f"Configuration parsed successfully. Firewall ID: {firewall_config.id}")
        
        # Validate the configuration
        logger.debug("Validating configuration")
        if not parser.validate_config(firewall_config):
            logger.error("Invalid configuration data")
            raise HTTPException(status_code=400, detail="Invalid configuration data")
        logger.info("Configuration validated successfully")
        
        # Analyze for inconsistencies (includes both rule-based and AI analysis)
        logger.debug("Starting inconsistency analysis")
        analysis_results = analyzer.analyze_single_firewall(firewall_config)
        logger.info("Inconsistency analysis completed successfully")
        
        # Extract analysis results
        summary = analysis_results.get("summary", {})
        inconsistencies = analysis_results.get("inconsistencies", [])
        rule_based = analysis_results.get("rule_based_analysis", {})
        ai_analysis = analysis_results.get("ai_analysis", {})
        
        # Format response in the requested structure
        response = {
            "summary": summary,
            "inconsistencies": inconsistencies,
            "firewall_config": {
                "id": firewall_config.id,
                "vendor": firewall_config.vendor,
                "version": firewall_config.version,
                "total_policies": len(firewall_config.policies),
                "total_objects": len(firewall_config.objects or [])
            },
            "additional_analysis": {
                "rule_based": rule_based,
                "ai_powered": ai_analysis
            }
        }
        
        # Log summary
        total_inconsistencies = summary.get("total_inconsistencies", 0)
        high_severity = summary.get("high_severity", 0)
        medium_severity = summary.get("medium_severity", 0)
        low_severity = summary.get("low_severity", 0)
        ai_findings_count = len(ai_analysis.get("findings", [])) if ai_analysis.get("enabled") else 0
        
        logger.info(f"Analysis complete. Total inconsistencies: {total_inconsistencies} "
                   f"(HIGH: {high_severity}, MEDIUM: {medium_severity}, LOW: {low_severity}). "
                   f"AI analysis: {ai_findings_count} findings")
        
        return response
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON format: {str(e)}")
        raise HTTPException(status_code=400, detail="Invalid JSON format")
    except ValueError as e:
        logger.error(f"Value error during parsing: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error analyzing firewall: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error analyzing firewall: {str(e)}")
