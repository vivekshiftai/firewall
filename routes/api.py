"""
Main API routes for cross-firewall policy analysis.
"""
import logging
import os
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from typing import Dict, Any
import json

from parsers.factory import ParserFactory
from analyzers.policy_analyzer import PolicyAnalyzer

# Configure logging
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")

# Initialize components
logger.info("Initializing application components")
# Get OpenAI API key from environment variable
openai_api_key = os.getenv("OPENAI_API_KEY")
openai_model = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")  # Default to gpt-3.5-turbo

if openai_api_key:
    logger.info("OpenAI API key found in environment variable")
else:
    logger.warning("OPENAI_API_KEY not found in environment. AI analysis will be disabled.")

analyzer = PolicyAnalyzer(
    use_ai=True,
    openai_api_key=openai_api_key,
    openai_model=openai_model
)
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
        
        # Parse JSON content
        logger.debug("Parsing JSON content")
        config_data = json.loads(contents)
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
        
        # Extract rule-based and AI analysis results
        rule_based = analysis_results.get("rule_based_analysis", {})
        ai_analysis = analysis_results.get("ai_analysis", {})
        
        # Combine parsed config summary with analysis results
        response = {
            "firewall_config": {
                "id": firewall_config.id,
                "vendor": firewall_config.vendor,
                "version": firewall_config.version,
                "total_policies": len(firewall_config.policies),
                "total_objects": len(firewall_config.objects or [])
            },
            "analysis": {
                "rule_based": rule_based,
                "ai_powered": ai_analysis
            }
        }
        
        # Log summary
        conflicts_count = len(rule_based.get("conflicts", []))
        redundancies_count = len(rule_based.get("redundancies", []))
        gaps_count = len(rule_based.get("coverage_gaps", []))
        ai_findings_count = len(ai_analysis.get("findings", [])) if ai_analysis.get("enabled") else 0
        
        logger.info(f"Analysis complete. Rule-based: {conflicts_count} conflicts, "
                   f"{redundancies_count} redundancies, {gaps_count} coverage gaps. "
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
