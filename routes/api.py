"""
Main API routes for cross-firewall policy analysis.
"""
import logging
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
analyzer = PolicyAnalyzer()
logger.info("Application components initialized successfully")

@router.post("/analyze-firewall")
async def analyze_firewall(vendor: str = Form(...), config_file: UploadFile = File(...)) -> Dict[str, Any]:
    """
    Parse a firewall configuration file and analyze it for inconsistencies.
    
    This endpoint:
    1. Parses the uploaded firewall configuration JSON
    2. Validates the configuration
    3. Analyzes for inconsistencies (conflicts, redundancies, coverage gaps)
    4. Returns the analysis results
    
    Args:
        vendor: The firewall vendor (fortinet, zscaler, etc.)
        config_file: The configuration file to parse and analyze
        
    Returns:
        Analysis results including:
        - Parsed configuration summary
        - Policy conflicts
        - Redundant policies
        - Coverage gaps
        - Risk score
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
        
        # Analyze for inconsistencies
        logger.debug("Starting inconsistency analysis")
        analysis_results = analyzer.analyze_single_firewall(firewall_config)
        logger.info("Inconsistency analysis completed successfully")
        
        # Combine parsed config summary with analysis results
        response = {
            "firewall_config": {
                "id": firewall_config.id,
                "vendor": firewall_config.vendor,
                "version": firewall_config.version,
                "total_policies": len(firewall_config.policies),
                "total_objects": len(firewall_config.objects or [])
            },
            "analysis": analysis_results
        }
        
        logger.info(f"Analysis complete. Found {len(analysis_results.get('conflicts', []))} conflicts, "
                   f"{len(analysis_results.get('redundancies', []))} redundancies, "
                   f"{len(analysis_results.get('coverage_gaps', []))} coverage gaps")
        
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
