"""
Main API routes for cross-firewall policy analysis.
"""
import logging
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import List, Dict, Any
import json
import uuid
import secrets

from parsers.factory import ParserFactory
from analyzers.policy_analyzer import PolicyAnalyzer
from reports.json_report import JSONReportGenerator
from models.base import FirewallConfig, PolicyComparisonResult, ComplianceReport
from utils.visualization import PolicyVisualizer
from utils.database import AnalysisDatabase

# Configure logging
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")

# Initialize components
logger.info("Initializing application components")
analyzer = PolicyAnalyzer()
report_generator = JSONReportGenerator()
visualizer = PolicyVisualizer()
database = AnalysisDatabase()
logger.info("Application components initialized successfully")

# Security
security = HTTPBasic()

# Simple user storage (in production, use a proper database)
users = {
    "admin": "password123",
    "analyst": "analyst123"
}

def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    """Authenticate user credentials."""
    username = credentials.username
    password = credentials.password
    
    if username in users and secrets.compare_digest(password, users[username]):
        return username
    else:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

def optional_auth(credentials: HTTPBasicCredentials = None):
    """Optional authentication for Swagger UI."""
    # In a real implementation, you would validate credentials if provided
    # For now, we'll just return None to indicate no authentication required
    return None


@router.post("/parse-config")
async def parse_config(vendor: str = Form(...), config_file: UploadFile = File(...)) -> Dict[str, Any]:
    """
    Parse a firewall configuration file.
    
    Args:
        vendor: The firewall vendor (fortinet, zscaler, etc.)
        config_file: The configuration file to parse
        
    Returns:
        Parsed firewall configuration
    """
    logger.info(f"Starting to parse configuration for vendor: {vendor}")
    try:
        # Read the uploaded file
        logger.debug(f"Reading uploaded file: {config_file.filename}")
        contents = await config_file.read()
        
        # Parse JSON content
        logger.debug("Parsing JSON content")
        config_data = json.loads(contents)
        logger.info(f"Successfully parsed JSON content with {len(config_data)} items")
        
        # Create appropriate parser
        logger.debug(f"Creating parser for vendor: {vendor}")
        parser = ParserFactory.create_parser(vendor)
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
            
        return firewall_config.dict()
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON format: {str(e)}")
        raise HTTPException(status_code=400, detail="Invalid JSON format")
    except ValueError as e:
        logger.error(f"Value error during parsing: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error parsing configuration: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error parsing configuration: {str(e)}")

@router.post("/analyze-single")
async def analyze_single_firewall(config: FirewallConfig, save_result: bool = True) -> Dict[str, Any]:
    """
    Analyze a single firewall configuration for internal inconsistencies.
    
    Args:
        config: The firewall configuration to analyze
        save_result: Whether to save the result to database
        
    Returns:
        Analysis results
    """
    logger.info(f"Starting single firewall analysis for firewall ID: {config.id}")
    try:
        logger.debug("Performing firewall analysis")
        results = analyzer.analyze_single_firewall(config)
        logger.info("Firewall analysis completed successfully")
        
        # Save to database if requested
        if save_result:
            logger.debug("Saving analysis result to database")
            analysis_id = str(uuid.uuid4())
            database.save_analysis_result(
                analysis_id=analysis_id,
                firewall_id=config.id,
                vendor=config.vendor,
                analysis_type="single_firewall",
                results=results
            )
            results["analysis_id"] = analysis_id
            logger.info(f"Analysis result saved to database with ID: {analysis_id}")
        
        return results
    except Exception as e:
        logger.error(f"Error analyzing firewall: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error analyzing firewall: {str(e)}")

@router.post("/compare-firewalls")
async def compare_firewalls(config_a: FirewallConfig, config_b: FirewallConfig, save_result: bool = True) -> Dict[str, Any]:
    """
    Compare two firewall configurations.
    
    Args:
        config_a: First firewall configuration
        config_b: Second firewall configuration
        save_result: Whether to save the result to database
        
    Returns:
        Comparison results
    """
    logger.info(f"Starting firewall comparison between {config_a.id} and {config_b.id}")
    try:
        logger.debug("Performing firewall comparison")
        comparison_result = analyzer.compare_firewalls(config_a, config_b)
        logger.info("Firewall comparison completed successfully")
        
        # Save to database if requested
        if save_result:
            logger.debug("Saving comparison result to database")
            comparison_id = str(uuid.uuid4())
            database.save_comparison_result(
                comparison_id=comparison_id,
                firewall_a_id=config_a.id,
                firewall_b_id=config_b.id,
                vendor_a=config_a.vendor,
                vendor_b=config_b.vendor,
                results=comparison_result.dict()
            )
            comparison_result_dict = comparison_result.dict()
            comparison_result_dict["comparison_id"] = comparison_id
            logger.info(f"Comparison result saved to database with ID: {comparison_id}")
            return comparison_result_dict
        else:
            logger.debug("Returning comparison result without saving to database")
            return comparison_result.dict()
    except Exception as e:
        logger.error(f"Error comparing firewalls: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error comparing firewalls: {str(e)}")

@router.post("/check-compliance")
async def check_compliance(config: FirewallConfig, standards: List[str], save_result: bool = True) -> Dict[str, Any]:
    """
    Check firewall configuration against compliance standards.
    
    Args:
        config: The firewall configuration to check
        standards: List of compliance standards to check against
        save_result: Whether to save the result to database
        
    Returns:
        Compliance check results
    """
    logger.info(f"Starting compliance check for firewall ID: {config.id} against standards: {standards}")
    try:
        logger.debug("Performing compliance check")
        results = analyzer.check_compliance(config, standards)
        logger.info("Compliance check completed successfully")
        
        # Save to database if requested
        if save_result:
            logger.debug("Saving compliance result to database")
            compliance_id = str(uuid.uuid4())
            database.save_compliance_result(
                compliance_id=compliance_id,
                firewall_id=config.id,
                vendor=config.vendor,
                standards=standards,
                results=results
            )
            results["compliance_id"] = compliance_id
            logger.info(f"Compliance result saved to database with ID: {compliance_id}")
        
        return results
    except Exception as e:
        logger.error(f"Error checking compliance: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error checking compliance: {str(e)}")

@router.post("/generate-report")
async def generate_report(
    report_type: str = Form(...),
    data: str = Form(...),
    export_format: str = Form("json"),
    filename: str = Form(None)
) -> Dict[str, Any]:
    """
    Generate a report from analysis results.
    
    Args:
        report_type: Type of report to generate (comparison, compliance)
        data: JSON string of the analysis data
        export_format: Format to export the report (json, csv, html)
        filename: Optional filename to save the report
        
    Returns:
        Generated report or success message
    """
    logger.info(f"Generating {report_type} report in {export_format} format")
    try:
        logger.debug("Parsing report data")
        report_data = json.loads(data)
        logger.info(f"Report data parsed successfully. Report type: {report_type}")
        
        if report_type == "comparison":
            logger.debug("Generating comparison report")
            comparison_result = PolicyComparisonResult(**report_data)
            report_content = report_generator.generate_comparison_report(comparison_result)
            logger.info("Comparison report generated successfully")
        elif report_type == "compliance":
            logger.debug("Generating compliance report")
            compliance_result = ComplianceReport(**report_data)
            report_content = report_generator.generate_compliance_report(compliance_result)
            logger.info("Compliance report generated successfully")
        else:
            logger.error(f"Unsupported report type: {report_type}")
            raise HTTPException(status_code=400, detail=f"Unsupported report type: {report_type}")
        
        # If export format is specified and filename provided, export to file
        if export_format.lower() != "json" and filename:
            logger.debug(f"Exporting report to {export_format} format with filename: {filename}")
            success = report_generator.export_report(report_content, export_format, filename)
            if success:
                logger.info(f"Report exported successfully to {filename}")
                return {"message": f"Report exported successfully to {filename}"}
            else:
                logger.error("Failed to export report")
                raise HTTPException(status_code=500, detail="Failed to export report")
        elif export_format.lower() == "html":
            # For HTML, return the HTML content directly
            logger.debug("Generating HTML report")
            html_content = report_generator.generate_html_report(report_content)
            logger.info("HTML report generated successfully")
            return {"report": html_content}
        else:
            # Default JSON response
            logger.debug("Returning report in JSON format")
            return {"report": report_content}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON data: {str(e)}")
        raise HTTPException(status_code=400, detail="Invalid JSON data")
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error generating report: {str(e)}")

@router.post("/generate-visualization")
async def generate_visualization(
    viz_type: str = Form(...),
    data: str = Form(...)
) -> Dict[str, Any]:
    """
    Generate visualizations from analysis data.
    
    Args:
        viz_type: Type of visualization to generate (policy_count, action_distribution, compliance_score, overlap_heatmap)
        data: JSON string of the data to visualize
        
    Returns:
        Base64 encoded image
    """
    logger.info(f"Generating visualization of type: {viz_type}")
    try:
        logger.debug("Parsing visualization data")
        viz_data = json.loads(data)
        logger.info("Visualization data parsed successfully")
        
        if viz_type == "policy_count":
            logger.debug("Generating policy count comparison chart")
            config_a = FirewallConfig(**viz_data["config_a"])
            config_b = FirewallConfig(**viz_data["config_b"])
            image = visualizer.generate_policy_count_comparison_chart(config_a.dict(), config_b.dict())
            logger.info("Policy count comparison chart generated successfully")
        elif viz_type == "action_distribution":
            logger.debug("Generating policy action distribution chart")
            config = FirewallConfig(**viz_data["config"])
            image = visualizer.generate_policy_action_distribution_chart(config.dict())
            logger.info("Policy action distribution chart generated successfully")
        elif viz_type == "compliance_score":
            logger.debug("Generating compliance score chart")
            image = visualizer.generate_compliance_score_chart(viz_data)
            logger.info("Compliance score chart generated successfully")
        elif viz_type == "overlap_heatmap":
            logger.debug("Generating policy overlap heatmap")
            config_a = FirewallConfig(**viz_data["config_a"])
            config_b = FirewallConfig(**viz_data["config_b"])
            image = visualizer.generate_policy_overlap_heatmap(config_a.dict(), config_b.dict())
            logger.info("Policy overlap heatmap generated successfully")
        else:
            logger.error(f"Unsupported visualization type: {viz_type}")
            raise HTTPException(status_code=400, detail=f"Unsupported visualization type: {viz_type}")
            
        return {"image": image}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON data: {str(e)}")
        raise HTTPException(status_code=400, detail="Invalid JSON data")
    except Exception as e:
        logger.error(f"Error generating visualization: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error generating visualization: {str(e)}")

@router.get("/visualization-demo")
async def visualization_demo():
    """Demo page for visualizations."""
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Firewall Policy Visualization Demo</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .container { max-width: 800px; margin: 0 auto; }
            .visualization { margin: 20px 0; text-align: center; }
            img { max-width: 100%; height: auto; }
            h1, h2 { color: #333; }
            button { 
                background-color: #4CAF50; 
                color: white; 
                padding: 10px 20px; 
                border: none; 
                cursor: pointer; 
                margin: 5px; 
            }
            button:hover { background-color: #45a049; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Firewall Policy Visualization Demo</h1>
            <p>This page demonstrates the visualization capabilities of the Cross-Firewall Policy Analysis Engine.</p>
            
            <div class="visualization">
                <h2>Policy Count Comparison</h2>
                <img id="policyCountChart" src="" alt="Policy Count Comparison Chart">
                <br>
                <button onclick="generatePolicyCountChart()">Generate Policy Count Chart</button>
            </div>
            
            <div class="visualization">
                <h2>Policy Action Distribution</h2>
                <img id="actionDistributionChart" src="" alt="Policy Action Distribution Chart">
                <br>
                <button onclick="generateActionDistributionChart()">Generate Action Distribution Chart</button>
            </div>
            
            <script>
                async function generatePolicyCountChart() {
                    // Sample data - in a real implementation, this would come from the analysis
                    const data = {
                        config_a: {
                            id: "firewall-a",
                            vendor: "fortinet",
                            policies: Array(45).fill({}) // 45 sample policies
                        },
                        config_b: {
                            id: "firewall-b",
                            vendor: "zscaler",
                            policies: Array(32).fill({}) // 32 sample policies
                        }
                    };
                    
                    const response = await fetch('/api/v1/generate-visualization', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded'
                        },
                        body: `viz_type=policy_count&data=${encodeURIComponent(JSON.stringify(data))}`
                    });
                    
                    const result = await response.json();
                    document.getElementById('policyCountChart').src = 'data:image/png;base64,' + result.image;
                }
                
                async function generateActionDistributionChart() {
                    // Sample data - in a real implementation, this would come from the analysis
                    const data = {
                        config: {
                            id: "sample-firewall",
                            vendor: "fortinet",
                            policies: [
                                ...Array(30).fill({action: "accept"}),
                                ...Array(15).fill({action: "deny"})
                            ]
                        }
                    };
                    
                    const response = await fetch('/api/v1/generate-visualization', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded'
                        },
                        body: `viz_type=action_distribution&data=${encodeURIComponent(JSON.stringify(data))}`
                    });
                    
                    const result = await response.json();
                    document.getElementById('actionDistributionChart').src = 'data:image/png;base64,' + result.image;
                }
            </script>
        </div>
    </body>
    </html>
    """)

@router.get("/analysis/{analysis_id}")
async def get_analysis_result(analysis_id: str) -> Dict[str, Any]:
    """
    Retrieve a saved analysis result.
    
    Args:
        analysis_id: Analysis identifier
        
    Returns:
        Analysis result
    """
    logger.info(f"Retrieving analysis result for ID: {analysis_id}")
    result = database.get_analysis_result(analysis_id)
    if not result:
        logger.warning(f"Analysis result not found for ID: {analysis_id}")
        raise HTTPException(status_code=404, detail="Analysis result not found")
    logger.info(f"Analysis result retrieved successfully for ID: {analysis_id}")
    return result

@router.get("/comparison/{comparison_id}")
async def get_comparison_result(comparison_id: str) -> Dict[str, Any]:
    """
    Retrieve a saved comparison result.
    
    Args:
        comparison_id: Comparison identifier
        
    Returns:
        Comparison result
    """
    logger.info(f"Retrieving comparison result for ID: {comparison_id}")
    result = database.get_comparison_result(comparison_id)
    if not result:
        logger.warning(f"Comparison result not found for ID: {comparison_id}")
        raise HTTPException(status_code=404, detail="Comparison result not found")
    logger.info(f"Comparison result retrieved successfully for ID: {comparison_id}")
    return result

@router.get("/compliance/{compliance_id}")
async def get_compliance_result(compliance_id: str) -> Dict[str, Any]:
    """
    Retrieve a saved compliance result.
    
    Args:
        compliance_id: Compliance check identifier
        
    Returns:
        Compliance result
    """
    logger.info(f"Retrieving compliance result for ID: {compliance_id}")
    result = database.get_compliance_result(compliance_id)
    if not result:
        logger.warning(f"Compliance result not found for ID: {compliance_id}")
        raise HTTPException(status_code=404, detail="Compliance result not found")
    logger.info(f"Compliance result retrieved successfully for ID: {compliance_id}")
    return result

@router.get("/recent-analyses")
async def get_recent_analyses(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Get recent analysis results.
    
    Args:
        limit: Maximum number of results to return
        
    Returns:
        List of recent analysis results
    """
    logger.info(f"Retrieving recent analyses with limit: {limit}")
    results = database.get_recent_analyses(limit)
    logger.info(f"Retrieved {len(results)} recent analyses")
    return results
