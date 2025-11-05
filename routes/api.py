"""
Main API routes for cross-firewall policy analysis.
"""
import logging
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse
from typing import List, Dict, Any
import json
import uuid

from parsers.factory import ParserFactory
from analyzers.policy_analyzer import PolicyAnalyzer
from reports.json_report import JSONReportGenerator
from models.base import FirewallConfig, PolicyComparisonResult, ComplianceReport
from utils.visualization import PolicyVisualizer

# Configure logging
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")

# Initialize components
logger.info("Initializing application components")
analyzer = PolicyAnalyzer()
report_generator = JSONReportGenerator()
visualizer = PolicyVisualizer()
logger.info("Application components initialized successfully")

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
async def analyze_single_firewall(config: FirewallConfig) -> Dict[str, Any]:
    """
    Analyze a single firewall configuration for internal inconsistencies.
    
    Args:
        config: The firewall configuration to analyze
        
    Returns:
        Analysis results
    """
    logger.info(f"Starting single firewall analysis for firewall ID: {config.id}")
    try:
        logger.debug("Performing firewall analysis")
        results = analyzer.analyze_single_firewall(config)
        logger.info("Firewall analysis completed successfully")
        
        return results
    except Exception as e:
        logger.error(f"Error analyzing firewall: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error analyzing firewall: {str(e)}")

@router.post("/compare-firewalls")
async def compare_firewalls(config_a: FirewallConfig, config_b: FirewallConfig) -> Dict[str, Any]:
    """
    Compare two firewall configurations.
    
    Args:
        config_a: First firewall configuration
        config_b: Second firewall configuration
        
    Returns:
        Comparison results
    """
    logger.info(f"Starting firewall comparison between {config_a.id} and {config_b.id}")
    try:
        logger.debug("Performing firewall comparison")
        comparison_result = analyzer.compare_firewalls(config_a, config_b)
        logger.info("Firewall comparison completed successfully")
        
        return comparison_result.dict()
    except Exception as e:
        logger.error(f"Error comparing firewalls: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error comparing firewalls: {str(e)}")

@router.post("/check-compliance")
async def check_compliance(config: FirewallConfig, standards: List[str]) -> Dict[str, Any]:
    """
    Check firewall configuration against compliance standards.
    
    Args:
        config: The firewall configuration to check
        standards: List of compliance standards to check against
        
    Returns:
        Compliance check results
    """
    logger.info(f"Starting compliance check for firewall ID: {config.id} against standards: {standards}")
    try:
        logger.debug("Performing compliance check")
        results = analyzer.check_compliance(config, standards)
        logger.info("Compliance check completed successfully")
        
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