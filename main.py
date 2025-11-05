import logging
import logging.config
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes.api import router as api_router
from config import settings

# Configure comprehensive logging
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(levelprefix)s %(asctime)s %(name)s %(process)d:%(thread)d %(message)s",
            "use_colors": None,
        },
        "access": {
            "()": "uvicorn.logging.AccessFormatter",
            "fmt": '%(levelprefix)s %(asctime)s %(name)s %(process)d:%(thread)d %(client_addr)s - "%(request_line)s" %(status_code)s',
        },
    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
        },
        "access": {
            "formatter": "access",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
        },
    },
    "loggers": {
        "": {"handlers": ["default"], "level": "INFO"},  # Root logger
        "uvicorn.error": {"level": "INFO"},
        "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
        "main": {"level": "INFO"},
        "routes.api": {"level": "INFO"},
        "parsers": {"level": "INFO"},
        "analyzers": {"level": "INFO"},
        "reports": {"level": "INFO"},
        "utils": {"level": "INFO"},
    },
}

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

logger.info("Starting Cross-Firewall Policy Analysis Engine")

app = FastAPI(
    title="Cross-Firewall Policy Analysis Engine",
    description="Analyze and compare firewall policies across vendors for compliance and consistency",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Include API routes
app.include_router(api_router)

@app.on_event("startup")
async def startup_event():
    """Event handler for application startup."""
    logger.info("Application startup event triggered")
    logger.info("Cross-Firewall Policy Analysis Engine is starting up")
    logger.info("CORS configured to allow all origins")
    logger.info("FastAPI application ready")
    logger.info("API Documentation endpoints available:")
    logger.info("  - Swagger UI: /docs")
    logger.info("  - ReDoc: /redoc")
    logger.info("  - OpenAPI Schema: /openapi.json")
    logger.info("Application startup completed successfully")

@app.on_event("shutdown")
async def shutdown_event():
    """Event handler for application shutdown."""
    logger.info("Application shutdown event triggered")
    logger.info("Cross-Firewall Policy Analysis Engine is shutting down")
    logger.info("Application shutdown completed successfully")

@app.get("/")
async def root():
    logger.info("Root endpoint accessed")
    logger.debug("Returning welcome message")
    return {"message": "Cross-Firewall Policy Analysis Engine"}

@app.get("/health")
async def health_check():
    logger.info("Health check endpoint accessed")
    logger.debug("Returning healthy status")
    return {"status": "healthy"}

@app.get("/api/v1/vendors")
async def get_supported_vendors():
    """Get list of supported vendors and their version info."""
    logger.info("Supported vendors endpoint accessed")
    logger.debug("Returning list of supported vendors")
    return {
        "vendors": [
            {
                "name": "fortinet",
                "versions": ["6.0", "6.2", "6.4", "7.0"],
                "description": "Fortinet FortiGate firewalls"
            },
            {
                "name": "zscaler",
                "versions": ["20.8", "20.9", "21.1", "21.2"],
                "description": "Zscaler Cloud Security Platform"
            },
            {
                "name": "cisco",
                "versions": ["9.2", "9.3", "9.4", "9.5"],
                "description": "Cisco ASA/FTD firewalls"
            },
            {
                "name": "paloalto",
                "versions": ["9.0", "9.1", "10.0", "10.1"],
                "description": "Palo Alto Networks firewalls (planned)"
            }
        ]
    }

if __name__ == "__main__":
    import uvicorn
    import sys
    import os
    
    # Check environment variable first, then command line argument, then default
    port = int(os.getenv("PORT", "8000"))
    
    # Check if port is specified as command line argument
    if "--port" in sys.argv:
        try:
            port_index = sys.argv.index("--port") + 1
            if port_index < len(sys.argv):
                port = int(sys.argv[port_index])
        except (ValueError, IndexError):
            logger.warning("Invalid port specified, using default port 8000")
            port = 8000
    
    logger.info(f"Starting server on host 0.0.0.0 port {port}")
    logger.info(f"API documentation will be available at: http://0.0.0.0:{port}/docs")
    logger.info(f"Alternative documentation at: http://0.0.0.0:{port}/redoc")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")