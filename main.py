import logging
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from routes.api import router as api_router
import secrets
from config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

app = FastAPI(
    title="Cross-Firewall Policy Analysis Engine",
    description="Analyze and compare firewall policies across vendors for compliance and consistency",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

# Include API routes
app.include_router(api_router)

@app.get("/")
async def root():
    return {"message": "Cross-Firewall Policy Analysis Engine"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/api/v1/vendors")
async def get_supported_vendors():
    """Get list of supported vendors and their version info."""
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
    
    # Default port
    port = 8000
    
    # Check if port is specified as command line argument
    if "--port" in sys.argv:
        try:
            port_index = sys.argv.index("--port") + 1
            if port_index < len(sys.argv):
                port = int(sys.argv[port_index])
        except (ValueError, IndexError):
            print("Invalid port specified, using default port 8000")
    
    print(f"Starting server on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
