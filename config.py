"""
Configuration settings for the Cross-Firewall Policy Analysis Engine.
"""
import os
from typing import List


class Settings:
    """Application settings."""
    
    # Application settings
    PROJECT_NAME: str = "Cross-Firewall Policy Analysis Engine"
    PROJECT_VERSION: str = "1.0.0"
    PROJECT_DESCRIPTION: str = "Analyze and compare firewall policies across vendors for compliance and consistency"
    
    # API settings
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    
    # Supported vendors
    SUPPORTED_VENDORS: List[str] = [
        "fortinet",
        "zscaler"
    ]
    
    # Compliance standards
    SUPPORTED_STANDARDS: List[str] = [
        "GDPR",
        "NIS2",
        "ISO27001",
        "PCI-DSS",
        "HIPAA"
    ]
    
    # Security settings
    SECRET_KEY: str = os.getenv("SECRET_KEY", "cross-firewall-secret-key")
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost",
        "http://localhost:8080",
        "http://127.0.0.1",
        "http://127.0.0.1:8080"
    ]


settings = Settings()