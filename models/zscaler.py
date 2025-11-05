"""
Zscaler cloud security platform specific models.
"""
from typing import List, Optional
from pydantic import BaseModel


class ZscalerLocation(BaseModel):
    """Zscaler location model."""
    id: str
    name: str
    ip_addresses: List[str]
    vpn_credentials: List[str]


class ZscalerUserGroup(BaseModel):
    """Zscaler user group model."""
    id: str
    name: str
    users: List[str]


class ZscalerDepartment(BaseModel):
    """Zscaler department model."""
    id: str
    name: str
    groups: List[str]


class ZscalerApplicationGroup(BaseModel):
    """Zscaler application group model."""
    id: str
    name: str
    applications: List[str]


class ZscalerRule(BaseModel):
    """Zscaler rule model."""
    id: str
    name: str
    locations: List[str]
    departments: List[str]
    users: List[str]
    applications: List[str]
    action: str
    enabled: bool