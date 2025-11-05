"""
Fortinet FortiGate specific models.
"""
from typing import List, Optional
from pydantic import BaseModel


class FortinetAddressObject(BaseModel):
    """Fortinet address object model."""
    name: str
    type: str
    subnet: Optional[str] = None
    fqdn: Optional[str] = None
    comment: Optional[str] = None


class FortinetServiceObject(BaseModel):
    """Fortinet service object model."""
    name: str
    protocol: str
    port_range: Optional[str] = None
    comment: Optional[str] = None


class FortinetPolicy(BaseModel):
    """Fortinet policy model."""
    id: int
    name: str
    srcintf: List[str]
    dstintf: List[str]
    srcaddr: List[str]
    dstaddr: List[str]
    service: List[str]
    action: str
    status: str
    schedule: str
    comments: Optional[str] = None


class FortinetZone(BaseModel):
    """Fortinet zone model."""
    name: str
    interface: List[str]
    intrazone: bool