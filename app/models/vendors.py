"""
Data models for multi-vendor firewall support.
"""
from enum import Enum
from typing import List, Dict, Optional
from pydantic import BaseModel
from datetime import datetime


class VendorType(str, Enum):
    """Enumeration of supported firewall vendors."""
    FORTINET = "fortinet"
    ZSCALER = "zscaler"
    CISCO = "cisco"
    PALO_ALTO = "palo_alto"
    PFSENSE = "pfsense"


class VendorInfo(BaseModel):
    """Information about a specific vendor and configuration."""
    vendor_name: str
    vendor_version: str
    config_format: str  # json, xml, cli
    features_supported: List[str]
    last_updated: datetime


class VendorNormalizedPolicy(BaseModel):
    """Normalized policy model that abstracts vendor differences."""
    policy_id: str  # unique within firewall
    policy_name: str
    source_entity: str  # IP, user group, location, VLAN
    source_entity_type: str  # ip_range, user_group, location, zone
    dest_entity: str
    dest_entity_type: str
    application_protocol: List[str]  # tcp, udp, http, ssl, etc.
    ports: List[int] | str  # port ranges
    action: str  # allow, deny, quarantine, redirect
    enforcement_layer: str  # network, application, user
    priority: int  # lower = higher priority
    enabled: bool
    logging_enabled: bool
    enforcement_technologies: List[str]  # firewall, dlp, ips, av, etc.
    vendor_specific_data: Dict  # store vendor-specific fields
    source_vendor: VendorType
    timestamp_added: datetime
    timestamp_modified: datetime


class NormalizedZone(BaseModel):
    """Normalized zone model that abstracts network zones."""
    zone_id: str
    zone_name: str
    zone_type: str  # dmz, internal, restricted, guest, external, untrusted
    entities: List[str]  # IPs, subnets, location IDs, VLAN IDs in this zone
    trust_level: str  # untrusted, semi-trusted, trusted
    vendor_specific_type: str  # keep vendor's native type
    source_vendor: VendorType


class NormalizedUserGroup(BaseModel):
    """Normalized user group model that abstracts user categories."""
    group_id: str
    group_name: str
    group_type: str  # admin, user, contractor, guest, service_account
    member_count: Optional[int]
    requires_mfa: bool
    requires_vpn: bool
    allowed_applications: List[str]
    data_access_level: str  # restricted, confidential, internal, public
    source_vendor: VendorType


class VendorParsedConfig(BaseModel):
    """Vendor-neutral configuration representation."""
    config_id: str
    vendor: VendorType
    vendor_info: VendorInfo
    policies: List[VendorNormalizedPolicy]
    zones: List[NormalizedZone]
    user_groups: List[NormalizedUserGroup]
    addresses: Dict[str, str]  # address_id → address_value
    services: Dict[str, Dict]  # service_id → service_definition
    statistics: Dict  # policy count, zone count, etc.