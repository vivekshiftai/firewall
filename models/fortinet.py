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
    """Fortinet policy model with all FortiGate fields."""
    # Required fields
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
    
    # Optional basic fields
    comments: Optional[str] = None
    srcaddr_negate: Optional[str] = None  # enable, disable
    service_negate: Optional[str] = None  # enable, disable
    
    # Internet service fields
    internet_service: Optional[str] = None  # enable, disable
    internet_service_id: Optional[List[int]] = None
    
    # Application fields
    application: Optional[List[int]] = None  # app IDs
    
    # User/Group fields
    users: Optional[List[str]] = None
    groups: Optional[List[str]] = None
    fsso: Optional[str] = None  # enable, disable
    ntlm: Optional[str] = None  # enable, disable
    wsso: Optional[str] = None  # enable, disable
    
    # NAT fields
    nat: Optional[str] = None  # enable, disable
    natip: Optional[str] = None
    ippool: Optional[str] = None  # enable, disable
    poolname: Optional[str] = None
    rtp_nat: Optional[str] = None  # enable, disable
    permit_any_host: Optional[str] = None  # enable, disable
    match_vip: Optional[str] = None  # enable, disable
    rtp_addr: Optional[str] = None
    
    # Traffic shaping
    traffic_shaper: Optional[str] = None
    session_ttl: Optional[int] = None
    vlan_cos_fwd: Optional[int] = None
    
    # UTM fields
    utm_status: Optional[str] = None  # enable, disable
    inspection_mode: Optional[str] = None  # proxy, flow
    av_profile: Optional[str] = None
    webfilter_profile: Optional[str] = None
    dnsfilter_profile: Optional[str] = None
    emailfilter_profile: Optional[str] = None
    dlp_sensor: Optional[str] = None
    ips_sensor: Optional[str] = None
    voip_profile: Optional[str] = None
    waf_profile: Optional[str] = None
    ssh_filter_profile: Optional[str] = None
    ssl_ssh_profile: Optional[str] = None
    profile_type: Optional[str] = None  # single, group
    profile_group: Optional[str] = None
    
    # Policy redirects
    http_policy_redirect: Optional[str] = None  # enable, disable
    ssh_policy_redirect: Optional[str] = None  # enable, disable
    webproxy_profile: Optional[str] = None
    
    # Logging fields
    logtraffic: Optional[str] = None  # all, utm, disable
    logtraffic_start: Optional[str] = None  # enable, disable
    capture_packet: Optional[str] = None  # enable, disable
    custom_log_fields: Optional[List[str]] = None
    
    # TOS fields
    tos: Optional[str] = None  # 0x00, 0x10, etc.
    tos_mask: Optional[str] = None
    tos_negate: Optional[str] = None  # enable, disable
    
    # Security fields
    anti_replay: Optional[str] = None  # enable, disable
    tcp_session_without_syn: Optional[str] = None  # all, data-only, disable
    
    # VPN fields
    vpntunnel: Optional[str] = None
    inbound: Optional[str] = None  # enable, disable
    outbound: Optional[str] = None  # enable, disable
    
    # Optimization fields
    wanopt: Optional[str] = None  # enable, disable
    webcache: Optional[str] = None  # enable, disable
    
    # Reputation
    reputation_minimum: Optional[int] = None
    
    # Authentication fields
    auth_cert: Optional[str] = None
    auth_redirect_addr: Optional[str] = None
    redirect_url: Optional[str] = None
    
    # QoS fields
    diffservcode_forward: Optional[int] = None
    identity_based_route: Optional[str] = None


class FortinetZone(BaseModel):
    """Fortinet zone model."""
    name: str
    interface: List[str]
    intrazone: bool