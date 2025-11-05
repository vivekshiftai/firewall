"""
Fortinet firewall configuration parser.
"""
import logging
from typing import Dict, Any, List, Union
from parsers.base import BaseParser
from models.base import FirewallConfig
from models.fortinet import FortinetPolicy, FortinetAddressObject, FortinetServiceObject
from exceptions.custom_exceptions import ParserError

# Configure logging
logger = logging.getLogger(__name__)

class FortinetParser(BaseParser):
    """Parser for Fortinet firewall configurations."""

    def parse(self, config_data: Union[Dict[str, Any], List[Dict[str, Any]]]) -> FirewallConfig:
        """
        Parse Fortinet configuration data into a standardized FirewallConfig.
        
        Args:
            config_data: Raw Fortinet configuration data (can be dict or list)
            
        Returns:
            Standardized FirewallConfig object
        """
        logger.info("Starting Fortinet configuration parsing")
        try:
            # Handle case where config_data is a list (array of policies)
            if isinstance(config_data, list):
                logger.info(f"Received list of {len(config_data)} items, treating as policies")
                config_data = {
                    "id": "fortinet-firewall",
                    "version": "unknown",
                    "policies": config_data,
                    "addresses": [],
                    "services": [],
                    "metadata": {}
                }
            
            # Extract basic information
            logger.debug("Extracting basic firewall information")
            firewall_id = config_data.get("id", "fortinet-firewall")
            version = config_data.get("version", "unknown")
            logger.info(f"Parsing Fortinet firewall ID: {firewall_id}, Version: {version}")
            
            # Parse policies
            logger.debug("Parsing policies")
            policies_data = config_data.get("policies", [])
            # If policies is a list, use it directly; otherwise try to extract it
            if isinstance(policies_data, list):
                policies = self._parse_policies(policies_data)
            else:
                logger.warning("Policies data is not a list, attempting to convert")
                policies = self._parse_policies([policies_data] if policies_data else [])
            logger.info(f"Parsed {len(policies)} policies")
            
            # Parse address objects
            logger.debug("Parsing address objects")
            address_objects = self._parse_address_objects(config_data.get("addresses", []))
            logger.info(f"Parsed {len(address_objects)} address objects")
            
            # Parse service objects
            logger.debug("Parsing service objects")
            service_objects = self._parse_service_objects(config_data.get("services", []))
            logger.info(f"Parsed {len(service_objects)} service objects")
            
            # Create standardized config
            logger.debug("Creating standardized firewall configuration")
            firewall_config = FirewallConfig(
                id=firewall_id,
                vendor="fortinet",
                version=version,
                policies=policies,
                objects=address_objects + service_objects,
                metadata=config_data.get("metadata", {})
            )
            
            logger.info("Fortinet configuration parsing completed successfully")
            return firewall_config
            
        except Exception as e:
            logger.error(f"Error parsing Fortinet configuration: {str(e)}")
            raise ParserError(f"Error parsing Fortinet configuration: {str(e)}")

    def _is_policy(self, policy_data: Dict[str, Any]) -> bool:
        """
        Check if the data looks like a firewall policy.
        
        Args:
            policy_data: Raw policy data to check
            
        Returns:
            True if it looks like a policy, False otherwise
        """
        if not isinstance(policy_data, dict):
            return False
        
        # Check for required policy fields (either exact or with variations)
        has_srcintf = ("srcintf" in policy_data or "source_interface" in policy_data or 
                      "source-interface" in policy_data or "srcintf" in str(policy_data).lower())
        has_dstintf = ("dstintf" in policy_data or "destination_interface" in policy_data or 
                      "destination-interface" in policy_data or "dstintf" in str(policy_data).lower())
        has_srcaddr = ("srcaddr" in policy_data or "source_address" in policy_data or 
                      "source-address" in policy_data or "srcaddr" in str(policy_data).lower())
        has_dstaddr = ("dstaddr" in policy_data or "destination_address" in policy_data or 
                      "destination-address" in policy_data or "dstaddr" in str(policy_data).lower())
        has_action = "action" in policy_data
        has_service = "service" in policy_data or "services" in policy_data
        
        # Check for policy identifier (policyid, policy_id, id)
        has_policy_id = "policyid" in policy_data or "policy_id" in policy_data or "id" in policy_data
        
        # A valid policy should have:
        # 1. At least source/destination interfaces or addresses, AND
        # 2. An action, AND  
        # 3. Either a policy ID or name (to identify it)
        has_source = has_srcintf or has_srcaddr
        has_destination = has_dstintf or has_dstaddr
        has_identifier = has_policy_id or "name" in policy_data
        
        return has_source and has_destination and has_action and has_identifier
    
    def _parse_policies(self, policies_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse Fortinet policies into standardized format.
        
        Args:
            policies_data: Raw policy data (may contain non-policy objects)
            
        Returns:
            List of standardized policies
        """
        logger.debug(f"Parsing {len(policies_data)} Fortinet policy items")
        policies = []
        skipped = 0
        
        for i, policy_data in enumerate(policies_data):
            try:
                # Skip if it doesn't look like a policy
                if not self._is_policy(policy_data):
                    logger.debug(f"Skipping item {i+1} - does not appear to be a firewall policy")
                    logger.debug(f"  Item keys: {list(policy_data.keys()) if isinstance(policy_data, dict) else 'not a dict'}")
                    skipped += 1
                    continue
                
                logger.debug(f"Parsing policy {i+1}: {policy_data.get('name', policy_data.get('policyid', 'unknown'))}")
                
                # Map field variations to expected format
                mapped_data = self._map_policy_fields(policy_data)
                
                # Ensure all required fields are present for FortinetPolicy
                required_fields = ['id', 'name', 'srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service', 'action', 'status', 'schedule']
                missing_fields = [f for f in required_fields if f not in mapped_data]
                if missing_fields:
                    logger.warning(f"Policy {i+1} missing required fields: {missing_fields}")
                    # Add defaults for missing required fields
                    if 'status' not in mapped_data:
                        mapped_data['status'] = 'enable'
                    if 'schedule' not in mapped_data:
                        mapped_data['schedule'] = 'always'
                
                # Try to create FortinetPolicy object
                fortinet_policy = FortinetPolicy(**mapped_data)
                
                # Convert to standardized format
                standardized_policy = {
                    "id": str(fortinet_policy.id),
                    "name": fortinet_policy.name,
                    "source_zones": fortinet_policy.srcintf,
                    "destination_zones": fortinet_policy.dstintf,
                    "source_addresses": fortinet_policy.srcaddr,
                    "destination_addresses": fortinet_policy.dstaddr,
                    "services": fortinet_policy.service,
                    "action": fortinet_policy.action,
                    "enabled": fortinet_policy.status == "enable",
                    "logging": getattr(fortinet_policy, "log", "disable") != "disable",
                    "schedule": fortinet_policy.schedule,
                    "comments": getattr(fortinet_policy, "comments", "")
                }
                
                # Extract ALL fields from original policy data - preserve everything
                original_policy = policy_data
                
                # First, preserve ALL original fields for maximum data extraction
                for key, value in original_policy.items():
                    # Skip fields we've already processed
                    if key not in ["id", "policy_id", "name", "policy_name", "srcintf", "dstintf", 
                                  "srcaddr", "dstaddr", "service", "services", "action", "status", 
                                  "schedule", "comments", "comment"]:
                        # Preserve original field name AND add standardized version if applicable
                        standardized_policy[key] = value
                
                # Map all Fortinet fields to standardized policy (with variations)
                field_mappings = {
                    # Basic fields
                    "groups": ["groups", "group-name", "group_name"],
                    "users": ["users", "user-name", "user_name"],
                    "srcaddr_negate": ["srcaddr-negate", "srcaddr_negate", "srcaddr-negate"],
                    "service_negate": ["service-negate", "service_negate", "service-negate"],
                    
                    # Internet service
                    "internet_service": ["internet-service", "internet_service"],
                    "internet_service_id": ["internet-service-id", "internet_service_id", "internet-service-id"],
                    
                    # Application
                    "application": ["application", "application-list", "application_list"],
                    
                    # User/Group auth
                    "fsso": ["fsso"],
                    "ntlm": ["ntlm"],
                    "wsso": ["wsso"],
                    
                    # NAT fields
                    "nat": ["nat"],
                    "natip": ["natip", "nat-ip"],
                    "ippool": ["ippool", "ip-pool"],
                    "poolname": ["poolname", "pool-name"],
                    "rtp_nat": ["rtp-nat", "rtp_nat"],
                    "permit_any_host": ["permit-any-host", "permit_any_host"],
                    "match_vip": ["match-vip", "match_vip"],
                    "rtp_addr": ["rtp-addr", "rtp_addr"],
                    
                    # Traffic shaping
                    "traffic_shaper": ["traffic-shaper", "traffic_shaper"],
                    "session_ttl": ["session-ttl", "session_ttl"],
                    "vlan_cos_fwd": ["vlan-cos-fwd", "vlan_cos_fwd"],
                    
                    # UTM fields
                    "utm_status": ["utm-status", "utm_status"],
                    "inspection_mode": ["inspection-mode", "inspection_mode"],
                    "av_profile": ["av-profile", "av_profile"],
                    "webfilter_profile": ["webfilter-profile", "webfilter_profile"],
                    "dnsfilter_profile": ["dnsfilter-profile", "dnsfilter_profile"],
                    "emailfilter_profile": ["emailfilter-profile", "emailfilter_profile"],
                    "dlp_sensor": ["dlp-sensor", "dlp_sensor"],
                    "ips_sensor": ["ips-sensor", "ips_sensor"],
                    "voip_profile": ["voip-profile", "voip_profile"],
                    "waf_profile": ["waf-profile", "waf_profile"],
                    "ssh_filter_profile": ["ssh-filter-profile", "ssh_filter_profile"],
                    "ssl_ssh_profile": ["ssl-ssh-profile", "ssl_ssh_profile"],
                    "profile_type": ["profile-type", "profile_type"],
                    "profile_group": ["profile-group", "profile_group"],
                    
                    # Policy redirects
                    "http_policy_redirect": ["http-policy-redirect", "http_policy_redirect"],
                    "ssh_policy_redirect": ["ssh-policy-redirect", "ssh_policy_redirect"],
                    "webproxy_profile": ["webproxy-profile", "webproxy_profile"],
                    
                    # Logging
                    "logtraffic": ["logtraffic", "log-traffic"],
                    "logtraffic_start": ["logtraffic-start", "logtraffic_start"],
                    "capture_packet": ["capture-packet", "capture_packet"],
                    "custom_log_fields": ["custom-log-fields", "custom_log_fields"],
                    
                    # TOS
                    "tos": ["tos"],
                    "tos_mask": ["tos-mask", "tos_mask"],
                    "tos_negate": ["tos-negate", "tos_negate"],
                    
                    # Security
                    "anti_replay": ["anti-replay", "anti_replay"],
                    "tcp_session_without_syn": ["tcp-session-without-syn", "tcp_session_without_syn"],
                    
                    # VPN
                    "vpntunnel": ["vpntunnel", "vpn-tunnel"],
                    "inbound": ["inbound"],
                    "outbound": ["outbound"],
                    
                    # Optimization
                    "wanopt": ["wanopt"],
                    "webcache": ["webcache"],
                    
                    # Reputation
                    "reputation_minimum": ["reputation-minimum", "reputation_minimum"],
                    
                    # Authentication
                    "auth_cert": ["auth-cert", "auth_cert"],
                    "auth_redirect_addr": ["auth-redirect-addr", "auth_redirect_addr"],
                    "redirect_url": ["redirect-url", "redirect_url"],
                    
                    # QoS
                    "diffservcode_forward": ["diffservcode-forward", "diffservcode_forward"],
                    "identity_based_route": ["identity-based-route", "identity_based_route"]
                }
                
                # Extract all fields using the mappings (preserve original AND add standardized)
                for std_field, field_variants in field_mappings.items():
                    for variant in field_variants:
                        if variant in original_policy:
                            value = original_policy[variant]
                            # Keep original field name (already done above, but ensure it's there)
                            standardized_policy[variant] = value
                            # Also add standardized name for consistency
                            standardized_policy[std_field] = value
                            break
                
                # Extract any remaining unknown fields that weren't in our mappings
                # This ensures we capture ALL data, even fields we don't know about
                for key, value in original_policy.items():
                    # Only add if not already processed
                    if key not in standardized_policy:
                        standardized_policy[key] = value
                        logger.debug(f"Preserved unknown field: {key}")
                
                policies.append(standardized_policy)
                logger.debug(f"Policy {i+1} parsed successfully")
            except Exception as e:
                logger.warning(f"Error parsing policy {i+1}: {str(e)}")
                logger.debug(f"  Policy data keys: {list(policy_data.keys()) if isinstance(policy_data, dict) else 'not a dict'}")
                import traceback
                logger.debug(f"  Traceback: {traceback.format_exc()}")
                skipped += 1
                continue
        
        logger.info(f"Successfully parsed {len(policies)} out of {len(policies_data)} items ({skipped} skipped)")
        return policies
    
    def _map_policy_fields(self, policy_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map policy fields from various formats to standard FortinetPolicy format.
        
        Args:
            policy_data: Raw policy data with potentially different field names
            
        Returns:
            Mapped policy data in FortinetPolicy format
        """
        mapped = {}
        
        # Map ID field - handle policyid, policy_id, and id
        policy_id = None
        if "policyid" in policy_data:
            policy_id = int(policy_data["policyid"]) if isinstance(policy_data["policyid"], (int, str)) else policy_data["policyid"]
        elif "id" in policy_data:
            policy_id = int(policy_data["id"]) if isinstance(policy_data["id"], (int, str)) else policy_data["id"]
        elif "policy_id" in policy_data:
            policy_id = int(policy_data["policy_id"]) if isinstance(policy_data["policy_id"], (int, str)) else policy_data["policy_id"]
        
        if policy_id is None:
            policy_id = 0  # Default ID if not found
        
        mapped["id"] = policy_id
        
        # Map name field
        mapped["name"] = policy_data.get("name", policy_data.get("policy_name", f"policy-{policy_id}"))
        
        # Map interfaces (handle Fortinet quoted string format)
        srcintf_value = policy_data.get("srcintf") or policy_data.get("source_interface") or policy_data.get("source-interface") or []
        mapped["srcintf"] = self._to_list(srcintf_value)
        
        dstintf_value = policy_data.get("dstintf") or policy_data.get("destination_interface") or policy_data.get("destination-interface") or []
        mapped["dstintf"] = self._to_list(dstintf_value)
        
        # Map addresses
        srcaddr_value = policy_data.get("srcaddr") or policy_data.get("source_address") or policy_data.get("source-address") or []
        mapped["srcaddr"] = self._to_list(srcaddr_value)
        
        dstaddr_value = policy_data.get("dstaddr") or policy_data.get("destination_address") or policy_data.get("destination-address") or []
        mapped["dstaddr"] = self._to_list(dstaddr_value)
        
        # Map services
        service_value = policy_data.get("service") or policy_data.get("services") or []
        mapped["service"] = self._to_list(service_value)
        
        # Map action
        mapped["action"] = policy_data.get("action", "deny")
        
        # Map status (default to "enable" if not present, as Fortinet policies are enabled by default)
        # Handle both "enable"/"disable" string and boolean
        status_value = policy_data.get("status")
        if status_value is None:
            status_value = policy_data.get("enabled")
            if isinstance(status_value, bool):
                status_value = "enable" if status_value else "disable"
        if status_value is None:
            status_value = "enable"  # Default
        mapped["status"] = str(status_value).lower()
        
        # Map schedule (default to "always" if not present)
        mapped["schedule"] = policy_data.get("schedule") or "always"
        
        # Map comments
        mapped["comments"] = policy_data.get("comments", policy_data.get("comment", ""))
        
        # Map all optional fields with field name variations
        optional_field_mappings = {
            # Basic
            "srcaddr_negate": ["srcaddr-negate", "srcaddr_negate"],
            "service_negate": ["service-negate", "service_negate"],
            
            # Internet service
            "internet_service": ["internet-service", "internet_service"],
            "internet_service_id": ["internet-service-id", "internet_service_id"],
            
            # Application
            "application": ["application", "application-list", "application_list"],
            
            # Users/Groups
            "users": ["users", "user-name", "user_name"],
            "groups": ["groups", "group-name", "group_name"],
            "fsso": ["fsso"],
            "ntlm": ["ntlm"],
            "wsso": ["wsso"],
            
            # NAT
            "nat": ["nat"],
            "natip": ["natip", "nat-ip"],
            "ippool": ["ippool", "ip-pool"],
            "poolname": ["poolname", "pool-name"],
            "rtp_nat": ["rtp-nat", "rtp_nat"],
            "permit_any_host": ["permit-any-host", "permit_any_host"],
            "match_vip": ["match-vip", "match_vip"],
            "rtp_addr": ["rtp-addr", "rtp_addr"],
            
            # Traffic shaping
            "traffic_shaper": ["traffic-shaper", "traffic_shaper"],
            "session_ttl": ["session-ttl", "session_ttl"],
            "vlan_cos_fwd": ["vlan-cos-fwd", "vlan_cos_fwd"],
            
            # UTM
            "utm_status": ["utm-status", "utm_status"],
            "inspection_mode": ["inspection-mode", "inspection_mode"],
            "av_profile": ["av-profile", "av_profile"],
            "webfilter_profile": ["webfilter-profile", "webfilter_profile"],
            "dnsfilter_profile": ["dnsfilter-profile", "dnsfilter_profile"],
            "emailfilter_profile": ["emailfilter-profile", "emailfilter_profile"],
            "dlp_sensor": ["dlp-sensor", "dlp_sensor"],
            "ips_sensor": ["ips-sensor", "ips_sensor"],
            "voip_profile": ["voip-profile", "voip_profile"],
            "waf_profile": ["waf-profile", "waf_profile"],
            "ssh_filter_profile": ["ssh-filter-profile", "ssh_filter_profile"],
            "ssl_ssh_profile": ["ssl-ssh-profile", "ssl_ssh_profile"],
            "profile_type": ["profile-type", "profile_type"],
            "profile_group": ["profile-group", "profile_group"],
            
            # Policy redirects
            "http_policy_redirect": ["http-policy-redirect", "http_policy_redirect"],
            "ssh_policy_redirect": ["ssh-policy-redirect", "ssh_policy_redirect"],
            "webproxy_profile": ["webproxy-profile", "webproxy_profile"],
            
            # Logging
            "logtraffic": ["logtraffic", "log-traffic"],
            "logtraffic_start": ["logtraffic-start", "logtraffic_start"],
            "capture_packet": ["capture-packet", "capture_packet"],
            "custom_log_fields": ["custom-log-fields", "custom_log_fields"],
            
            # TOS
            "tos": ["tos"],
            "tos_mask": ["tos-mask", "tos_mask"],
            "tos_negate": ["tos-negate", "tos_negate"],
            
            # Security
            "anti_replay": ["anti-replay", "anti_replay"],
            "tcp_session_without_syn": ["tcp-session-without-syn", "tcp_session_without_syn"],
            
            # VPN
            "vpntunnel": ["vpntunnel", "vpn-tunnel"],
            "inbound": ["inbound"],
            "outbound": ["outbound"],
            
            # Optimization
            "wanopt": ["wanopt"],
            "webcache": ["webcache"],
            
            # Reputation
            "reputation_minimum": ["reputation-minimum", "reputation_minimum"],
            
            # Authentication
            "auth_cert": ["auth-cert", "auth_cert"],
            "auth_redirect_addr": ["auth-redirect-addr", "auth_redirect_addr"],
            "redirect_url": ["redirect-url", "redirect_url"],
            
            # QoS
            "diffservcode_forward": ["diffservcode-forward", "diffservcode_forward"],
            "identity_based_route": ["identity-based-route", "identity_based_route"]
        }
        
        # Map all optional fields
        for std_field, field_variants in optional_field_mappings.items():
            for variant in field_variants:
                if variant in policy_data:
                    value = policy_data[variant]
                    # Handle list conversion for certain fields
                    if std_field in ["users", "groups", "internet_service_id", "application", "custom_log_fields"]:
                        if isinstance(value, str):
                            mapped[std_field] = self._to_list(value)
                        elif isinstance(value, list):
                            mapped[std_field] = value
                        else:
                            mapped[std_field] = [value] if value else []
                    # Handle integer conversion
                    elif std_field in ["session_ttl", "vlan_cos_fwd", "reputation_minimum", "diffservcode_forward"]:
                        try:
                            mapped[std_field] = int(value) if value else None
                        except (ValueError, TypeError):
                            mapped[std_field] = None
                    else:
                        mapped[std_field] = value
                    break
        
        # IMPORTANT: Preserve ALL other fields from policy_data that weren't in our mappings
        # This ensures we extract ALL data, even unknown fields
        for key, value in policy_data.items():
            # Skip fields we've already mapped
            if key not in mapped and key not in ["id", "policy_id", "name", "policy_name", 
                                                  "srcintf", "dstintf", "srcaddr", "dstaddr", 
                                                  "service", "services", "action", "status", 
                                                  "schedule", "comments", "comment"]:
                # Check if this key matches any variant we already processed
                already_processed = False
                for std_field, field_variants in optional_field_mappings.items():
                    if key in field_variants:
                        already_processed = True
                        break
                
                if not already_processed:
                    # Preserve the field as-is
                    mapped[key] = value
                    logger.debug(f"Preserved additional field from policy_data: {key}")
        
        return mapped
    
    def _to_list(self, value: Any) -> List[str]:
        """
        Convert value to list if it's not already a list.
        Handles Fortinet's quoted string format like "port1\" \"port3".
        
        Args:
            value: Value to convert (can be string, list, or None)
            
        Returns:
            List representation
        """
        if isinstance(value, list):
            return [str(v) for v in value]
        elif isinstance(value, str):
            # Handle Fortinet's quoted string format: "port1\" \"port3"
            # Split by escaped quotes and spaces
            if '\\" \\"' in value or '" "' in value:
                # Remove outer quotes and split by escaped quotes
                cleaned = value.strip('"').replace('\\"', '"')
                # Split by space-quote-space pattern or just space if it's a simple list
                if '\\" \\"' in value:
                    parts = [part.strip('"') for part in value.split('\\" \\"')]
                else:
                    parts = [part.strip().strip('"') for part in cleaned.split(' ') if part.strip()]
                return [p for p in parts if p]
            # Handle comma-separated values
            elif ',' in value:
                return [v.strip() for v in value.split(',') if v.strip()]
            # Regular space-separated values
            elif ' ' in value:
                return [v.strip() for v in value.split(' ') if v.strip()]
            # Single value
            elif value:
                return [value]
            else:
                return []
        elif value:
            return [str(value)]
        else:
            return []

    def _parse_address_objects(self, addresses_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse Fortinet address objects.
        
        Args:
            addresses_data: Raw address object data
            
        Returns:
            List of address objects
        """
        logger.debug(f"Parsing {len(addresses_data)} Fortinet address objects")
        address_objects = []
        for i, addr_data in enumerate(addresses_data):
            try:
                logger.debug(f"Parsing address object {i+1}")
                addr_obj = FortinetAddressObject(**addr_data)
                address_objects.append(addr_obj.dict())
                logger.debug(f"Address object {i+1} parsed successfully")
            except Exception as e:
                logger.warning(f"Error parsing address object {i+1}: {str(e)}")
                continue
        logger.info(f"Successfully parsed {len(address_objects)} out of {len(addresses_data)} address objects")
        return address_objects

    def _parse_service_objects(self, services_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse Fortinet service objects.
        
        Args:
            services_data: Raw service object data
            
        Returns:
            List of service objects
        """
        logger.debug(f"Parsing {len(services_data)} Fortinet service objects")
        service_objects = []
        for i, service_data in enumerate(services_data):
            try:
                logger.debug(f"Parsing service object {i+1}")
                service_obj = FortinetServiceObject(**service_data)
                service_objects.append(service_obj.dict())
                logger.debug(f"Service object {i+1} parsed successfully")
            except Exception as e:
                logger.warning(f"Error parsing service object {i+1}: {str(e)}")
                continue
        logger.info(f"Successfully parsed {len(service_objects)} out of {len(services_data)} service objects")
        return service_objects

    def validate_config(self, config: FirewallConfig) -> bool:
        """
        Validate the parsed Fortinet configuration.
        
        Args:
            config: Parsed firewall configuration
            
        Returns:
            True if valid, False otherwise
        """
        logger.info("Validating Fortinet configuration")
        try:
            # Check if required fields are present
            if not config.id:
                logger.error("Firewall ID is missing")
                return False
            
            if not config.vendor or config.vendor != "fortinet":
                logger.error("Invalid vendor for Fortinet parser")
                return False
            
            # Check policies
            logger.debug("Validating policies")
            for i, policy in enumerate(config.policies):
                if not isinstance(policy, dict):
                    logger.error(f"Policy {i+1} is not a dictionary")
                    return False
                # Check required fields
                required_fields = ["id", "source_zones", "destination_zones", "action"]
                for field in required_fields:
                    if field not in policy:
                        logger.error(f"Required field '{field}' missing in policy {i+1}")
                        return False
            
            logger.info("Fortinet configuration validation completed successfully")
            return True
        except Exception as e:
            logger.error(f"Error validating Fortinet configuration: {str(e)}")
            return False