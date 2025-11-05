# JSON Format Specification

## Overview
This document describes the expected JSON formats for firewall policy configurations.

## Fortinet JSON Format

### Structure 1: Object with Policies Array (Standard)
```json
{
  "device": {
    "vendor": "Fortinet",
    "model": "FortiGate-600E",
    "hostname": "fgt-core-1",
    "version": "v7.2.3"
  },
  "policies": [
    {
      "policyid": 1,
      "name": "Allow_HTTP_Web",
      "srcintf": ["port1"],
      "dstintf": ["port2"],
      "srcaddr": ["10.0.0.0/24"],
      "dstaddr": ["203.0.113.10"],
      "service": ["HTTP"],
      "action": "accept",
      "schedule": "always",
      "logtraffic": "all",
      "nat": false,
      "status": "enable",
      "comment": "Standard web allow"
    }
  ]
}
```

### Structure 2: Direct Array (Alternative)
```json
[
  {
    "policy_id": "10",
    "name": "POL-010-EXECUTIVE-INTERNET",
    "srcintf": "VLAN-10-EXECUTIVE",
    "dstintf": "port1",
    "action": "accept",
    ...
  }
]
```

### Fortinet Policy Fields

#### Required Fields
- `policyid` or `policy_id`: Policy identifier (number or string)
- `name`: Policy name
- `srcintf`: Source interface(s) - string or array
- `dstintf`: Destination interface(s) - string or array
- `srcaddr`: Source address(es) - string or array
- `dstaddr`: Destination address(es) - string or array
- `service`: Service(s) - string or array
- `action`: Action ("accept", "deny")

#### Optional Fields
- `schedule`: Schedule ("always", "workhours", etc.)
- `logtraffic`: Logging level ("all", "utm", "disable")
- `nat`: NAT enabled (boolean)
- `status`: Policy status ("enable", "disable")
- `comment` or `comments`: Policy comment/description

#### UTM/Security Fields
- `utm-status`: UTM enabled (boolean)
- `av-profile`: Antivirus profile name
- `webfilter-profile`: Web filter profile name
- `ips-sensor`: IPS sensor name
- `dlp-sensor`: DLP sensor name
- `application-list`: Application control list name
- `ssl-ssh-profile`: SSL/SSH inspection profile
- `dnsfilter-profile`: DNS filter profile
- `emailfilter-profile`: Email filter profile
- `voip-profile`: VoIP profile
- `waf-profile`: WAF profile
- `ssh-filter-profile`: SSH filter profile

#### User/Group Fields
- `groups`: User groups (string with escaped quotes format: `"Group1\" \"Group2"`)
- `users`: Users (string or array)
- `fsso`: FSSO enabled (string)
- `ntlm`: NTLM enabled (string)
- `wsso`: WSSO enabled (string)

#### NAT Fields
- `nat`: NAT enabled (boolean)
- `natip`: NAT IP address
- `ippool`: IP pool enabled (string)
- `poolname`: Pool name
- `rtp-nat`: RTP NAT (string)
- `permit-any-host`: Permit any host (string)
- `match-vip`: Match VIP (string)
- `rtp-addr`: RTP address

#### Traffic Shaping
- `traffic-shaper`: Traffic shaper profile
- `session-ttl`: Session TTL (number)
- `vlan-cos-fwd`: VLAN CoS forward (number)

#### Other Fields
- `internet-service`: Internet service enabled (string)
- `internet-service-id`: Internet service IDs (array)
- `application`: Application IDs (array)
- `inspection-mode`: Inspection mode ("proxy", "flow")
- `profile-type`: Profile type ("single", "group")
- `profile-group`: Profile group name
- `http-policy-redirect`: HTTP redirect (string)
- `ssh-policy-redirect`: SSH redirect (string)
- `webproxy-profile`: Web proxy profile
- `logtraffic-start`: Log traffic start (string)
- `capture-packet`: Capture packet (string)
- `custom-log-fields`: Custom log fields (array)
- `tos`: Type of Service (string)
- `tos-mask`: TOS mask (string)
- `tos-negate`: TOS negate (string)
- `anti-replay`: Anti-replay (string)
- `tcp-session-without-syn`: TCP session without SYN (string)
- `vpntunnel`: VPN tunnel name
- `inbound`: Inbound (string)
- `outbound`: Outbound (string)
- `wanopt`: WAN optimization (string)
- `webcache`: Web cache (string)
- `reputation-minimum`: Reputation minimum (number)
- `auth-cert`: Auth certificate
- `auth-redirect-addr`: Auth redirect address
- `redirect-url`: Redirect URL
- `diffservcode-forward`: Diffserv code forward (number)
- `identity-based-route`: Identity-based route

### Special Format: Escaped Quotes
Fortinet uses escaped quotes for multiple values in strings:
- `"srcintf": "port1\" \"port2"` → `["port1", "port2"]`
- `"groups": "Group1\" \"Group2"` → `["Group1", "Group2"]`

## Zscaler JSON Format

### Structure: Object with Policies Array
```json
{
  "platform": "Zscaler",
  "org": {
    "name": "example-corp",
    "location": "global",
    "version": "zpa-proxy-sim-1.0"
  },
  "policies": [
    {
      "policy_id": 1001,
      "name": "Z-Allow-Web",
      "enabled": true,
      "source": ["10.0.0.0/24", "192.0.2.0/28"],
      "destination": ["*"],
      "ports": ["80", "443"],
      "action": "allow",
      "category": ["Business"],
      "application": ["HTTP", "HTTPS"],
      "notes": "Allow web for corp"
    }
  ]
}
```

### Zscaler Policy Fields

#### Required Fields
- `policy_id`: Policy identifier (number)
- `name`: Policy name
- `enabled`: Policy enabled status (boolean)
- `source`: Source address(es) - array
- `destination`: Destination address(es) - array (can include "*" or "all")
- `ports`: Port(s) - array (can include "*" or ranges like "1234-1236")
- `action`: Action ("allow", "block")

#### Optional Fields
- `category`: Category(ies) - array
- `application`: Application(s) - array
- `notes`: Policy notes/description (string)

### Port Format
- Single port: `"443"`
- Multiple ports: `["80", "443", "8080"]`
- Port ranges: `["1234-1236"]`
- All ports: `["*"]` or `["all"]`

### Address Format
- Single address: `"10.0.0.0/24"`
- Multiple addresses: `["10.0.0.0/24", "192.0.2.0/28"]`
- All addresses: `["*"]` or `["all"]`
- Range: `["10.30.50.10-10.30.50.20"]`

## Notes

1. **Field Name Variations**: The system handles both hyphenated (`utm-status`) and underscore (`utm_status`) formats
2. **Array vs String**: Some fields can be arrays or strings (e.g., `srcintf` can be `["port1"]` or `"port1"`)
3. **Case Sensitivity**: Field names are case-sensitive
4. **Null Values**: Some fields may be `null` - the system handles this
5. **Additional Fields**: Any additional fields not in this specification are preserved in the parsed output
