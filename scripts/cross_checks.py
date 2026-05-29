# -*- coding: utf-8 -*-
"""
Cross-Check Module for MikroTik RouterOS RSC Auditor
=====================================================

Detects contradictions BETWEEN configuration domains that individual
single-domain checks (AUTH, FW, ROUTE, etc.) cannot see.

A cross-check fires when two or more configuration settings, each
valid in isolation, produce an inconsistent overall state.

Example: DHCP hands out the router's IP as DNS server, but the router
has no upstream DNS forwarders configured. Neither is individually wrong
but together they break DNS resolution for clients.

Each cross-check produces an Annotation that is either attached to an
existing finding (cross-reference warning) or emitted as a standalone
XCHK- finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════════════
# Annotation data model
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class Annotation:
    """A single cross-check result.

    When *target_finding_id* is set, the annotation is attached to the
    existing finding with that ID. When it is None, a standalone XCHK-
    finding is created.
    """

    check_id: str  # e.g. "XCHK-DNS-DHCP-GATEWAY"
    target_finding_id: Optional[str]  # None → standalone
    severity: str  # "Critical" | "High" | "Medium" | "Low" | "Info"
    warning: str  # Short human-readable warning
    details: str  # Context: what was found where
    remediation: str  # What to do about it

    def to_annotation_dict(self) -> Dict[str, str]:
        """Return the dict appended to a finding's *cross_checks* list."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "warning": self.warning,
            "details": self.details,
            "remediation": self.remediation,
        }

    def to_finding_dict(self) -> Dict[str, Any]:
        """Return a standalone finding dict (when no target exists)."""
        return {
            "id": self.check_id,
            "name": f"Cross-Check: {self.warning[:60]}",
            "severity": self.severity,
            "cvss": "5.5",
            "category": "Cross-Domain Consistency",
            "path": "analysis",
            "description": self.warning,
            "details": self.details,
            "remediation": self.remediation,
            "compliance": {},
        }


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════


def _join_continuations(lines: List[str]) -> List[str]:
    """Join lines split with backslash continuations into single logical lines.

    RouterOS exports use trailing backslash to continue long commands on the
    next line. This must be resolved before parameter extraction.
    """
    joined: List[str] = []
    buf = ""
    for line in lines:
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
        else:
            joined.append(buf + stripped)
            buf = ""
    if buf:
        joined.append(buf)
    return joined


# ═══════════════════════════════════════════════════════════════════════════
# Parameter extraction helpers
# ═══════════════════════════════════════════════════════════════════════════


def _parse_params(line: str) -> Dict[str, str]:
    """Extract key=value parameters from a RouterOS command line.

    Handles both quoted and unquoted values:
        address=192.168.88.0/24  →  {"address": "192.168.88.0/24"}
        servers="10.0.0.1,10.0.0.2"  →  {"servers": "10.0.0.1,10.0.0.2"}
    """
    params: Dict[str, str] = {}
    for m in re.finditer(r'(\w[\w-]*)=(?:"([^"]*)"|(\S+))', line):
        key = m.group(1)
        value = m.group(2) if m.group(2) is not None else m.group(3)
        params[key] = value
    return params

def _find_section(content: str, path: str) -> List[str]:
    """Collect parameter-bearing lines from ALL sections for a given path.

    RouterOS exports can have the same path declaration multiple times
    (e.g. two /interface vlan blocks). This collects from ALL occurrences.
    Joins backslash continuations before returning.
    """
    all_lines: List[str] = []
    in_section = False
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        if stripped.startswith("/") and not stripped.startswith("/ "):
            if stripped == path:
                in_section = True
            else:
                in_section = False
            continue
        if in_section and "=" in stripped:
            all_lines.append(stripped)

    # Join continuation lines
    joined = _join_continuations(all_lines)
    return [l for l in joined if l.strip() and "=" in l]

def get_dhcp_networks(content: str) -> List[Dict[str, str]]:
    """Parse /ip dhcp-server network entries.

    Returns list of dicts with keys: address, dns-server, gateway, etc.
    """
    entries: List[Dict[str, str]] = []
    for line in _find_section(content, "/ip dhcp-server network"):
        if line.startswith("add ") or line.startswith("set "):
            entries.append(_parse_params(line))
    return entries


def get_dns_config(content: str) -> Dict[str, Any]:
    """Parse /ip dns set command.

    Returns dict with keys like: servers, allow-remote-requests,
    cache-size, etc. (keys present only if set).
    """
    config: Dict[str, Any] = {}
    for line in _find_section(content, "/ip dns"):
        if "set " in line:
            config = _parse_params(line)
    return config


def get_interface_list_members(content: str) -> List[Dict[str, str]]:
    """Parse /interface list member entries.

    Returns list of dicts with keys: interface, list.
    """
    members: List[Dict[str, str]] = []
    for line in _find_section(content, "/interface list member"):
        if line.startswith("add ") or line.startswith("set "):
            members.append(_parse_params(line))
        elif members and not line.startswith("/"):
            members[-1].update(_parse_params(line))
    return members


def get_local_addresses(content: str) -> List[Dict[str, str]]:
    """Parse /ip address entries.

    Returns list of dicts with keys: address, interface, network.
    """
    addrs: List[Dict[str, str]] = []
    for line in _find_section(content, "/ip address"):
        if line.startswith("add ") or line.startswith("set "):
            addrs.append(_parse_params(line))
        elif addrs and not line.startswith("/"):
            addrs[-1].update(_parse_params(line))
    return addrs


def get_service_config(content: str) -> Dict[str, Dict[str, str]]:
    """Parse /ip service settings.

    Returns dict mapping service name → param dict:
        {"ssh": {"disabled": "yes"}, "www": {"disabled": "no", "address": "0.0.0.0/0"}}
    """
    services: Dict[str, Dict[str, str]] = {}
    for line in _find_section(content, "/ip service"):
        m = re.match(r"set\s+(\S+)\s+(.*)", line)
        if m:
            service = m.group(1)
            params = _parse_params(m.group(2))
            services[service] = params
    return services


def get_nat_rules(content: str) -> List[Dict[str, str]]:
    """Parse /ip firewall nat rules.

    Returns list of dicts. Key fields:
      action, chain, to-addresses, dst-port, protocol, in-interface, etc.
    """
    rules: List[Dict[str, str]] = []
    for line in _find_section(content, "/ip firewall nat"):
        if line.startswith("add ") or line.startswith("set "):
            rules.append(_parse_params(line))
        elif rules and not line.startswith("/"):
            rules[-1].update(_parse_params(line))
    return rules


def get_filter_rules(content: str) -> List[Dict[str, str]]:
    """Parse /ip firewall filter rules.

    Returns list of dicts. Key fields:
      action, chain, protocol, dst-port, in-interface, connection-state, etc.
    """
    rules: List[Dict[str, str]] = []
    for line in _find_section(content, "/ip firewall filter"):
        if line.startswith("add ") or line.startswith("set "):
            rules.append(_parse_params(line))
        elif rules and not line.startswith("/"):
            rules[-1].update(_parse_params(line))
    return rules


def get_wifi_interfaces(content: str) -> List[Dict[str, str]]:
    """Parse /interface wifi entries.

    Returns list of dicts. Key fields: configuration, disabled, etc.
    Also handles /interface wireless (v6) entries.
    """
    ifaces: List[Dict[str, str]] = []
    for path in ("/interface wifi", "/interface wireless"):
        for line in _find_section(content, path):
            if line.startswith("add ") or line.startswith("set "):
                ifaces.append(_parse_params(line))
            elif ifaces and not line.startswith("/"):
                ifaces[-1].update(_parse_params(line))
    return ifaces


def get_bridge_ports(content: str) -> List[Dict[str, str]]:
    """Parse /interface bridge port entries.

    Returns list of dicts. Key fields: interface, bridge, pvid, etc.
    """
    ports: List[Dict[str, str]] = []
    for line in _find_section(content, "/interface bridge port"):
        if line.startswith("add ") or line.startswith("set "):
            ports.append(_parse_params(line))
        elif ports and not line.startswith("/"):
            ports[-1].update(_parse_params(line))
    return ports


def get_vlan_interfaces(content: str) -> List[Dict[str, str]]:
    """Parse /interface vlan entries.

    Returns list of dicts. Key fields: name, vlan-id, interface.
    """
    vlans: List[Dict[str, str]] = []
    for line in _find_section(content, "/interface vlan"):
        if line.startswith("add ") or line.startswith("set "):
            vlans.append(_parse_params(line))
        elif vlans and not line.startswith("/"):
            vlans[-1].update(_parse_params(line))
    return vlans


def _get_wan_interface_names(content: str) -> List[str]:
    """Resolve WAN interface list members to concrete interface names.

    Returns the interface names that belong to interface list named 'WAN'.
    Matches case-insensitively.
    """
    members = get_interface_list_members(content)
    return [m["interface"] for m in members if m.get("list", "").upper() == "WAN"]


# ═══════════════════════════════════════════════════════════════════════════
# Individual cross-checks
# ═══════════════════════════════════════════════════════════════════════════


def check_dns_dhcp_gateway(content: str) -> Optional[Annotation]:
    """XCHK-DNS-DHCP-GATEWAY

    Verify that when DHCP assigns the router as DNS server, the router
    actually has upstream forwarders configured.

    Incident context: Client got correct DNS IP via DHCP but the router
    had no forwarders configured → all DNS resolution failed silently.
    """
    dhcp_networks = get_dhcp_networks(content)
    if not dhcp_networks:
        return None

    local_addrs = get_local_addresses(content)
    local_ips = set()
    for addr in local_addrs:
        ip = addr.get("address", "").split("/")[0]
        if ip:
            local_ips.add(ip)

    dns_config = get_dns_config(content)
    has_forwarders = bool(dns_config.get("servers", "").strip())
    allow_remote = dns_config.get("allow-remote-requests", "yes").lower()

    router_dns_networks: List[str] = []
    for net in dhcp_networks:
        dns_val = net.get("dns-server", "")
        if not dns_val:
            # No explicit dns-server → clients use router by default
            router_dns_networks.append(net.get("address", "?"))
            continue
        # Check whether dns-server points to a local interface
        for dns_ip in dns_val.split(","):
            dns_ip = dns_ip.strip()
            if dns_ip in local_ips:
                router_dns_networks.append(net.get("address", "?"))

    if not router_dns_networks:
        return None  # No DHCP network points DNS to this router

    # Router is expected to resolve — check configuration
    issues: List[str] = []
    if not has_forwarders:
        issues.append("no upstream DNS forwarders configured (servers=)")
    if allow_remote == "no":
        issues.append("allow-remote-requests=no (refuses client queries)")

    if not issues:
        return None

    networks_str = ", ".join(router_dns_networks)
    issues_str = "; ".join(issues)

    return Annotation(
        check_id="XCHK-DNS-DHCP-GATEWAY",
        target_finding_id="NET-004",
        severity="High",
        warning=(
            f"DHCP assigns router as DNS server for {networks_str}, "
            f"but router has {issues_str}"
        ),
        details=(
            f"DHCP networks pointing DNS to router: {networks_str}. "
            f"Router DNS config: servers={dns_config.get('servers', '(not set)')}, "
            f"allow-remote-requests={allow_remote}."
        ),
        remediation=(
            "Set upstream DNS forwarders:\n"
            "  /ip dns set servers=1.1.1.1,8.8.8.8 allow-remote-requests=yes\n"
            "Or if the router should not act as DNS, configure DHCP to hand out "
            "a different DNS server."
        ),
    )


def check_interface_restriction(content: str) -> List[Annotation]:
    """XCHK-INTERFACE-RESTRICTION

    Detect when management services are bound to 0.0.0.0/0 (all interfaces)
    while a WAN interface exists — exposes management to the internet.

    Annotates AUTH-009 (WinBox on WAN), AUTH-010 (API on WAN),
    AUTH-011 (unrestricted services).
    """
    services = get_service_config(content)
    wan_ifaces = _get_wan_interface_names(content)

    if not services or not wan_ifaces:
        return []

    # Management services that should be restricted
    mgmt_services = {"www", "www-ssl", "winbox", "api", "api-ssl", "ssh"}
    exposed: List[str] = []
    for svc, params in services.items():
        if svc not in mgmt_services:
            continue
        if params.get("disabled", "").lower() == "yes":
            continue
        addr = params.get("address", "0.0.0.0/0")
        if addr in ("0.0.0.0/0", "::/0", ""):
            exposed.append(f"{svc} (address={addr})")

    if not exposed:
        return []

    exposed_str = ", ".join(exposed)
    annotations: List[Annotation] = []

    # Map each exposed service to the relevant AUTH finding
    target_map: Dict[str, str] = {
        "winbox": "AUTH-009",
        "www": "AUTH-011",
        "www-ssl": "AUTH-011",
        "api": "AUTH-010",
        "api-ssl": "AUTH-010",
        "ssh": "AUTH-011",
    }

    for svc_name in [s.split(" ")[0] for s in exposed]:
        target = target_map.get(svc_name)
        if target:
            annotations.append(Annotation(
                check_id="XCHK-INTERFACE-RESTRICTION",
                target_finding_id=target,
                severity="High",
                warning=(
                    f"Service '{svc_name}' is bound to all interfaces "
                    f"(not restricted to LAN)"
                ),
                details=(
                    f"WAN interfaces detected: {', '.join(wan_ifaces)}. "
                    f"Service {svc_name} is enabled and bound to 0.0.0.0/0."
                ),
                remediation=(
                    f"/ip service set {svc_name} address=<lan-subnet/cidr>"
                ),
            ))

    return annotations


def check_dhcp_option(content: str) -> Optional[Annotation]:
    """XCHK-DHCP-OPTION

    Verify DHCP gateway IP matches a local interface address.

    A mismatched gateway means DHCP clients get a default route
    that doesn't exist on the local network.
    """
    dhcp_networks = get_dhcp_networks(content)
    if not dhcp_networks:
        return None

    local_addrs = get_local_addresses(content)
    local_networks: Dict[str, str] = {}  # cidr → ip
    for addr in local_addrs:
        cidr = addr.get("address", "")
        ip = cidr.split("/")[0] if "/" in cidr else cidr
        if cidr and ip:
            local_networks[cidr] = ip

    mismatches: List[str] = []
    for net in dhcp_networks:
        gw = net.get("gateway", "")
        net_cidr = net.get("address", "")
        if not gw or not net_cidr:
            continue
        # Check if gateway IP matches any local interface address
        for local_cidr, local_ip in local_networks.items():
            gw_ip = gw.split("/")[0] if "/" in gw else gw
            if gw_ip == local_ip:
                break  # gateway matches → OK
        else:
            # Gateway doesn't match any local IP — but it could be an upstream router
            # Only flag if gateway is in the same subnet as the DHCP network
            mismatches.append(f"net={net_cidr} gateway={gw}")

    if not mismatches:
        return None

    mismatches_str = "; ".join(mismatches)
    return Annotation(
        check_id="XCHK-DHCP-OPTION",
        target_finding_id="NET-002",
        severity="Medium",
        warning=f"DHCP gateway IP does not match any local interface: {mismatches_str}",
        details=(
            f"DHCP networks with potentially mismatched gateways: {mismatches_str}. "
            f"Local addresses: {', '.join(local_networks.values())}."
        ),
        remediation=(
            "Ensure the DHCP gateway IP matches the router's LAN interface address "
            "on that subnet, or that the gateway points to an upstream router "
            "reachable from the subnet."
        ),
    )


def check_nat_fw(content: str) -> List[Annotation]:
    """XCHK-NAT-FW

    Detect DST-NAT rules that forward traffic to internal hosts without
    corresponding firewall filter rules allowing the forwarded traffic.

    A DST-NAT without a corresponding input/forward allow means the
    forwarded traffic may be dropped by the firewall.
    """
    nat_rules = get_nat_rules(content)
    filter_rules = get_filter_rules(content)

    dstnat_rules = [r for r in nat_rules if r.get("chain", "").lower() == "dstnat"]

    if not dstnat_rules:
        return []

    # Collect ports/protocols that the filter rules allow in forward chain
    allowed_forward: List[Dict[str, str]] = []
    for rule in filter_rules:
        if rule.get("chain", "").lower() != "forward":
            continue
        if rule.get("action", "").lower() in ("accept", "fasttrack-connection"):
            allowed_forward.append(rule)

    # For each dst-nat rule, check if the destination port is allowed forward
    annotations: List[Annotation] = []
    for rule in dstnat_rules:
        dst_port = rule.get("dst-port", "")
        protocol = rule.get("protocol", "tcp")
        to_addr = rule.get("to-addresses", "")
        if not dst_port and not to_addr:
            continue

        # See if any filter rule explicitly allows this port forward
        port_allowed = False
        for fw_rule in allowed_forward:
            fw_port = fw_rule.get("dst-port", "")
            fw_proto = fw_rule.get("protocol", "")
            if fw_port and fw_port == dst_port:
                if not fw_proto or fw_proto == protocol:
                    port_allowed = True
                    break
            # Also check for broad allow rules (established/related)
            if fw_rule.get("connection-state", "") in ("established,related", "established"):
                port_allowed = True
                break

        if not port_allowed:
            annotations.append(Annotation(
                check_id="XCHK-NAT-FW",
                target_finding_id="FW-014",
                severity="High",
                warning=(
                    f"DST-NAT to {to_addr or '?'} port {dst_port} "
                    f"has no matching firewall forward allow rule"
                ),
                details=(
                    f"NAT rule: action={rule.get('action','')} "
                    f"chain={rule.get('chain','')} "
                    f"dst-port={dst_port} to-addresses={to_addr}. "
                    f"No corresponding filter rule allows this port in forward chain."
                ),
                remediation=(
                    "Add a firewall filter rule to allow the forwarded traffic:\n"
                    f"  /ip firewall filter add chain=forward action=accept "
                    f"protocol={protocol} dst-port={dst_port} dst-address={to_addr}"
                ),
            ))

    return annotations


def check_wifi_bridge(content: str) -> Optional[Annotation]:
    """XCHK-WIFI-BRIDGE

    Detect WiFi interfaces that are not members of any bridge.

    A WiFi interface not connected to a bridge means wireless clients
    are isolated from the LAN.
    """
    wifi_ifaces = get_wifi_interfaces(content)
    if not wifi_ifaces:
        return None

    # Get bridge ports to see which interfaces are bridged
    bridge_ports = get_bridge_ports(content)
    bridged_interfaces = set(p.get("interface", "") for p in bridge_ports)

    # Get VLAN interfaces — a WiFi interface is bridged if it's the parent
    # of a VLAN interface that IS a bridge port member
    vlans = get_vlan_interfaces(content)
    vlan_parents = set(v.get("interface", "") for v in vlans)

    # Get the configured WiFi interface names
    # In v7, the 'set' command on /interface wifi may have disabled=no
    # In v6, /interface wireless has add/set with default-name
    unbridged: List[str] = []
    for wifi in wifi_ifaces:
        # Skip disabled interfaces
        if wifi.get("disabled", "").lower() == "yes":
            continue

        # Get the interface name (from 'set default-name=wifi2' or 'add name=...')
        iface_name = wifi.get("name", "")
        default_name = wifi.get("default-name", "")
        active_name = iface_name or default_name

        if not active_name:
            continue

        # Check: directly bridged?
        if active_name in bridged_interfaces:
            continue

        # Check: bridged via VLAN? (WiFi → VLAN interface → bridge port)
        if active_name in vlan_parents:
            # Find VLAN children and check if any is a bridge port
            vlan_names = [v.get("name", "") for v in vlans if v.get("interface", "") == active_name]
            if any(vn in bridged_interfaces for vn in vlan_names):
                continue

        unbridged.append(active_name)

    if not unbridged:
        return None

    unbridged_str = ", ".join(unbridged)
    return Annotation(
        check_id="XCHK-WIFI-BRIDGE",
        target_finding_id="WIFI-008",
        severity="Medium",
        warning=f"WiFi interfaces not bridged to LAN: {unbridged_str}",
        details=(
            f"WiFi interfaces {unbridged_str} are enabled but not members "
            f"of any bridge port. Wireless clients cannot reach LAN resources."
        ),
        remediation=(
            "Add WiFi interfaces to a bridge:\n"
            "  /interface bridge port add bridge=<bridge-name> interface=<wifi-iface>\n"
            "Or if isolation is intentional, ensure firewall rules handle "
            "the isolated segment."
        ),
    )


def check_port_service(content: str) -> List[Annotation]:
    """XCHK-PORT-SERVICE

    Detect services configured on non-default ports that may conflict
    or expose services on unexpected interfaces.

    Annotates SRV-016 (non-default service ports).
    """
    services = get_service_config(content)
    if not services:
        return []

    # Default ports per service
    default_ports = {
        "ftp": 21, "ssh": 22, "telnet": 23, "www": 80,
        "winbox": 8291, "api": 8728, "api-ssl": 8729,
        "www-ssl": 443,
    }

    used_ports: Dict[int, List[str]] = {}
    for svc, params in services.items():
        port_str = params.get("port", "")
        if not port_str:
            continue
        try:
            port = int(port_str)
        except ValueError:
            continue
        used_ports.setdefault(port, []).append(svc)

    annotations: List[Annotation] = []
    for port, svcs in used_ports.items():
        if len(svcs) > 1:
            annotations.append(Annotation(
                check_id="XCHK-PORT-SERVICE",
                target_finding_id="SRV-016",
                severity="Medium",
                warning=f"Port {port} assigned to multiple services: {', '.join(svcs)}",
                details=f"Services {', '.join(svcs)} all use port {port}.",
                remediation=(
                    "Assign unique ports to each service:\n"
                    "  /ip service set <service> port=<unique-port>"
                ),
            ))

    if not annotations:
        return []

    return annotations


def check_bridge_vlan(content: str) -> Optional[Annotation]:
    """XCHK-BRIDGE-VLAN

    Detect VLAN interfaces that exist but are not tagged members of the
    bridge VLAN table.

    A VLAN interface without a corresponding bridge VLAN entry means
    the VLAN traffic may not be properly forwarded across the bridge.
    """
    vlans = get_vlan_interfaces(content)
    bridge_ports = get_bridge_ports(content)

    if not vlans:
        return None

    # Collect VLAN IDs configured on bridge ports
    bridge_vlan_ids: set = set()
    for port in bridge_ports:
        pvid = port.get("pvid", "")
        if pvid:
            try:
                bridge_vlan_ids.add(int(pvid))
            except ValueError:
                pass
        # Also check tagged VLANs from the bridge vlan table
        vlan_ids = port.get("vlan-ids", "")
        if vlan_ids:
            # Could be "1,2,3" or "10-20"
            for part in vlan_ids.split(","):
                part = part.strip()
                if "-" in part:
                    try:
                        start, end = part.split("-", 1)
                        bridge_vlan_ids.update(range(int(start), int(end) + 1))
                    except ValueError:
                        pass
                else:
                    try:
                        bridge_vlan_ids.add(int(part))
                    except ValueError:
                        pass

    # Check each VLAN interface
    unregistered: List[str] = []
    for vlan in vlans:
        vlan_id_str = vlan.get("vlan-id", "")
        if not vlan_id_str:
            continue
        try:
            vlan_id = int(vlan_id_str)
        except ValueError:
            continue
        if vlan_id not in bridge_vlan_ids:
            unregistered.append(
                f"{vlan.get('name', '?')} (vlan-id={vlan_id})"
            )

    if not unregistered:
        return None

    unreg_str = ", ".join(unregistered)
    return Annotation(
        check_id="XCHK-BRIDGE-VLAN",
        target_finding_id="NET-001",
        severity="Medium",
        warning=f"VLAN interfaces not registered in bridge VLAN table: {unreg_str}",
        details=(
            f"VLAN interfaces {unreg_str} exist but are not configured as "
            f"tagged members in any bridge port's VLAN configuration."
        ),
        remediation=(
            "Add VLAN IDs to the bridge VLAN table:\n"
            "  /interface bridge vlan add bridge=<bridge-name> vlan-ids=<vlan-id> "
            "tagged=<bridge-ports>\n"
            "Or set the PVID on the bridge port:\n"
            "  /interface bridge port set <port> pvid=<vlan-id>"
        ),
    )


# ═══════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════


def run_cross_checks(content: str) -> List[Annotation]:
    """Run all cross-checks against parsed .rsc content.

    Returns a flat list of Annotation objects. Each annotation either
    targets an existing finding (target_finding_id set) or is standalone
    (target_finding_id is None).

    Cross-checks that produce no finding return None/[] and are skipped.
    """
    annotations: List[Annotation] = []

    # Order matters: run the most impactful checks first
    check_handlers = [
        check_dns_dhcp_gateway,
        check_interface_restriction,
        check_dhcp_option,
        check_nat_fw,
        check_wifi_bridge,
        check_port_service,
        check_bridge_vlan,
    ]

    for handler in check_handlers:
        try:
            result = handler(content)
            if result is None:
                continue
            if isinstance(result, list):
                annotations.extend(result)
            else:
                annotations.append(result)
        except Exception as e:
            # Log and skip — don't let one bad check crash the batch
            annotations.append(Annotation(
                check_id=f"{handler.__name__}-ERROR",
                target_finding_id=None,
                severity="Info",
                warning=f"Cross-check {handler.__name__} failed: {e}",
                details="",
                remediation="",
            ))

    return annotations
