"""Unit tests for the cross-check module.

Tests each cross-check in isolation with minimal .rsc content
to verify correct detection and absence of false positives.
"""

from typing import Dict


# ── Helper: build .rsc content ──

def _rsc(version: str, *sections: str) -> str:
    """Build a minimal .rsc file with header and config sections."""
    lines = [
        f"# dd/mm/yyyy hh:mm:ss by RouterOS {version}",
    ]
    for section in sections:
        lines.append(section)
    return "\n".join(lines)


def _section(path: str, *commands: str) -> str:
    """Build a config section: path declaration followed by commands."""
    parts = [path]
    parts.extend(commands)
    return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════════════════
# DNS-DHCP-GATEWAY
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckDnsDhcpGateway:
    """XCHK-DNS-DHCP-GATEWAY: DHCP router-as-DNS but no forwarders."""

    def test_no_dhcp_no_finding(self):
        from scripts.cross_checks import check_dns_dhcp_gateway
        content = _rsc("7.15",
            _section("/ip dns", "set servers=1.1.1.1"),
        )
        assert check_dns_dhcp_gateway(content) is None

    def test_forwarders_configured_no_finding(self):
        from scripts.cross_checks import check_dns_dhcp_gateway
        content = _rsc("7.15",
            _section("/ip address", "add address=192.168.88.1/24 interface=bridge"),
            _section("/ip dhcp-server network",
                'add address=192.168.88.0/24 dns-server=192.168.88.1 gateway=192.168.88.1'),
            _section("/ip dns", "set servers=1.1.1.1,8.8.8.8"),
        )
        assert check_dns_dhcp_gateway(content) is None

    def test_router_dns_no_forwarders_fires(self):
        from scripts.cross_checks import check_dns_dhcp_gateway
        content = _rsc("7.15",
            _section("/ip address", "add address=192.168.88.1/24 interface=bridge"),
            _section("/ip dhcp-server network",
                'add address=192.168.88.0/24 dns-server=192.168.88.1 gateway=192.168.88.1'),
            _section("/ip dns", "set cache-size=4096"),
        )
        ann = check_dns_dhcp_gateway(content)
        assert ann is not None
        assert ann.check_id == "XCHK-DNS-DHCP-GATEWAY"
        assert "but router has no upstream DNS forwarders configured" in ann.warning
        assert ann.target_finding_id == "NET-004"
        assert ann.severity == "High"

    def test_router_dns_remote_refused_fires(self):
        from scripts.cross_checks import check_dns_dhcp_gateway
        content = _rsc("7.15",
            _section("/ip address", "add address=192.168.88.1/24 interface=bridge"),
            _section("/ip dhcp-server network",
                'add address=192.168.88.0/24 dns-server=192.168.88.1 gateway=192.168.88.1'),
            _section("/ip dns", "set servers=1.1.1.1 allow-remote-requests=no"),
        )
        ann = check_dns_dhcp_gateway(content)
        assert ann is not None
        assert "allow-remote-requests=no" in ann.warning

    def test_dhcp_dns_points_elsewhere_no_finding(self):
        """DHCP gives non-router DNS server → skip check."""
        from scripts.cross_checks import check_dns_dhcp_gateway
        content = _rsc("7.15",
            _section("/ip address", "add address=192.168.88.1/24 interface=bridge"),
            _section("/ip dhcp-server network",
                'add address=192.168.88.0/24 dns-server=1.1.1.1 gateway=192.168.88.1'),
        )
        assert check_dns_dhcp_gateway(content) is None


# ═══════════════════════════════════════════════════════════════════════════
# INTERFACE-RESTRICTION
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckInterfaceRestriction:
    """XCHK-INTERFACE-RESTRICTION: services on 0.0.0.0/0 with WAN."""

    def test_no_wan_no_finding(self):
        from scripts.cross_checks import check_interface_restriction
        content = _rsc("7.15",
            _section("/ip service", "set www address=0.0.0.0/0"),
        )
        anns = check_interface_restriction(content)
        assert len(anns) == 0

    def test_restricted_services_no_finding(self):
        from scripts.cross_checks import check_interface_restriction
        content = _rsc("7.15",
            _section("/interface list member", "add interface=ether1 list=WAN"),
            _section("/ip service", "set www address=192.168.88.0/24"),
        )
        anns = check_interface_restriction(content)
        assert len(anns) == 0

    def test_exposed_service_on_wan_fires(self):
        from scripts.cross_checks import check_interface_restriction
        content = _rsc("7.15",
            _section("/interface list member", "add interface=ether1 list=WAN"),
            _section("/ip service",
                "set www address=0.0.0.0/0",
                "set winbox address=0.0.0.0/0",
            ),
        )
        anns = check_interface_restriction(content)
        assert len(anns) == 2
        ids = {a.target_finding_id for a in anns}
        assert "AUTH-011" in ids  # www
        assert "AUTH-009" in ids  # winbox

    def test_disabled_services_not_flagged(self):
        from scripts.cross_checks import check_interface_restriction
        content = _rsc("7.15",
            _section("/interface list member", "add interface=ether1 list=WAN"),
            _section("/ip service",
                "set www disabled=yes address=0.0.0.0/0",
            ),
        )
        anns = check_interface_restriction(content)
        assert len(anns) == 0


# ═══════════════════════════════════════════════════════════════════════════
# DHCP-OPTION
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckDhcpOption:
    """XCHK-DHCP-OPTION: DHCP gateway doesn't match local interfaces."""

    def test_gateway_matches_local(self):
        from scripts.cross_checks import check_dhcp_option
        content = _rsc("7.15",
            _section("/ip address", "add address=192.168.88.1/24 interface=bridge"),
            _section("/ip dhcp-server network",
                'add address=192.168.88.0/24 gateway=192.168.88.1'),
        )
        assert check_dhcp_option(content) is None

    def test_no_dhcp_no_finding(self):
        from scripts.cross_checks import check_dhcp_option
        content = _rsc("7.15")
        assert check_dhcp_option(content) is None

    def test_gateway_mismatch_no_address(self):
        from scripts.cross_checks import check_dhcp_option
        content = _rsc("7.15",
            _section("/ip address", "add address=10.0.0.1/24 interface=lan"),
            _section("/ip dhcp-server network",
                'add address=192.168.88.0/24 gateway=192.168.88.1'),
        )
        ann = check_dhcp_option(content)
        assert ann is not None
        assert ann.target_finding_id == "NET-002"
        assert ann.severity == "Medium"


# ═══════════════════════════════════════════════════════════════════════════
# NAT-FW
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckNatFw:
    """XCHK-NAT-FW: DST-NAT without matching firewall allow."""

    def test_no_nat_no_finding(self):
        from scripts.cross_checks import check_nat_fw
        content = _rsc("7.15",
            _section("/ip firewall filter",
                "add action=accept chain=forward connection-state=established,related"),
        )
        assert len(check_nat_fw(content)) == 0

    def test_dstnat_with_fw_allow_no_finding(self):
        from scripts.cross_checks import check_nat_fw
        content = _rsc("7.15",
            _section("/ip firewall nat",
                "add action=dst-nat chain=dstnat dst-port=8443 protocol=tcp to-addresses=10.0.0.42"),
            _section("/ip firewall filter",
                "add action=accept chain=forward protocol=tcp dst-port=8443"),
        )
        assert len(check_nat_fw(content)) == 0

    def test_dstnat_without_fw_allow_fires(self):
        from scripts.cross_checks import check_nat_fw
        content = _rsc("7.15",
            _section("/ip firewall nat",
                "add action=dst-nat chain=dstnat dst-port=8443 protocol=tcp to-addresses=10.0.0.42"),
            _section("/ip firewall filter",
                "add action=accept chain=input connection-state=established,related"),
        )
        anns = check_nat_fw(content)
        assert len(anns) == 1
        assert anns[0].check_id == "XCHK-NAT-FW"
        assert anns[0].severity == "High"


# ═══════════════════════════════════════════════════════════════════════════
# WIFI-BRIDGE
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckWifiBridge:
    """XCHK-WIFI-BRIDGE: WiFi interfaces not bridged."""

    def test_no_wifi_no_finding(self):
        from scripts.cross_checks import check_wifi_bridge
        content = _rsc("7.15")
        assert check_wifi_bridge(content) is None

    def test_wifi_bridged_directly(self):
        from scripts.cross_checks import check_wifi_bridge
        content = _rsc("7.15",
            _section("/interface wifi",
                'set [ find default-name=wifi2 ] disabled=no name=wifi_2ghz'),
            _section("/interface bridge port",
                "add bridge=bridge interface=wifi_2ghz"),
        )
        assert check_wifi_bridge(content) is None

    def test_wifi_bridged_via_vlan(self):
        """WiFi → VLAN → bridge port."""
        from scripts.cross_checks import check_wifi_bridge
        content = _rsc("7.15",
            _section("/interface wifi",
                'set [ find default-name=wifi2 ] disabled=no name=wifi_2ghz'),
            _section("/interface vlan",
                "add interface=wifi_2ghz name=guest_vlan20 vlan-id=20"),
            _section("/interface bridge port",
                "add bridge=bridge_guest interface=guest_vlan20"),
        )
        assert check_wifi_bridge(content) is None

    def test_disabled_wifi_not_flagged(self):
        from scripts.cross_checks import check_wifi_bridge
        content = _rsc("7.15",
            _section("/interface wifi",
                'set [ find default-name=wifi2 ] disabled=yes name=wifi_2ghz'),
        )
        assert check_wifi_bridge(content) is None

    def test_unbridged_wifi_fires(self):
        from scripts.cross_checks import check_wifi_bridge
        content = _rsc("7.15",
            _section("/interface wifi",
                'set [ find default-name=wifi2 ] disabled=no name=wifi_2ghz'),
        )
        ann = check_wifi_bridge(content)
        assert ann is not None
        assert ann.check_id == "XCHK-WIFI-BRIDGE"
        assert "wifi_2ghz" in ann.warning


# ═══════════════════════════════════════════════════════════════════════════
# PORT-SERVICE
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckPortService:
    """XCHK-PORT-SERVICE: port conflicts between services."""

    def test_no_port_conflicts(self):
        from scripts.cross_checks import check_port_service
        content = _rsc("7.15",
            _section("/ip service",
                "set www port=80",
                "set ssh port=22",
            ),
        )
        assert len(check_port_service(content)) == 0

    def test_port_conflict_fires(self):
        from scripts.cross_checks import check_port_service
        content = _rsc("7.15",
            _section("/ip service",
                "set www port=8080",
                "set www-ssl port=8080",
            ),
        )
        anns = check_port_service(content)
        assert len(anns) == 1
        assert "8080" in anns[0].warning
        assert "www" in anns[0].warning
        assert "www-ssl" in anns[0].warning

    def test_no_services_no_finding(self):
        from scripts.cross_checks import check_port_service
        content = _rsc("7.15")
        assert len(check_port_service(content)) == 0


# ═══════════════════════════════════════════════════════════════════════════
# BRIDGE-VLAN
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckBridgeVlan:
    """XCHK-BRIDGE-VLAN: VLAN interfaces not in bridge VLAN table."""

    def test_no_vlans_no_finding(self):
        from scripts.cross_checks import check_bridge_vlan
        content = _rsc("7.15")
        assert check_bridge_vlan(content) is None

    def test_vlan_in_bridge_table(self):
        from scripts.cross_checks import check_bridge_vlan
        content = _rsc("7.15",
            _section("/interface vlan",
                "add interface=bridge name=vlan10 vlan-id=10"),
            _section("/interface bridge port",
                "add bridge=bridge interface=ether2 pvid=10"),
        )
        assert check_bridge_vlan(content) is None

    def test_unregistered_vlan_fires(self):
        from scripts.cross_checks import check_bridge_vlan
        content = _rsc("7.15",
            _section("/interface vlan",
                "add interface=ether1 name=telekom_vlan vlan-id=7"),
            _section("/interface bridge port",
                "add bridge=bridge interface=ether2"),
        )
        ann = check_bridge_vlan(content)
        assert ann is not None
        assert ann.check_id == "XCHK-BRIDGE-VLAN"
        assert "telekom_vlan" in ann.warning
        assert ann.severity == "Medium"


# ═══════════════════════════════════════════════════════════════════════════
# Integration: run_cross_checks entry point
# ═══════════════════════════════════════════════════════════════════════════

class TestRunCrossChecks:
    """run_cross_checks orchestrator."""

    def test_clean_config_no_findings(self):
        from scripts.cross_checks import run_cross_checks
        content = _rsc("7.15",
            _section("/ip address", "add address=192.168.88.1/24 interface=bridge"),
            _section("/ip dhcp-server network",
                'add address=192.168.88.0/24 dns-server=192.168.88.1 gateway=192.168.88.1'),
            _section("/ip dns", "set servers=1.1.1.1"),
            _section("/interface list member", "add interface=ether1 list=WAN"),
            _section("/ip service", "set www address=192.168.88.0/24"),
            _section("/interface wifi",
                'set [ find default-name=wifi2 ] disabled=no name=wifi_2ghz'),
            _section("/interface bridge port",
                "add bridge=bridge interface=wifi_2ghz"),
        )
        anns = run_cross_checks(content)
        assert len(anns) == 0

    def test_dns_misconfig_fires(self):
        from scripts.cross_checks import run_cross_checks
        content = _rsc("7.15",
            _section("/ip address", "add address=192.168.88.1/24 interface=bridge"),
            _section("/ip dhcp-server network",
                'add address=192.168.88.0/24 dns-server=192.168.88.1 gateway=192.168.88.1'),
            _section("/ip dns", "set cache-size=4096"),  # no servers=
        )
        anns = run_cross_checks(content)
        ids = {a.check_id for a in anns}
        assert "XCHK-DNS-DHCP-GATEWAY" in ids

    def test_bad_data_doesnt_crash(self):
        """Garbage content shouldn't crash the orchestrator."""
        from scripts.cross_checks import run_cross_checks
        anns = run_cross_checks("this is not a routeros export at all !!!")
        assert isinstance(anns, list)
