---
description: >-
  Complete audit checklist for MikroTik RouterOS .rsc configuration files.
  100+ checks across 9 security domains with CVSS scoring, detection queries,
  and remediation commands. Use as reference when running RouterOS audits.
---

# Audit Checks Reference

## Security Domain Overview

| Domain | Code | Checks | Severity Range | Purpose |
|--------|------|--------|----------------|---------|
| Authentication & Access Control | AUTH | 18 | Critical | Default accounts, passwords, service ACLs, RoMON, policy restrictions |
| Service Hardening | SRV | 17 | High | Unnecessary/disabling services, WAN exposure, insecure protocols |
| Firewall & Network Security | FW | 17 | Critical–High | Filter/NAT/RAW rules, brute-force protection, connection tracking |
| System Hardening | SYS | 10 | High–Medium | Version, NTP, logging, updates, backups, watchdog |
| Network Configuration | NET | 9 | Medium | VLANs, DHCP, DNS, bridges, MTU, IGMP |
| Routing Security | ROUTE | 9 | Medium–High | BGP/OSPF auth, filters, prefix limits, default route |
| WiFi Security | WIFI | 13 | High–Medium | Encryption, WPS, isolation, CAPsMAN, PMF, rogue AP |
| Script & Automation | SCRIPT | 9 | Medium | Permissions, secrets, scheduler, error handling |
| Compliance Mapping | COMP | 6 | Info | CIS, NIST, ISO, PCI-DSS, ATT&CK, CVSS mappings |

**Total: 108 checks**

---

## Check Format

Each audit check in this document uses the following fields:

- **ID** — Unique hyphenated identifier (DOM-NNN)
- **Severity** — CVSS v3.1 severity rating with score
- **Category** — Security domain classification
- **Path** — RouterOS config path where the finding manifests
- **What to look for** — Human-readable description of the misconfiguration
- **Detection** — RouterOS config patterns indicating the finding
- **Rationale** — Security justification for the check
- **Remediation** — Exact RouterOS CLI commands to fix
- **Compliance** — Framework control mappings (CIS, NIST, ISO, PCI)
- **Note** — Device-specific or context-specific considerations (where applicable)

---

## AUTH — Authentication & Access Control (18 checks)

### AUTH-001: Default admin user present
**Severity**: Critical (CVSS 9.8)
**Category**: Authentication & Access Control
**Path**: `/user`
**What to look for**: The default `admin` user exists without being disabled or removed
**Detection**:
  - `/user add name=admin` or `/user set ... name=admin` without `disabled=yes`
  - No `/user set [find name=admin] disabled=yes` (admin user not disabled)
**Rationale**: Default admin credentials are widely known. The `admin` username should be renamed or a new admin user created and the default admin disabled. Leaving the default admin active with default credentials allows instant compromise.
**Remediation**:
  ```
  /user set [find name=admin] disabled=yes
  /user add name=<unique-admin> group=full password=<strong-password>
  ```
**Safety Warning**: Disabling the default admin without creating an alternative admin first will lock you out of the router. Always test by keeping an active SSH session while making changes.
**Compliance**: CIS RouterOS v1.x 1.1, NIST AC-2(1), ISO 27001 A.9.2.1, PCI-DSS 8.1
**Note**: All hAP models ship with default admin user — must be renamed on first boot.

### AUTH-002: No password set on admin user
**Severity**: Critical (CVSS 9.8)
**Category**: Authentication & Access Control
**Path**: `/user`
**What to look for**: A user account (especially `admin`) with no password or an empty password hash
**Detection**:
  - `/user add name=admin password=""` or `password=` absent
  - Hash field missing or empty: `/user set ...` without `password=`
  - `hide-sensitive` output shows `[REDACTED]` for all users — flag for live verification
**Rationale**: A user without a password is an open backdoor. Any network-local attacker can authenticate without credentials.
**Remediation**:
  ```
  /user set [find name=admin] password=<strong-password>
  ```
**Compliance**: CIS RouterOS v1.x 1.2, NIST IA-5(1), ISO 27001 A.9.3.1, PCI-DSS 8.2.3

### AUTH-003: Weak password patterns
**Severity**: Critical (CVSS 8.6)
**Category**: Authentication & Access Control
**Path**: `/user`
**What to look for**: Short passwords (<8 characters), common dictionary passwords, no character complexity
**Detection**:
  - When `hide-sensitive=no` exported: `password=` value shorter than 8 characters
  - When `hide-sensitive=yes` or password hash visible: check hash against known weak patterns (hash length, MD5-based $1$ prefix)
  - Known default passwords: `admin`, `1234`, `password`, `default`, blank
**Rationale**: Weak passwords are trivially bruteforceable. RouterOS does not enforce strength natively — the administrator must enforce password quality.
**Remediation**:
  ```
  /user set [find] password=<16+char-password-with-complexity>
  ```
**Compliance**: CIS RouterOS v1.x 1.3, NIST IA-5(1)(a), ISO 27001 A.9.3.1, PCI-DSS 8.2.3

### AUTH-004: Users in 'full' group without IP restrictions
**Severity**: High (CVSS 8.1)
**Category**: Authentication & Access Control
**Path**: `/user`
**What to look for**: Users in the `full` group that do not have `address=X.X.X.X/X` set to restrict login source
**Detection**:
  - `/user set [find group=full]` without `address=...` or with `address=0.0.0.0/0`
  - `/user add group=full` without `address=` parameter
**Rationale**: Full administrative access should only be possible from trusted management networks. Without source-IP restrictions, an attacker who obtains credentials can log in from anywhere.
**Remediation**:
  ```
  /user set [find group=full] address=<mgmt-subnet>
  ```
**Safety Warning**: Adding IP restrictions to users in the 'full' group may lock out administrators currently connected from outside the allowed subnet. Ensure at least one admin session is within the new restriction before applying.
**Compliance**: CIS RouterOS v1.x 1.4, NIST AC-6, ISO 27001 A.9.2.3, PCI-DSS 7.2.1

### AUTH-005: SSH weak-crypto enabled
**Severity**: High (CVSS 7.5)
**Category**: Authentication & Access Control
**Path**: `/ip ssh`
**What to look for**: SSH configured with `strong-crypto=no`
**Detection**:
  - `/ip ssh set strong-crypto=no`
  - Absence of `/ip ssh set strong-crypto=yes`
**Rationale**: Weak crypto enables legacy ciphers (RC4, 3DES, MD5 MACs) that are vulnerable to numerous attacks. RouterOS v6+ supports strong crypto (AES-CTR, SHA2, ECDH).
**Remediation**:
  ```
  /ip ssh set strong-crypto=yes host-key-size=4096
  ```
**Compliance**: CIS RouterOS v1.x 2.1, NIST SC-13, ISO 27001 A.10.1.1, PCI-DSS 4.1

### AUTH-006: MAC-Telnet service enabled
**Severity**: High (CVSS 7.5)
**Category**: Authentication & Access Control
**Path**: `/tool mac-server`
**What to look for**: MAC-Telnet service is accessible from unrestricted interfaces
**Detection**:
  - `/tool mac-server set allowed-interface-list=all` or `=bridge` where bridge has WAN access
  - Absence of `/tool mac-server set allowed-interface-list=none` or a specific management-only list
**Rationale**: MAC-Telnet bypasses IP-level authentication and encryption. Layer-2 access is sufficient to connect. If exposed on WAN-facing bridges, attackers on the broadcast domain can connect without IP connectivity.
**Remediation**:
  ```
  /tool mac-server set allowed-interface-list=none
  ```
**Compliance**: CIS RouterOS v1.x 2.2, NIST AC-6, ISO 27001 A.13.1.1, PCI-DSS 2.2.2

### AUTH-007: MAC-WinBox service enabled
**Severity**: High (CVSS 7.4)
**Category**: Authentication & Access Control
**Path**: `/tool mac-server mac-winbox`
**What to look for**: MAC-WinBox service accessible from unrestricted interfaces
**Detection**:
  - `/tool mac-server mac-winbox set allowed-interface-list=all` or `=bridge`
  - Absence of the restriction to a management-only list
**Rationale**: MAC-WinBox provides WinBox over layer-2 without IP, bypassing firewall rules. It should only be available on dedicated out-of-band management interfaces, never on WAN or general LAN bridges.
**Remediation**:
  ```
  /tool mac-server mac-winbox set allowed-interface-list=none
  ```
**Compliance**: CIS RouterOS v1.x 2.3, NIST AC-6, ISO 27001 A.13.1.1, PCI-DSS 2.2.2

### AUTH-008: MAC-Ping service enabled
**Severity**: Medium (CVSS 6.5)
**Category**: Authentication & Access Control
**Path**: `/tool mac-server ping` or `/ip neighbor discovery`
**What to look for**: MAC-layer ping responses enabled on WAN interfaces
**Detection**:
  - `/tool mac-server ping set enabled=yes` on WAN or unrestricted interface list
  - `/ip neighbor discovery-settings set discover-interface-list=all`
**Rationale**: MAC-ping leaks presence information at layer-2 and can be used for network reconnaissance. It should be restricted or disabled on untrusted interfaces.
**Remediation**:
  ```
  /ip neighbor discovery-settings set discover-interface-list=none
  /tool mac-server ping set enabled=no
  ```
**Compliance**: CIS RouterOS v1.x 2.4, NIST SC-7, ISO 27001 A.13.1.1, PCI-DSS 2.2.2

### AUTH-009: WinBox service exposed on WAN
**Severity**: Critical (CVSS 9.1)
**Category**: Authentication & Access Control
**Path**: `/ip service winbox`
**What to look for**: WinBox accessible from WAN interface or 0.0.0.0/0
**Detection**:
  - `/ip service set winbox address=0.0.0.0/0` or `address=::/0`
  - `/ip service set winbox` without `address=` restriction
  - WAN interface firewall not blocking port 8291
**Rationale**: WinBox uses a proprietary protocol with known vulnerabilities. Exposing it to WAN allows unauthenticated connection attempts and protocol-level attacks. All management must be restricted to trusted networks or VPN.
**Remediation**:
  ```
  /ip service set winbox address=<mgmt-subnet>
  /ip firewall filter add chain=input in-interface=<wan> protocol=tcp dst-port=8291 action=drop
  ```
**Compliance**: CIS RouterOS v1.x 2.5, NIST AC-6, ISO 27001 A.13.1.1, PCI-DSS 1.3.2

### AUTH-010: API/REST-API exposed on WAN
**Severity**: Critical (CVSS 9.0)
**Category**: Authentication & Access Control
**Path**: `/ip service api`, `/ip service api-ssl`
**What to look for**: API or API-SSL accessible from WAN or 0.0.0.0/0
**Detection**:
  - `/ip service set api address=0.0.0.0/0` or `api-ssl address=0.0.0.0/0`
  - `/ip service set api disabled=no` or `api-ssl disabled=no` without address restriction
**Rationale**: The API provides programmatic access to the router. Exposed to WAN, it becomes a high-value attack surface. All API access should be restricted to management subnets or tunneled over VPN.
**Remediation**:
  ```
  /ip service set api disabled=yes
  /ip service set api-ssl address=<mgmt-subnet>
  ```
**Compliance**: CIS RouterOS v1.x 2.6, NIST AC-6, ISO 27001 A.13.1.1, PCI-DSS 1.3.2

### AUTH-011: No login attempt restrictions
**Severity**: High (CVSS 7.5)
**Category**: Authentication & Access Control
**Path**: `/ip firewall filter` (input chain)
**What to look for**: No firewall rules limiting connection attempts to management services
**Detection**:
  - No `/ip firewall filter` rules with `connection-state=new` and `dst-port=22,8291,80,443` with `limit` or `addr-list` rate limiting
  - No `/ip firewall filter` rules dropping excessive connections to `/ip service` ports
**Rationale**: Without rate limiting, an attacker can brute force passwords indefinitely. Connection-rate limiting on input chain for management services provides essential brute-force mitigation.
**Remediation**:
  ```
  /ip firewall filter add chain=input dst-port=22,8291 protocol=tcp connection-state=new \
      src-address-list=ssh_blacklist action=drop
  /ip firewall filter add chain=input dst-port=22,8291 protocol=tcp connection-state=new \
      src-address-list=ssh_stage3 action=add-src-to-list list=ssh_blacklist timeout=1h
  /ip firewall filter add chain=input dst-port=22,8291 protocol=tcp connection-state=new \
      src-address-list=ssh_stage2 action=add-src-to-list list=ssh_stage3 timeout=1m
  /ip firewall filter add chain=input dst-port=22,8291 protocol=tcp connection-state=new \
      src-address-list=ssh_stage1 action=add-src-to-list list=ssh_stage2 timeout=30s
  /ip firewall filter add chain=input dst-port=22,8291 protocol=tcp connection-state=new \
      action=add-src-to-list list=ssh_stage1 timeout=10s
  ```
**Compliance**: CIS RouterOS v1.x 1.5, NIST AC-7, ISO 27001 A.9.4.1, PCI-DSS 8.1.6

### AUTH-012: Default management ports unchanged
**Severity**: Medium (CVSS 5.3)
**Category**: Authentication & Access Control
**Path**: `/ip service`
**What to look for**: Default port numbers for management services — SSH (22), WinBox (8291), API (8728), API-SSL (8729), HTTP (80), HTTPS (443)
**Detection**:
  - `/ip service set ssh port=22`
  - `/ip service set winbox port=8291`
  - `/ip service set api port=8728`
  - `/ip service set api-ssl port=8729`
  - `/ip service set www port=80`
  - `/ip service set www-ssl port=443`
**Rationale**: Default ports are targeted by automated scanners. Changing management ports reduces noise from mass scans. This is defense-in-depth — proper firewall rules remain the primary control.
**Remediation**:
  ```
  /ip service set ssh port=<non-standard-port>
  /ip service set winbox port=<non-standard-port>
  /ip service set api port=<non-standard-port>
  ```
**Compliance**: CIS RouterOS v1.x 2.7, NIST SC-7, ISO 27001 A.13.1.1, PCI-DSS 2.2.3

### AUTH-013: RoMON enabled
**Severity**: High (CVSS 7.2)
**Category**: Authentication & Access Control
**Path**: `/romon`
**What to look for**: RoMON protocol enabled
**Detection**:
  - `/romon set enabled=yes`
  - `hide-sensitive` obscuring the value — flag for live verification
**Rationale**: RoMON is a proprietary L2 discovery and management protocol. If enabled on WAN-facing interfaces, it allows router discovery and potential management-plane access at layer-2. Only enable for specific management applications on isolated OOB networks.
**Remediation**:
  ```
  /romon set enabled=no
  ```
**Compliance**: CIS RouterOS v1.x 2.8, NIST AC-3, ISO 27001 A.13.1.1, PCI-DSS 2.2.2

### AUTH-014: No password policy configured
**Severity**: Medium (CVSS 5.9)
**Category**: Authentication & Access Control
**Path**: `/user settings`
**What to look for**: No minimum password length or complexity settings
**Detection**:
  - `/user settings` not present in export
  - `/user settings set minimum-password-length=0` or absent
  - `/user settings` without `password-strength-check` or similar
**Rationale**: RouterOS v7+ allows setting minimum password length via `/user settings`. Without it, users may choose short/weak passwords. Enforcing minimum length is the first line of password defense.
**Remediation**:
  ```
  /user settings set minimum-password-length=8
  ```
**Compliance**: CIS RouterOS v1.x 1.6, NIST IA-5(1)(a), ISO 27001 A.9.3.1, PCI-DSS 8.2.3

### AUTH-015: User accounts without expiry configured
**Severity**: Medium (CVSS 5.3)
**Category**: Authentication & Access Control
**Path**: `/user`
**What to look for**: Service or temporary accounts without expiry dates
**Detection**:
  - `/user add ...` without `comment=expires:YYYY-MM-DD` or similar convention
  - No procedural mechanism for account expiry
**Rationale**: Without expiry, temporary or service accounts remain active indefinitely. An attacker who obtains a stale credential maintains persistent access. RouterOS does not support native account expiry via `/user` — organizations must implement procedural controls or use RADIUS for expiry enforcement.
**Remediation**:
  ```
  /user set [find comment~"temporary"] disabled=yes
  # Implement out-of-band expiry tracking via scheduler and comment convention
  ```
**Compliance**: NIST AC-2(3), ISO 27001 A.9.2.4, PCI-DSS 8.1.4

### AUTH-016: Sensitive policies too permissive
**Severity**: High (CVSS 7.7)
**Category**: Authentication & Access Control
**Path**: `/user group`
**What to look for**: Groups with `policy=full` or combined sensitive policies all at once
**Detection**:
  - `/user group set full policy=full,...` or `=read,write,policy,test,sniff,sensitive,reboot`
  - `/user group add policy=full`
  - Default v7.22 policies: `local,reboot,read,write,policy,test,winbox,password,web,ssh,telnet,sniff,sensitive,api,romon,dude,tikapp,rest-api`
**Rationale**: Granting `full` or combining `read,write,policy,test,sniff,sensitive,reboot` gives broad capabilities that violate least privilege. `sensitive` policy allows viewing passwords and secrets. `sniff` allows traffic capture. These should be granted individually to specific groups for specific roles.
**Remediation**:
  ```
  # Create specific groups with minimal policies instead of modifying 'full':
  /user group add name=monitor policy=read,test,local,winbox,password
  /user group add name=operator policy=read,write,policy,test,reboot,local,winbox,password,web,ssh
  /user group add name=admin-hardened policy=local,reboot,read,write,policy,test,winbox,password,web,ssh,telnet,sniff,sensitive,api,romon,dude,tikapp,rest-api

  # Migrate users from 'full' to new group:
  /user set [find group=full] group=admin-hardened

  # NOTE: The default 'full' group is left intact with its full policy as emergency fallback.
  # This approach avoids lock-out risk from replacing the 'full' group's policy list.
  ```
**Compliance**: CIS RouterOS v1.x 1.7, NIST AC-6, ISO 27001 A.9.2.3, PCI-DSS 7.2.1

### AUTH-017: SSH idle timeout not configured
**Severity**: Medium (CVSS 5.3)
**Category**: Authentication & Access Control
**Path**: `/ip ssh`
**What to look for**: SSH idle timeout not set or set too high
**Detection**:
  - `/ip ssh set` without `idle-timeout=...` (default is infinite on RouterOS v6, 10m on v7)
  - `/ip ssh set idle-timeout=0` (infinite idle timeout)
  - `/ip ssh set idle-timeout=1h` or higher
**Rationale**: Without an idle timeout, an SSH session stays open indefinitely. An unattended authenticated session is a risk — any passerby with access to the console or a connected machine can take over.
**Remediation**:
  ```
  /ip ssh set idle-timeout=5m
  ```
**Compliance**: NIST SC-10, ISO 27001 A.11.2.8, PCI-DSS 8.1.8, CIS RouterOS v1.x 2.9

### AUTH-018: RADIUS AAA not configured for admin authentication
**Severity**: Medium (CVSS 5.0)
**Category**: Authentication & Access Control
**Path**: `/radius`, `/user aaa`
**What to look for**: RADIUS authentication not configured for admin users
**Detection**:
  - `/user aaa set use-radius=no` or absent
  - No `/radius add` configuration present
**Rationale**: Local-only authentication limits audit trail and centralized control. RADIUS provides centralized authentication, authorization, and accounting. For environments with multiple devices or compliance requirements, RADIUS is preferred for admin access.
**Remediation**:
  ```
  /radius add address=<radius-server> secret=<radius-secret> service=login
  /user aaa set use-radius=yes accounting=yes interim-update=10s
  ```
**Compliance**: NIST AC-2(4), ISO 27001 A.9.2.1, PCI-DSS 8.3.2

---

## SRV — Service Hardening (17 checks)

### SRV-001: DNS remote requests allowed
**Severity**: High (CVSS 8.0)
**Category**: Service Hardening
**Path**: `/ip dns`
**What to look for**: DNS service allowing remote queries
**Detection**:
  - `/ip dns set allow-remote-requests=yes`
**Rationale**: An open DNS resolver can be used for amplification DDoS attacks. This makes your router a participant in attacks against third parties. Only internal LAN interfaces should have DNS service enabled.
**Remediation**:
  ```
  /ip dns set allow-remote-requests=no
  # Or restrict with specific interfaces:
  /ip dns set allow-remote-requests=yes interface=<lan-interface>
  ```
**Compliance**: CIS RouterOS v1.x 5.1, NIST SC-7, ISO 27001 A.13.1.3, PCI-DSS 2.2.2

### SRV-002: Bandwidth server enabled
**Severity**: High (CVSS 7.5)
**Category**: Service Hardening
**Path**: `/tool bandwidth-server`
**What to look for**: Bandwidth test server enabled
**Detection**:
  - `/tool bandwidth-server set enabled=yes`
**Rationale**: The bandwidth server is a CPU-intensive service that can be abused for resource-exhaustion attacks. It responds to bandwidth test requests from any reachable host, consuming CPU and memory on the router.
**Remediation**:
  ```
  /tool bandwidth-server set enabled=no
  ```
**Compliance**: CIS RouterOS v1.x 3.1, NIST SC-7, ISO 27001 A.17.2.1, PCI-DSS 2.2.2

### SRV-003: Proxy service enabled
**Severity**: High (CVSS 7.5)
**Category**: Service Hardening
**Path**: `/ip proxy`
**What to look for**: HTTP Proxy service enabled
**Detection**:
  - `/ip proxy set enabled=yes`
**Rationale**: The RouterOS proxy can be abused as an open HTTP proxy, allowing traffic relay and IP address hiding. It also introduces unnecessary processing overhead on the router.
**Remediation**:
  ```
  /ip proxy set enabled=no
  ```
**Compliance**: NIST SC-7, ISO 27001 A.13.1.1, PCI-DSS 2.2.2

### SRV-004: SOCKS service enabled
**Severity**: High (CVSS 7.2)
**Category**: Service Hardening
**Path**: `/ip socks`
**What to look for**: SOCKS proxy service enabled
**Detection**:
  - `/ip socks set enabled=yes`
**Rationale**: SOCKS proxies provide TCP/UDP relay with minimal logging. An open SOCKS proxy on the router can be abused for traffic relay and malicious activity proxying.
**Remediation**:
  ```
  /ip socks set enabled=no
  ```
**Compliance**: NIST SC-7, ISO 27001 A.13.1.1, PCI-DSS 2.2.2

### SRV-005: UPnP enabled
**Severity**: High (CVSS 7.5)
**Category**: Service Hardening
**Path**: `/ip upnp`
**What to look for**: Universal Plug and Play service enabled
**Detection**:
  - `/ip upnp set enabled=yes`
  - `/ip upnp interfaces` present with `type=external`
**Rationale**: UPnP allows internal devices to open firewall ports automatically. This bypasses the firewall policy and has been exploited by malware to expose internal services. UPnP should be disabled except in specific SOHO scenarios where it is explicitly required.
**Remediation**:
  ```
  /ip upnp set enabled=no
  ```
**Compliance**: NIST SC-7(3), ISO 27001 A.13.1.1, PCI-DSS 1.3.4

### SRV-006: Neighbor discovery enabled on WAN interfaces
**Severity**: Medium (CVSS 4.9)
**Category**: Service Hardening
**Path**: `/ip neighbor discovery-settings`
**What to look for**: Discovery protocols (MNDP/CDP/LLDP) enabled on WAN interfaces
**Detection**:
  - `/ip neighbor discovery-settings set discover-interface-list=all`
  - `/ip neighbor discovery` entries for WAN interfaces without explicit disable
**Rationale**: Neighbor discovery leaks router identity, model, uptime, interface names, and MAC addresses. On WAN interfaces this provides reconnaissance data to external attackers.
**Remediation**:
  ```
  # Create a management-only interface list:
  /interface list add name=mgmt-vlan
  /interface list member add list=mgmt-vlan interface=mgmt-vlan
  /ip neighbor discovery-settings set discover-interface-list=mgmt-vlan
  ```
**Compliance**: CIS RouterOS v1.x 3.2, NIST SC-7, ISO 27001 A.13.1.1, PCI-DSS 2.2.2

### SRV-007: SNMP v1/v2c with public community
**Severity**: High (CVSS 8.0)
**Category**: Service Hardening
**Path**: `/snmp community`
**What to look for**: SNMP community string set to `public` or other well-known strings
**Detection**:
  - `/snmp community set public address=` or `address=0.0.0.0/0`
  - `/snmp community set public name=public`
  - `/snmp community add name=public`
  - `/snmp set enabled=yes` with weak communities
**Rationale**: SNMP v1/v2c sends community strings in cleartext. The `public` community is universally known and allows read-only or read-write access. Attackers use SNMP to enumerate interfaces, routes, ARP tables, and user accounts.
**Remediation**:
  ```
  /snmp community set [find name=public] disabled=yes
  /snmp community add name=<random-community> address=<mgmt-subnet>
  ```
**Compliance**: CIS RouterOS v1.x 4.1, NIST SI-7, ISO 27001 A.12.6.2, PCI-DSS 2.2.3

### SRV-008: Telnet service enabled
**Severity**: High (CVSS 7.6)
**Category**: Service Hardening
**Path**: `/ip service telnet`
**What to look for**: Telnet service enabled
**Detection**:
  - `/ip service set telnet disabled=no`
**Rationale**: Telnet transmits all data including credentials in cleartext. Any attacker with access to the path between client and router can capture passwords. SSH must be used instead.
**Remediation**:
  ```
  /ip service set telnet disabled=yes
  ```
**Compliance**: CIS RouterOS v1.x 2.10, NIST IA-5(1), ISO 27001 A.10.1.1, PCI-DSS 4.1

### SRV-009: FTP service enabled
**Severity**: High (CVSS 7.4)
**Category**: Service Hardening
**Path**: `/ip service ftp`
**What to look for**: FTP service enabled
**Detection**:
  - `/ip service set ftp disabled=no`
**Rationale**: FTP transmits credentials and data in cleartext. RouterOS FTP also allows the default admin to transfer files. Use SCP/SFTP over SSH or HTTP over HTTPS instead.
**Remediation**:
  ```
  /ip service set ftp disabled=yes
  ```
**Compliance**: CIS RouterOS v1.x 2.11, NIST IA-5(1), ISO 27001 A.10.1.1, PCI-DSS 4.1

### SRV-010: PPTP server enabled
**Severity**: High (CVSS 7.2)
**Category**: Service Hardening
**Path**: `/ppp profile`, `/interface pptp-server`
**What to look for**: PPTP VPN server enabled
**Detection**:
  - `/interface pptp-server server set enabled=yes`
  - `/ppp profile set ... use-encryption=no` or `use-mppe=no`
  - `/ppp profile set default` with `local-address=...` and `remote-address=...` indicating PPTP usage
**Rationale**: PPTP is deprecated due to known vulnerabilities (MSCHAPv2 weaknesses, RC4 encryption). L2TP/IPsec or SSTP should be used instead. PPTP should be disabled entirely.
**Remediation**:
  ```
  /interface pptp-server server set enabled=no
  ```
**Compliance**: NIST SC-8, ISO 27001 A.10.1.1, PCI-DSS 4.1

### SRV-011: Cloud services enabled
**Severity**: Medium (CVSS 5.5)
**Category**: Service Hardening
**Path**: `/ip cloud`
**What to look for**: MikroTik Cloud DDNS or automatic update-time enabled
**Detection**:
  - `/ip cloud set ddns-enabled=yes`
  - `/ip cloud set update-time=yes`
**Rationale**: MikroTik Cloud provides DDNS and time synchronization via MikroTik's infrastructure. While convenient, it exposes the router's public IP to an external service, and the DDNS hostname could be used to locate the router. For sensitive environments, disable cloud services and use internal NTP and DDNS.
**Remediation**:
  ```
  /ip cloud set ddns-enabled=no update-time=no
  ```
**Compliance**: NIST AC-20, ISO 27001 A.13.1.1, PCI-DSS 2.2.2

### SRV-012: SMB service enabled
**Severity**: High (CVSS 7.2)
**Category**: Service Hardening
**Path**: `/ip smb`
**What to look for**: SMB file sharing service enabled
**Detection**:
  - `/ip smb set enabled=yes`
**Rationale**: SMB on RouterOS provides file sharing from the router's filesystem. This is rarely needed and introduces multiple protocol-level attack vectors. SMB has a history of critical vulnerabilities across implementations.
**Remediation**:
  ```
  /ip smb set enabled=no
  ```
**Compliance**: NIST SC-7, ISO 27001 A.13.1.1, PCI-DSS 2.2.2

### SRV-013: Unused interfaces not disabled
**Severity**: Low (CVSS 3.1)
**Category**: Service Hardening
**Path**: `/interface ethernet`
**What to look for**: Physical interfaces that are unused but not disabled
**Detection**:
  - `/interface ethernet set X disabled=no` for ports without `comment=` or `poe=` config
  - `/interface ethernet` entries with `disabled=no` but no `comment=`, `poe=` role assignment, or `master-port=` reference
  - Note: `running` status is a live property — not available in static .rsc exports. Detection based on missing documentation comments.
**Rationale**: Every enabled interface is an attack surface. Unused ports should be administratively disabled to prevent physical access attacks and reduce noise in logs.
**Remediation**:
  ```
  /interface ethernet set [find where !running] disabled=yes
  # Or individually:
  /interface ethernet set ether5 disabled=yes
  ```
**Compliance**: NIST AC-4, ISO 27001 A.11.2.6, PCI-DSS 2.2.2

### SRV-014: WebFig/HTTP enabled without HTTPS
**Severity**: High (CVSS 7.4)
**Category**: Service Hardening
**Path**: `/ip service www`, `/ip service www-ssl`
**What to look for**: HTTP (WebFig) enabled while HTTPS is disabled
**Detection**:
  - `/ip service set www disabled=no`
  - `/ip service set www-ssl disabled=yes` or not configured
**Rationale**: HTTP transmits all traffic including session cookies in cleartext. All web access to the router must be over TLS. If web management is not needed, disable HTTP entirely.
**Remediation**:
  ```
  /ip service set www disabled=yes
  # OR:
  /ip service set www-ssl disabled=no certificate=<valid-cert> address=<mgmt-subnet>
  ```
**Compliance**: CIS RouterOS v1.x 2.12, NIST SC-8, ISO 27001 A.10.1.2, PCI-DSS 4.1

### SRV-015: LCD not secured
**Severity**: Low (CVSS 2.6)
**Category**: Service Hardening
**Path**: `/lcd`
**What to look for**: LCD panel without PIN protection on devices with physical display
**Detection**:
  - `/lcd set enabled=yes` without `/lcd set pin=...`
  - `/lcd set pin=""` or absent
**Rationale**: On devices with LCD screens and buttons (hAP series, RB4011), the LCD provides physical access to basic router information and configuration. Without PIN protection, anyone with physical access can view IP addresses, interface status, and possibly trigger actions.
**Remediation**:
  ```
  /lcd set enabled=yes pin=<4-digit-pin>
  ```
**Compliance**: NIST PE-3, ISO 27001 A.11.1.1, PCI-DSS 9.1.1
**Note**: Only applies to devices with physical LCD — hAP ac², hAP ax³, RB4011, etc.

### SRV-016: DNS cache size not configured
**Severity**: Low (CVSS 3.7)
**Category**: Service Hardening
**Path**: `/ip dns`
**What to look for**: DNS cache size left at default or set very large without memory consideration
**Detection**:
  - `/ip dns set` without `cache-size=...`
  - `/ip dns set cache-size=20480` or higher on flash-constrained devices
**Rationale**: The DNS cache uses RAM. On memory-constrained devices (hAP ac² with 128MB RAM), a large DNS cache can contribute to memory pressure. Set an appropriate cache size based on available memory.
**Remediation**:
  ```
  /ip dns set cache-size=2048
  ```
**Compliance**: N/A (operational hardening)
**Note**: hAP ac² and other 128MB-RAM devices should use cache-size=2048 maximum.

### SRV-017: Graphing service enabled
**Severity**: Low (CVSS 3.1)
**Category**: Service Hardening
**Path**: `/tool graphing`
**What to look for**: Traffic graphing interface enabled on the router
**Detection**:
  - `/tool graphing set enabled=yes`
  - `/tool graphing interface` entries present
  - `/tool graphing resource add ... disabled=no`
**Rationale**: The graphing interface exposes traffic and resource usage data. While low-risk as informational, it can reveal traffic patterns to attackers performing reconnaissance.
**Remediation**:
  ```
  /tool graphing set enabled=no
  ```
**Compliance**: NIST SC-7, ISO 27001 A.13.1.1

---

## FW — Firewall & Network Security (17 checks)

### FW-001: No firewall filter rules at all
**Severity**: Critical (CVSS 10.0)
**Category**: Firewall & Network Security
**Path**: `/ip firewall filter`
**What to look for**: No filter rules defined at all
**Detection**:
  - `/ip firewall filter` not present in the export
  - Empty `/ip firewall filter` block
**Rationale**: A RouterOS device without firewall filter rules passes all traffic. There is no access control, no security policy enforcement, and the router management interfaces are fully exposed. This is the most critical security finding possible.
**Remediation**:
  ```
  # Essential minimum rules:
  /ip firewall filter add chain=input connection-state=established,related action=accept
  /ip firewall filter add chain=input connection-state=invalid action=drop
  /ip firewall filter add chain=input in-interface=<lan> action=accept
  /ip firewall filter add chain=input action=drop
  /ip firewall filter add chain=forward connection-state=established,related action=accept
  /ip firewall filter add chain=forward connection-state=invalid action=drop
  /ip firewall filter add chain=forward in-interface=<lan> action=accept
  /ip firewall filter add chain=forward action=drop
  ```
**Compliance**: CIS RouterOS v1.x 3.3, NIST SC-7, ISO 27001 A.13.1.1, PCI-DSS 1.1, PCI-DSS 1.2

### FW-002: WAN input chain without a default drop rule
**Severity**: Critical (CVSS 9.2)
**Category**: Firewall & Network Security
**Path**: `/ip firewall filter` (input chain)
**What to look for**: No `action=drop` rule at the end of the input chain for WAN traffic
**Detection**:
  - Last input chain rule is not `action=drop`
  - No `in-interface=<wan>` `action=drop` rule
  - Rules flow through to implicit accept
**Rationale**: Without an explicit drop rule at the bottom of the input chain, RouterOS accepts all packets by default. Any unblocked service is reachable from WAN. The input chain must explicitly drop traffic from WAN that is not part of an allowed service.
**Remediation**:
  ```
  /ip firewall filter add chain=input action=drop comment="Default drop input"
  # Or more specifically:
  /ip firewall filter add chain=input in-interface=<wan> connection-state=new action=drop
  ```
**Safety Warning**: Adding a default-drop rule on the input chain will break all active management sessions not already permitted. Ensure rules allowing established/related AND your current session are placed BEFORE the drop rule.
**Compliance**: CIS RouterOS v1.x 3.4, NIST SC-7(11), ISO 27001 A.13.1.1, PCI-DSS 1.2

### FW-003: No established/related connection rule in input chain
**Severity**: Critical (CVSS 9.0)
**Category**: Firewall & Network Security
**Path**: `/ip firewall filter` (input chain)
**What to look for**: No rule in input chain accepting established/related connections
**Detection**:
  - No `/ip firewall filter add chain=input connection-state=established,related action=accept`
**Rationale**: Without an established/related rule, return traffic from router-originated connections is dropped or must be explicitly permitted. This can break critical services (NTP, DNS, updates) and forces overly permissive rules.
**Remediation**:
  ```
  /ip firewall filter add chain=input connection-state=established,related action=accept
  /ip firewall filter add chain=input connection-state=invalid action=drop
  ```
**Compliance**: CIS RouterOS v1.x 3.5, NIST SC-7(11), ISO 27001 A.13.1.1, PCI-DSS 1.3.1

### FW-004: No brute-force protection
**Severity**: High (CVSS 8.2)
**Category**: Firewall & Network Security
**Path**: `/ip firewall filter` (input chain)
**What to look for**: No connection-rate limiting rules for management service ports
**Detection**:
  - No `/ip firewall filter` rules with `connection-state=new` and `layer7` or `rate`/`limit` for dst-port 22, 8291, 80, 443
  - No address-list based brute-force blocking as described in AUTH-011
**Rationale**: Without rate limiting, an attacker can make unlimited login attempts. RouterOS connection tracking with address-lists provides an effective method to detect and block brute-force attempts before they succeed.
**Remediation**:
  ```
  # Brute-force protection example:
  /ip firewall filter add chain=input dst-port=22,8291 protocol=tcp connection-state=new \
      src-address-list=ssh-blocklist action=drop
  /ip firewall filter add chain=input dst-port=22,8291 protocol=tcp connection-state=new \
      src-address-list=ssh-stage3 action=add-src-to-list list=ssh-blocklist timeout=1h
  /ip firewall filter add chain=input dst-port=22,8291 protocol=tcp connection-state=new \
      src-address-list=ssh-stage2 action=add-src-to-list list=ssh-stage3 timeout=1m
  /ip firewall filter add chain=input dst-port=22,8291 protocol=tcp connection-state=new \
      src-address-list=ssh-stage1 action=add-src-to-list list=ssh-stage2 timeout=30s
  /ip firewall filter add chain=input dst-port=22,8291 protocol=tcp connection-state=new \
      action=add-src-to-list list=ssh-stage1 timeout=10s
  ```
**Compliance**: CIS RouterOS v1.x 3.6, NIST AC-7, ISO 27001 A.9.4.1, PCI-DSS 8.1.6, PCI-DSS 11.4

### FW-005: No bogon filtering in RAW table
**Severity**: High (CVSS 7.8)
**Category**: Firewall & Network Security
**Path**: `/ip firewall raw`
**What to look for**: No RAW table rules dropping bogon/martian traffic on WAN
**Detection**:
  - No `/ip firewall raw add chain=prerouting in-interface=<wan> src-address=... action=drop` for RFC1918, RFC3927, RFC5735 ranges
  - No `/ip firewall raw` rules at all
**Rationale**: Bogons (RFC1918, RFC6598, RFC3927, multicast, reserved addresses) should never appear as source addresses on WAN interfaces. Without RAW table filtering, these packets consume connection-tracking resources and can bypass firewall rules that evaluate only after connection tracking.
**Remediation**:
  ```
  # IPv4 bogons:
  /ip firewall raw add chain=prerouting in-interface=<wan> src-address=0.0.0.0/8 action=drop
  /ip firewall raw add chain=prerouting in-interface=<wan> src-address=10.0.0.0/8 action=drop
  /ip firewall raw add chain=prerouting in-interface=<wan> src-address=100.64.0.0/10 action=drop
  /ip firewall raw add chain=prerouting in-interface=<wan> src-address=127.0.0.0/8 action=drop
  /ip firewall raw add chain=prerouting in-interface=<wan> src-address=169.254.0.0/16 action=drop
  /ip firewall raw add chain=prerouting in-interface=<wan> src-address=172.16.0.0/12 action=drop
  /ip firewall raw add chain=prerouting in-interface=<wan> src-address=192.0.2.0/24 action=drop
  /ip firewall raw add chain=prerouting in-interface=<wan> src-address=192.168.0.0/16 action=drop
  /ip firewall raw add chain=prerouting in-interface=<wan> src-address=198.18.0.0/15 action=drop
  /ip firewall raw add chain=prerouting in-interface=<wan> src-address=198.51.100.0/24 action=drop
  /ip firewall raw add chain=prerouting in-interface=<wan> src-address=203.0.113.0/24 action=drop
  /ip firewall raw add chain=prerouting in-interface=<wan> src-address=224.0.0.0/4 action=drop
  /ip firewall raw add chain=prerouting in-interface=<wan> src-address=233.252.0.0/24 action=drop
  /ip firewall raw add chain=prerouting in-interface=<wan> src-address=240.0.0.0/4 action=drop
  /ip firewall raw add chain=prerouting in-interface=<wan> dst-address=255.255.255.255 action=drop

  # IPv6 bogons (if IPv6 enabled):
  /ipv6 firewall raw add chain=prerouting in-interface=<wan> src-address=::/8 action=drop
  /ipv6 firewall raw add chain=prerouting in-interface=<wan> src-address=2001:db8::/32 action=drop
  /ipv6 firewall raw add chain=prerouting in-interface=<wan> src-address=fe80::/10 action=drop
  ```
**Compliance**: NIST SC-7(5), ISO 27001 A.13.1.3, PCI-DSS 1.3.1

### FW-006: IPv6 firewall not configured
**Severity**: High (CVSS 8.2)
**Category**: Firewall & Network Security
**Path**: `/ipv6 firewall filter`
**What to look for**: No IPv6 firewall filter rules
**Detection**:
  - `/ipv6 firewall filter` not present in export
  - Empty `/ipv6 firewall filter` block
  - `/ipv6 firewall filter` without any deny/drop rules
**Rationale**: Many administrators secure IPv4 and forget IPv6. If IPv6 is enabled (often on by default), the router may be fully exposed over IPv6 even with a robust IPv4 firewall. IPv6 firewall rules must mirror IPv4 security policy.
**Remediation**:
  ```
  /ipv6 firewall filter add chain=input connection-state=established,related action=accept
  /ipv6 firewall filter add chain=input connection-state=invalid action=drop
  /ipv6 firewall filter add chain=input in-interface=<lan> action=accept
  /ipv6 firewall filter add chain=input action=drop
  /ipv6 firewall filter add chain=forward connection-state=established,related action=accept
  /ipv6 firewall filter add chain=forward connection-state=invalid action=drop
  /ipv6 firewall filter add chain=forward action=drop
  ```
**Compliance**: CIS RouterOS v1.x 3.7, NIST SC-7(11), ISO 27001 A.13.1.1, PCI-DSS 1.2.1

### FW-007: FastTrack not configured
**Severity**: Medium (CVSS 5.0)
**Category**: Firewall & Network Security
**Path**: `/ip firewall filter` (forward chain)
**What to look for**: No FastTrack rule in the forward chain
**Detection**:
  - No `/ip firewall filter add chain=forward action=fasttrack-connection connection-state=established,related`
**Rationale**: FastTrack offloads established connections to hardware, significantly improving throughput and reducing CPU load. Without it, all traffic is processed by the CPU slow path. This is particularly impactful on hAP ac² and other lower-end devices.
**Remediation**:
  ```
  /ip firewall filter add chain=forward action=fasttrack-connection connection-state=established,related
  ```
**Compliance**: N/A (performance hardening)
**Note**: FastTrack works correctly with NAT (masquerade, src-nat, dst-nat). NAT translation state is established before FastTrack offloads connections. However, FastTrack DOES bypass queue trees, simple queues, connection marking, packet marking, and layer7 inspection. If you use QoS/queuing or mangle rules on the forward chain, do NOT enable FastTrack for those connections.

**Safety Warning**: Enabling FastTrack on a config that relies on queue trees, per-connection queuing, or mangle marks will silently break those features. Verify no dependency on these before adding the FastTrack rule.

### FW-008: Port knocking not configured for WAN services
**Severity**: Medium (CVSS 5.9)
**Category**: Firewall & Network Security
**Path**: `/ip firewall filter` (input chain)
**What to look for**: No port-knocking rules for WAN-accessible management services
**Detection**:
  - Management services (SSH, WinBox) accessible from WAN without port knocking
  - No address-list rules implementing port-knocking sequence before allowing access
**Rationale**: Port knocking hides management services behind a required sequence of connection attempts. Without it, services exposed on WAN are continuously probed by automated scanners. Port knocking provides defense in depth but should not be the sole access control.
**Remediation**:
  ```
  /ip firewall filter add chain=input protocol=tcp dst-port=12345 in-interface=<wan> \
      action=add-src-to-list list=knock1 timeout=10s
  /ip firewall filter add chain=input protocol=tcp dst-port=23456 in-interface=<wan> \
      src-address-list=knock1 action=add-src-to-list list=knock2 timeout=10s
  /ip firewall filter add chain=input protocol=tcp dst-port=34567 in-interface=<wan> \
      src-address-list=knock2 action=add-src-to-list list=ssh_allowed timeout=1h
  /ip firewall filter add chain=input protocol=tcp dst-port=22 in-interface=<wan> \
      src-address-list=ssh_allowed action=accept
  ```
**Compliance**: NIST AC-3, ISO 27001 A.13.1.1

### FW-009: WAN-side management access unrestricted
**Severity**: Critical (CVSS 9.4)
**Category**: Firewall & Network Security
**Path**: `/ip firewall filter` (input chain)
**What to look for**: Management services (SSH, WinBox, WebFig) accessible directly from WAN without source restriction
**Detection**:
  - `/ip firewall filter add chain=input protocol=tcp dst-port=22 action=accept` without `src-address=` restriction
  - `/ip firewall filter add chain=input protocol=tcp dst-port=8291 action=accept` without `in-interface=<mgmt>` restriction
  - Management ports allowed from WAN interface
**Rationale**: Direct WAN access to management ports exposes the router's control plane to the entire internet. This is the most common attack vector for router compromise. Management access must be restricted to trusted IPs, VPN, or at minimum require port knocking.
**Remediation**:
  ```
  /ip firewall filter remove [find dst-port=22 in-interface=<wan>]
  /ip firewall filter add chain=input protocol=tcp dst-port=22 src-address=<mgmt-subnet> action=accept
  # Or block WAN entirely:
  /ip firewall filter add chain=input in-interface=<wan> connection-state=new action=drop
  ```
**Compliance**: CIS RouterOS v1.x 3.8, NIST AC-6, ISO 27001 A.13.1.1, PCI-DSS 1.3.2

### FW-010: Forward chain rules too permissive
**Severity**: High (CVSS 8.0)
**Category**: Firewall & Network Security
**Path**: `/ip firewall filter` (forward chain)
**What to look for**: No restrictions on inter-VLAN or inter-subnet routing
**Detection**:
  - `/ip firewall filter add chain=forward action=accept` without restrictions
  - No `/ip firewall filter` rules limiting traffic between VLANs/subnets
  - `/ip firewall filter add chain=forward action=drop` not present or not enforced
**Rationale**: Without forward chain restrictions, all permitted traffic between subnets flows freely. There is no segmentation enforcement — an infected workstation on one VLAN can probe all other VLANs without hindrance.
**Remediation**:
  ```
  /ip firewall filter add chain=forward connection-state=established,related action=accept
  /ip firewall filter add chain=forward connection-state=invalid action=drop
  /ip firewall filter add chain=forward in-interface=<dmz> out-interface=<lan> action=drop
  /ip firewall filter add chain=forward in-interface=<lan> out-interface=<dmz> action=accept
  /ip firewall filter add chain=forward action=drop
  ```
**Compliance**: CIS RouterOS v1.x 3.9, NIST SC-7(21), ISO 27001 A.13.1.3, PCI-DSS 1.2.1

### FW-011: NAT rules with too broad source
**Severity**: Medium (CVSS 5.5)
**Category**: Firewall & Network Security
**Path**: `/ip firewall nat`
**What to look for**: Masquerade/SrcNAT rules matching 0.0.0.0/0 or overly broad source ranges
**Detection**:
  - `/ip firewall nat add chain=srcnat action=masquerade src-address=0.0.0.0/0` or `src-address=::/0`
  - `/ip firewall nat add chain=srcnat action=masquerade` without `src-address=`
  - `/ip firewall nat add chain=srcnat action=src-nat to-address=<ext-ip>` without `src-address=`
**Rationale**: NAT rules that match all source addresses will translate traffic from any source, including traffic that arrives on WAN. This can allow source-spoofed traffic or unintended forwarding. Always restrict srcNAT to specific LAN subnets.
**Remediation**:
  ```
  /ip firewall nat add chain=srcnat action=masquerade src-address=<lan-subnet> out-interface=<wan>
  ```
**Compliance**: NIST SC-7(5), ISO 27001 A.13.1.1, PCI-DSS 1.3.5

### FW-012: No ICMP rate limiting
**Severity**: Medium (CVSS 5.3)
**Category**: Firewall & Network Security
**Path**: `/ip firewall filter` (input chain)
**What to look for**: No rate limiting on ICMP traffic to the router
**Detection**:
  - No `/ip firewall filter` rule with `protocol=icmp` and `limit` or `connection-rate` for input chain
  - Unrestricted ICMP Echo (ping) allowed without rate limit
**Rationale**: Without ICMP rate limiting, the router CPU can be overwhelmed by ICMP floods. This is a denial-of-service vector that affects the control plane. Reasonable rate limiting preserves availability.
**Remediation**:
  ```
  # Option A: Rate-limit ICMP echo, drop other ICMP types
  /ip firewall filter add chain=input protocol=icmp icmp-options=8:0 \
      connection-state=new limit=10,5 action=accept comment="Rate-limit ICMP echo"
  /ip firewall filter add chain=input protocol=icmp action=drop \
      comment="Drop excess ICMP"

  # Option B: Accept all ICMP with single rate limit
  /ip firewall filter add chain=input protocol=icmp \
      connection-state=new limit=10,5 action=accept comment="Rate-limit ICMP"
  /ip firewall filter add chain=input protocol=icmp action=drop \
      comment="Drop excess ICMP"
  ```
**Compliance**: NIST SC-5, ISO 27001 A.17.2.1, PCI-DSS 2.2.2

### FW-013: DSTNAT to internal services without restriction
**Severity**: High (CVSS 7.5)
**Category**: Firewall & Network Security
**Path**: `/ip firewall nat` (dstnat chain)
**What to look for**: DSTNAT rules forwarding traffic from WAN to internal services without source-address restriction
**Detection**:
  - `/ip firewall nat add chain=dstnat in-interface=<wan> action=dst-nat to-addresses=<internal-ip>` without `src-address=`
  - `/ip firewall nat add chain=dstnat in-interface=<wan> protocol=tcp dst-port=... action=dst-nat` without `src-address=`
**Rationale**: DSTNAT without source restrictions exposes internal services to the entire internet. Even if the firewall forward chain has restrictions, the NAT rule itself should limit which external sources can reach internal services.
**Remediation**:
  ```
  /ip firewall nat add chain=dstnat in-interface=<wan> protocol=tcp dst-port=<port> \
      src-address=<allowed-source> action=dst-nat to-addresses=<internal-ip>
  /ip firewall filter add chain=forward dst-address=<internal-ip> src-address=<allowed-source> action=accept
  ```
**Compliance**: NIST SC-7(3), ISO 27001 A.13.1.1, PCI-DSS 1.3.3

### FW-014: Broadcast/multicast not blocked in forward chain
**Severity**: Medium (CVSS 4.0)
**Category**: Firewall & Network Security
**Path**: `/ip firewall filter` (forward chain)
**What to look for**: No rules blocking broadcast or multicast forwarding between networks
**Detection**:
  - No `/ip firewall filter add chain=forward ... protocol=udp dst-port=67-68 ... action=drop` for cross-subnet DHCP
  - No `/ip firewall filter add chain=forward ... dst-address=224.0.0.0/4 ... action=drop`
  - No `/ip firewall filter add chain=forward ... dst-address=255.255.255.255 action=drop`
**Rationale**: Broadcast and multicast traffic should not cross network segments unless explicitly needed (e.g., multicast streaming). Forwarding broadcasts between VLANs causes unnecessary traffic, information leaks, and potential DoS amplification.
**Remediation**:
  ```
  /ip firewall filter add chain=forward dst-address=224.0.0.0/4 action=drop
  /ip firewall filter add chain=forward dst-address=255.255.255.255 action=drop
  ```
**Compliance**: NIST SC-7, ISO 27001 A.13.1.1, PCI-DSS 1.2.1

### FW-015: RAW table not configured at all
**Severity**: Medium (CVSS 6.1)
**Category**: Firewall & Network Security
**Path**: `/ip firewall raw`
**What to look for**: No RAW table rules configured
**Detection**:
  - `/ip firewall raw` not present or empty
**Rationale**: The RAW table processes traffic before connection tracking. It allows dropping unwanted traffic before it consumes connection tracking resources. This is essential for high-traffic environments and for filtering bogon/martian addresses without filling the connection table.
**Remediation**:
  ```
  /ip firewall raw add chain=prerouting in-interface=<wan> protocol=tcp dst-port=22 \
      connection-state=new action=accept
  # Add bogon filtering rules (see FW-005)
  ```
**Compliance**: NIST SC-7, ISO 27001 A.13.1.1, PCI-DSS 1.3.1

### FW-016: Connection tracking limits not configured
**Severity**: High (CVSS 7.8)
**Category**: Firewall & Network Security
**Path**: `/ip firewall connection tracking`
**What to look for**: No max-entries limit or TCP syncookie configured
**Detection**:
  - `/ip firewall connection tracking set` without `max-entries=...`
  - `/ip firewall connection tracking set tcp-syncookie=no` or absent
  - Default `max-entries` (e.g., 32768 or 65536) not tuned for device memory
**Rationale**: Connection tracking uses system memory. On hAP ac² and similar devices (128MB RAM), the default max-entries can exhaust available memory under DoS. Setting appropriate limits and enabling syncookies prevents resource exhaustion.
**Remediation**:
  ```
  /ip firewall connection tracking set tcp-syncookie=yes max-entries=16384
  ```
**Compliance**: NIST SC-5, ISO 27001 A.17.2.1, PCI-DSS 2.2.2
**Note**: Adjust `max-entries` based on device RAM: 16384 for 128MB devices, 32768 for 256MB, 65536+ for >=512MB.

### FW-017: BGP TTL security not configured
**Severity**: Medium (CVSS 5.3)
**Category**: Firewall & Network Security
**Path**: `/routing bgp connection`
**What to look for**: BGP TTL security (GTSM) not configured — BGP sessions vulnerable to off-path attacks
**Detection**:
  - No `/routing bgp connection add` with `ttl=1` or `ttl=255` parameter
**Rationale**: BGP TTL security (RFC 5082, GTSM) prevents off-path attacks by setting TTL=1 for directly connected eBGP peers. Attackers further than one hop away cannot forge BGP packets because their TTL will be decremented to 0 before reaching the router.
**Remediation**:
  ```
  /routing bgp connection set [find remote.address=<peer>] ttl=1
  ```
**Compliance**: NIST SC-7, ISO 27001 A.8.20, PCI-DSS 1.2

---

## SYS — System Hardening (10 checks)

### SYS-001: RouterOS version not found
**Severity**: High (CVSS 8.0)
**Category**: System Hardening
**Path**: `/system resource` (export header)
**What to look for**: Export header missing RouterOS version information
**Detection**:
  - Export header absent: no comment with `RouterOS` or `RouterBoard` marker
  - `/system resource` not in export
  - Version string missing, truncated, or obfuscated
**Rationale**: Without version information, vulnerability assessment is impossible. The auditor cannot determine if known CVEs apply. The export must include `verbose=yes` to capture version details. Missing version may indicate a sanitized or manipulated export.
**Remediation**: Re-export with verbose mode:
  ```
  /export verbose file=audit-export
  ```
**Compliance**: NIST RA-5, ISO 27001 A.12.6.1, PCI-DSS 6.2

### SYS-002: System identity not set or set to default
**Severity**: Low (CVSS 2.1)
**Category**: System Hardening
**Path**: `/system identity`
**What to look for**: Router identity unchanged from default
**Detection**:
  - `/system identity set name=Router` or `name=MikroTik`
  - `/system identity set name=""`
  - Generic, non-descriptive identity
**Rationale**: A default identity provides no context in logs and makes fleet management difficult. While not a security vulnerability, setting a descriptive identity (location, role, asset tag) aids in audit and incident response.
**Remediation**:
  ```
  /system identity set name=<location-role-tag>
  ```
**Compliance**: N/A (operational hardening)

### SYS-003: NTP not configured
**Severity**: High (CVSS 7.5)
**Category**: System Hardening
**Path**: `/system ntp client`
**What to look for**: NTP client not configured or disabled
**Detection**:
  - `/system ntp client set enabled=no` or absent
  - No `/system ntp client set server=...` configured
  - `/system clock` showing incorrect date/time (relative to export timestamp)
**Rationale**: Accurate time is essential for log correlation, certificate validation, and incident forensics. Without NTP, logs have unreliable timestamps and services that depend on time synchronization (VPN, AD auth, CAPsMAN) may fail.
**Remediation**:
  ```
  /system ntp client set enabled=yes server=0.pool.ntp.org,1.pool.ntp.org
  /system ntp client set server-dns-max-udp-packet-size=512
  ```
**Compliance**: CIS RouterOS v1.x 6.1, NIST AU-8, ISO 27001 A.12.4.3, PCI-DSS 10.4

### SYS-004: Local logging not configured
**Severity**: Medium (CVSS 5.3)
**Category**: System Hardening
**Path**: `/system logging`
**What to look for**: No logging rules for critical, error, or warning events
**Detection**:
  - `/system logging` not present in export
  - No `/system logging add topics=critical action=memory` or similar
  - Only default logging entries present
**Rationale**: Without adequate logging, security events (failed logins, config changes, interface flaps) are not recorded. This prevents incident detection and forensic analysis.
**Remediation**:
  ```
  /system logging add topics=critical action=memory
  /system logging add topics=error action=memory
  /system logging add topics=warning action=memory
  /system logging add topics=info action=memory
  /system logging set [find topics~"critical" action=echo] action=memory
  ```
**Compliance**: CIS RouterOS v1.x 6.2, NIST AU-3, ISO 27001 A.12.4.1, PCI-DSS 10.2

### SYS-005: Remote syslog not configured
**Severity**: Medium (CVSS 5.5)
**Category**: System Hardening
**Path**: `/system logging action`
**What to look for**: Remote syslog server not configured
**Detection**:
  - `/system logging action set ... disabled=no` without `remote=...`
  - No `/system logging action add name=remote target=remote remote=<syslog-server>`
**Rationale**: Local logs are lost if the router fails or is compromised. Remote syslog provides centralized, immutable log storage that survives device compromise. It is essential for SIEM integration and forensic analysis.
**Remediation**:
  ```
  /system logging action add name=remote target=remote remote=<syslog-server> remote-port=514
  /system logging add topics=critical action=remote
  /system logging add topics=error,action,info action=remote
  ```
**Compliance**: CIS RouterOS v1.x 6.3, NIST AU-4, ISO 27001 A.12.4.1, PCI-DSS 10.5.3

### SYS-006: Auto-update check not configured
**Severity**: Medium (CVSS 4.8)
**Category**: System Hardening
**Path**: `/system package update`
**What to look for**: No automatic update channel configured
**Detection**:
  - `/system package update set channel=stable` without checking for updates
  - No scheduler for `/system package update check-installed`
**Rationale**: Unpatched RouterOS versions are a primary attack vector. Without update checks, critical security patches may be missed. While auto-update is not recommended for production, scheduled update checks should be configured.
**Remediation**:
  ```
  /system package update set channel=stable
  /system scheduler add name=check-updates interval=1d on-event="/system package update check-installed" start-time=03:00
  ```
**Compliance**: NIST SI-2, ISO 27001 A.12.6.1, PCI-DSS 6.2

### SYS-007: Unsigned packages allowed
**Severity**: High (CVSS 7.8)
**Category**: System Hardening
**Path**: `/system package update`
**What to look for**: RouterOS configured to allow unsigned packages
**Detection**:
  - `/system package update set allow-signed=no`
  - Absent `/system package update set allow-signed=yes`
**Rationale**: Unsigned packages bypass integrity verification. An attacker who compromises the update channel or MITMs the connection can install malicious packages with full system access.
**Remediation**:
  ```
  /system package update set allow-signed=yes
  ```
**Compliance**: NIST SI-7, ISO 27001 A.12.5.1, PCI-DSS 6.4.3

### SYS-008: Support output not secured
**Severity**: Low (CVSS 3.1)
**Category**: System Hardening
**Path**: `/tool bandwidth-test`, `/tool sniffer`
**What to look for**: Bandwidth test or sniffer tools without restrictions
**Detection**:
  - `/tool bandwidth-test set enabled=yes` without interface restrictions
  - `/tool sniffer set disabled=no` without interface or address restrictions
  - `/tool sniffer` available to users without proper policy restrictions
**Rationale**: The sniffer and bandwidth test are powerful diagnostic tools. Unrestricted, they allow traffic capture and CPU exhaustion. The sniffer should be restricted by policy (not granted to low-privilege users) and the bandwidth test should be disabled or IP-restricted.
**Remediation**:
  ```
  /tool bandwidth-test set enabled=no
  # Or restrict:
  /tool bandwidth-test set enabled=yes allocated-cpu=10
  # Sniffer access is controlled via user group policy — remove 'sniff' from non-admin groups
  ```
**Compliance**: NIST SC-7, ISO 27001 A.13.1.1

### SYS-009: System backup not configured
**Severity**: Medium (CVSS 5.5)
**Category**: System Hardening
**Path**: `/system backup`, `/system scheduler`
**What to look for**: No scheduled backup configuration
**Detection**:
  - No `/system backup save name=...` in scheduler scripts
  - No `/system scheduler` entry for backup
  - No `/file copy` or `/tool fetch` for backup export
**Rationale**: Without backups, a misconfiguration or hardware failure requires full reconfiguration. While not a direct security finding, backup is essential for recovery from ransomware, failed updates, and hardware failures.
**Remediation**:
  ```
  /system scheduler add name=backup interval=1d on-event="/system backup save name=(\$[/system clock get date])" start-time=03:30
  /system scheduler add name=export interval=1d on-event="/export file=backup_(\$[/system identity get name])" start-time=03:35
  ```
**Compliance**: NIST CP-9, ISO 27001 A.12.3.1, PCI-DSS 10.7

### SYS-010: System watchdog not configured
**Severity**: Medium (CVSS 4.0)
**Category**: System Hardening
**Path**: `/system watchdog`
**What to look for**: No watchdog timer set to reboot router on lockup
**Detection**:
  - `/system watchdog set` not present in export
  - `/system watchdog set watchdog-timer=none`
  - `/system watchdog set watchdog-timer=no` (RouterOS v6 syntax)
**Rationale**: A watchdog timer automatically reboots the router if it becomes unresponsive. This limits downtime from software hangs, memory exhaustion, or certain types of DoS attacks that freeze the control plane.
**Remediation**:
  ```
  /system watchdog set watchdog-timer=30s
  ```
**Compliance**: NIST CP-10, ISO 27001 A.17.1.2

---

## NET — Network Configuration (9 checks)

### NET-001: Bridge VLAN filtering not enabled when VLANs are present
**Severity**: High (CVSS 7.8)
**Category**: Network Configuration
**Path**: `/interface bridge`
**What to look for**: VLANs defined but bridge VLAN filtering disabled
**Detection**:
  - `/interface bridge set ... vlan-filtering=no` while `/interface vlan` entries exist
  - Bridge ports without `pvid` and `bridge-vlan-tagged`/`bridge-vlan-untagged` configured
  - `/interface bridge vlan` not present despite VLAN interfaces
**Rationale**: Without VLAN filtering on the bridge, VLAN traffic is not segregated at layer 2. All VLANs can communicate across the bridge, defeating the purpose of VLAN segmentation. This is especially critical on hAP ac² where VLAN filtering affects HW offload behavior (see NET-006).
**Remediation**:
  ```
  /interface bridge set [find] vlan-filtering=yes
  /interface bridge vlan add bridge=<bridge> vlan-ids=<vlan-id> tagged=<uplink-port> untagged=<access-ports>
  /interface bridge port set [find] pvid=<default-vlan>
  ```
**Compliance**: NIST AC-4, ISO 27001 A.13.1.3, PCI-DSS 1.2.1

### NET-002: DHCP server without secure options
**Severity**: Medium (CVSS 5.4)
**Category**: Network Configuration
**Path**: `/ip dhcp-server`
**What to look for**: DHCP server without lease time limits or authoritative configuration
**Detection**:
  - `/ip dhcp-server set ... lease-time=3d` or longer (excessive)
  - `/ip dhcp-server set ... authoritative=no` or absent
  - `/ip dhcp-server set ... add-arp=no` while desired
  - No `bootp-lease-time` limit
**Rationale**: Without secure DHCP options, an attacker can exhaust the lease pool (long leases) or inject rogue DHCP responses (non-authoritative). Setting authoritative mode and reasonable lease times limits the blast radius of DHCP attacks.
**Remediation**:
  ```
  /ip dhcp-server set [find] authoritative=yes lease-time=1h add-arp=yes
  /ip dhcp-server network set [find] bootp-lease-time=30m
  ```
**Compliance**: NIST SC-7, ISO 27001 A.13.1.1, PCI-DSS 1.3.3

### NET-003: DHCP lease storage enabled on flash-constrained devices
**Severity**: Medium (CVSS 4.9)
**Category**: Network Configuration
**Path**: `/ip dhcp-server config`
**What to look for**: DHCP leases stored to disk on devices with limited flash
**Detection**:
  - `/ip dhcp-server config set store-leases-on-disk=yes`
  - No `store-leases-on-disk=no` override
**Rationale**: On devices with limited flash storage (hAP ac² — 16MB), storing DHCP leases to disk accelerates flash wear and can fill available storage. With many leases, the lease file can exhaust available flash, causing instability or boot failure.
**Remediation**:
  ```
  /ip dhcp-server config set store-leases-on-disk=no
  ```
**Compliance**: N/A (operational hardening)
**Note**: hAP ac² and RB750 series should always disable on-disk lease storage.

**Important (v7)**: The `store-leases-on-disk` parameter is removed in RouterOS v7. DHCP lease storage is managed via database settings (`/ip dhcp-server config set lease-write-interval=...`). For hAP ac² flash-constrained devices, keep lease counts low and use static leases for high-churn clients.

### NET-004: DNS cache poisoning protection not configured
**Severity**: Medium (CVSS 5.3)
**Category**: Network Configuration
**Path**: `/ip dns`
**What to look for**: No DNS cache poisoning mitigation
**Detection**:
  - `/ip dns set` without `query-server-timeout=...` or `max-concurrent-queries=...`
  - `/ip dns set` without `cache-max-ttl=...` restriction
**Rationale**: Without cache TTL limits and query restrictions, DNS cache poisoning attacks have a longer window of effectiveness. Setting a reasonable `cache-max-ttl` limits the time poisoned data remains cached.
**Remediation**:
  ```
  /ip dns set cache-max-ttl=1d query-server-timeout=2s max-concurrent-queries=100
  ```
**Compliance**: NIST SC-20, ISO 27001 A.13.1.1
**Note**: If DoH (DNS-over-HTTPS) is configured with `use-doh=yes`, that provides stronger cache poisoning protection than cache TTL limits alone. DoH encrypts DNS queries and verifies server identity via TLS, preventing on-path cache poisoning. When DoH is active, the severity of this finding may be reduced.

### NET-005: Split horizon / DNS forwarders not configured
**Severity**: Low (CVSS 3.3)
**Category**: Network Configuration
**Path**: `/ip dns`
**What to look for**: DNS servers not explicitly configured
**Detection**:
  - `/ip dns set servers=""` or absent
  - `/ip dns set` without `servers=<dns-ip>` and `allow-remote-requests=no`
**Rationale**: Without explicit DNS servers, the router may use default DNS or fail to resolve names. This affects client connectivity, NTP resolution, and update checks. Explicit DNS server configuration ensures consistent resolution behavior.
**Remediation**:
  ```
  /ip dns set servers=<primary-dns>,<secondary-dns>
  ```
**Compliance**: N/A (operational hardening)

### NET-006: Bridge HW offload misconfiguration
**Severity**: High (CVSS 7.0)
**Category**: Network Configuration
**Path**: `/interface bridge`
**What to look for**: Bridge VLAN filtering enabled with HW offload causing throughput collapse
**Detection**:
  - hAP ac² or similar device: `/interface bridge port set ... hw=yes` on bridge member ports
  - `/interface bridge set ... vlan-filtering=yes` on hAP ac² with all ports in bridge
  - Bridge has `auto-mac=yes` and HW offload ports
**Rationale**: On hAP ac² (IPQ-4018), enabling VLAN filtering on the bridge disables HW offload, forcing all traffic through the CPU. This drops throughput from ~800Mbps to ~100Mbps. The workaround is to use the switch chip VLAN configuration instead, or accept the performance trade-off.
**Remediation**:
  ```
  # Option A: Use switch VLAN instead of bridge VLAN filtering
  /interface ethernet switch vlan ...
  # Option B: Accept performance impact and document explicitly
  /interface bridge set bridge1 vlan-filtering=yes
  /interface bridge port set [find] hw=no
  ```
**Compliance**: N/A (operational constraint)
**Note**: hAP ac² specific. Use switch VLAN configuration to preserve HW offload on this platform.

### NET-007: MTU/fragmentation issues
**Severity**: Medium (CVSS 4.0)
**Category**: Network Configuration
**Path**: `/interface bridge`, `/interface ethernet`
**What to look for**: MTU mismatch between bridge and member ports
**Detection**:
  - `/interface bridge set ... mtu=...` different from member ethernet ports
  - `/interface bridge set ... l2mtu=...` not set
  - `/interface ethernet set ... mtu=1500` while bridge is set to `mtu=1500` (default)
  - PPPoE interface MTU (1492) not accounted for on bridge
**Rationale**: MTU mismatch causes fragmentation or packet drops. With PPPoE (1492 MTU), the bridge MTU should be reduced. Larger-than-default MTU (e.g., 9000 jumbo frames) must be consistent across all bridge members.
**Remediation**:
  ```
  /interface bridge set bridge1 mtu=<correct-mtu> l2mtu=<hardware-limit>
  # For PPPoE:
  /interface bridge set bridge1 mtu=1500
  /ip firewall mangle add chain=forward protocol=tcp tcp-flags=syn action=change-mss new-mss=1452
  ```
**Compliance**: N/A (operational hardening)

### NET-008: VRRP/HA not configured for critical gateways
**Severity**: Medium (CVSS 4.0)
**Category**: Network Configuration
**Path**: `/interface vrrp`
**What to look for**: No VRRP/HA redundancy for critical gateway roles
**Detection**:
  - Only one router in config with no `/interface vrrp` configuration
  - `/interface vrrp` not present despite `default gateway` set on the router
  - No `gateway-status` monitoring or failover configuration
**Rationale**: A single router is a single point of failure. For networks requiring high availability, VRRP provides automatic failover. While this is an operational concern, the security impact is denial-of-service through single-device failure.
**Remediation**:
  ```
  /interface vrrp add name=vrrp-wan interface=<wan> vrid=50 priority=255 address=<virtual-gw>
  /ip address add address=<virtual-gw>/32 interface=vrrp-wan
  ```
**Compliance**: NIST CP-9, ISO 27001 A.17.1.2

### NET-009: IGMP snooping not configured on bridge with multicast
**Severity**: Medium (CVSS 4.5)
**Category**: Network Configuration
**Path**: `/interface bridge`
**What to look for**: IGMP snooping disabled on bridge with multicast traffic
**Detection**:
  - `/interface bridge set ... igmp-snooping=no` or absent
  - `/interface bridge` has `igmp-snooping=no` but multicast sources or receivers exist (IPTV, streaming)
**Rationale**: Without IGMP snooping, multicast traffic is flooded to all bridge ports. This wastes bandwidth on ports that have no multicast listeners and can cause unnecessary load on the CPU.
**Remediation**:
  ```
  /interface bridge set bridge1 igmp-snooping=yes igmp-version=3
  ```
**Compliance**: N/A (operational hardening)

---

## ROUTE — Routing Security (9 checks)

### ROUTE-001: BGP without MD5 authentication
**Severity**: High (CVSS 8.2)
**Category**: Routing Security
**Path**: `/routing bgp connection`
**What to look for**: BGP peerings without TCP-MD5 password
**Detection**:
  - `/routing bgp connection add ... remote.address=...` without `tcp-md5-key=`
  - `/routing bgp connection set ...` without `tcp-md5-key`
  - `/routing bgp peer` entries without `ttl=1` or password (RouterOS v7 syntax)
**Rationale**: BGP without MD5 authentication allows anyone on the path to inject BGP updates, hijacking prefixes and redirecting traffic. TCP-MD5 protects the TCP connection between peers.
**Remediation**:
  ```
  /routing bgp connection set [find] tcp-md5-key=<strong-key>
  ```
**Compliance**: NIST SC-20, ISO 27001 A.13.1.1, PCI-DSS 1.3.2

### ROUTE-002: OSPF without authentication
**Severity**: High (CVSS 7.8)
**Category**: Routing Security
**Path**: `/routing ospf interface-template`
**What to look for**: OSPF interfaces without authentication configured
**Detection**:
  - `/routing ospf interface-template add ...` without `authentication=md5` or `authentication=sha256`
  - `/routing ospf interface-template set ... authentication=none`
  - No `auth-key` or `auth-id` on OSPF template interfaces
**Rationale**: OSPF without authentication allows attackers to inject false LSAs, corrupting the routing table. All OSPF neighbors should authenticate their adjacency exchanges.
**Remediation**:
  ```
  # Preferred: SHA256 (v7.3+):
  /routing ospf interface-template set [find] authentication=sha256 auth-id=1 auth-key=<strong-key>

  # Fallback for v6 / mixed environments:
  /routing ospf interface-template set [find] authentication=md5 auth-id=1 auth-key=<strong-key>
  ```
**Compliance**: NIST SC-20, ISO 27001 A.13.1.1, PCI-DSS 1.3.2

### ROUTE-003: Routing filters not applied
**Severity**: High (CVSS 7.8)
**Category**: Routing Security
**Path**: `/routing bgp connection`, `/routing ospf` (filter chain)
**What to look for**: BGP or OSPF without input/output route filters
**Detection**:
  - `/routing bgp connection` without `input.filter=...` or `output.filter=...`
  - `/routing bgp connection` using default `accept` chains
  - `/routing filter` not defined for routing protocols
**Rationale**: Without route filters, a BGP peer can advertise any prefix, including hijacked or private ranges. Input filters restrict which prefixes are accepted; output filters control what is advertised. This is essential for route leak prevention.
**Remediation**:
  ```
  /routing filter add chain=bgp-in prefix-length=8-24 action=accept
  /routing filter add chain=bgp-in action=discard
  /routing bgp connection set [find] input.filter=bgp-in output.filter=bgp-out
  ```
**Compliance**: NIST SC-20, ISO 27001 A.13.1.1, PCI-DSS 1.3.2

### ROUTE-004: BGP TTL security not configured
**Severity**: Medium (CVSS 6.4)
**Category**: Routing Security
**Path**: `/routing bgp connection`
**What to look for**: BGP sessions without TTL hardening
**Detection**:
  - `/routing bgp connection set ... ttl=...` not matching expected hop count
  - `/routing bgp connection add ...` without `ttl=1` (for directly connected peers)
**Rationale**: TTL security (GTSM/RFC 5082) prevents off-path BGP injection attacks. Setting ttl=1 for directly-connected peers ensures that spoofed BGP packets from non-adjacent networks are discarded.
**Remediation**:
  ```
  /routing bgp connection set [find] ttl=1
  # For multi-hop peers, ttl=255 allows any but ensures TTL field is validated
  ```
**Compliance**: NIST SC-20, ISO 27001 A.13.1.1

### ROUTE-005: BGP prefix limits not configured
**Severity**: High (CVSS 7.1)
**Category**: Routing Security
**Path**: `/routing bgp connection`
**What to look for**: No maximum prefix limit on BGP sessions
**Detection**:
  - `/routing bgp connection` without `max-prefix-limit=...`
  - `/routing bgp connection set ... max-prefix-limit=0` or absent
**Rationale**: Without prefix limits, a misconfigured or malicious peer can exhaust the router's routing table (FIB). This causes memory exhaustion and routing failure. Set a reasonable max-prefix per peer based on expected routes.
**Remediation**:
  ```
  /routing bgp connection set [find] max-prefix-limit=500000 restart-time=30m
  ```
**Compliance**: NIST SC-20, ISO 27001 A.13.1.1

### ROUTE-006: Dynamic routing on WAN-facing interfaces
**Severity**: High (CVSS 8.0)
**Category**: Routing Security
**Path**: `/routing ospf interface-template`, `/routing bgp connection`
**What to look for**: OSPF/BGP adjacencies formed on WAN-facing interfaces
**Detection**:
  - `/routing ospf interface-template add interface=<wan>` or `=all`
  - `/routing bgp connection` with `remote.address` on WAN network
  - OSPF configured on all interfaces without restricting to specific ones
**Rationale**: Dynamic routing protocols on WAN interfaces expose the routing system to external attackers. If BGP/OSPF is required on WAN, it must be authenticated and encrypted. In most cases, dynamic routing should be confined to internal network segments.
**Remediation**:
  ```
  /routing ospf interface-template remove [find interface=<wan>]
  # Or restrict OSPF to specific internal interfaces:
  /routing ospf interface-template set [find] interface=<internal-net>
  ```
**Compliance**: NIST SC-7, ISO 27001 A.13.1.3

### ROUTE-007: Default route without backup/check
**Severity**: Medium (CVSS 5.5)
**Category**: Routing Security
**Path**: `/ip route`
**What to look for**: Single default gateway without connectivity check
**Detection**:
  - `/ip route add dst-address=0.0.0.0/0 gateway=<wan-gw>` without `check-gateway=ping`
  - No backup default route with higher distance
  - No `routing-mark` with failover
**Rationale**: A single default route with no health check means the router continues to route traffic through a dead gateway. `check-gateway=ping` monitors gateway reachability and removes the route on failure. For critical networks, a backup cellular or secondary ISP route should exist.
**Remediation**:
  ```
  /ip route add dst-address=0.0.0.0/0 gateway=<primary-gw> check-gateway=ping distance=1
  /ip route add dst-address=0.0.0.0/0 gateway=<backup-gw> check-gateway=ping distance=2

  # For sub-second failover, configure BFD (v7.14+):
  /routing bfd interface add interface=<wan> min-tx=100 min-rx=100 multiplier=3
  /ip route add dst-address=0.0.0.0/0 gateway=<primary-gw> bfd=yes distance=1
  ```
**Compliance**: NIST CP-9, ISO 27001 A.17.1.2

### ROUTE-008: Loopback interface not configured for router ID
**Severity**: Low (CVSS 2.5)
**Category**: Routing Security
**Path**: `/interface bridge` (loopback-like), routing protocol settings
**What to look for**: No dedicated loopback interface for router ID
**Detection**:
  - `/routing ospf instance` or `/routing bgp connection` using a physical interface IP as router ID
  - No `/interface bridge add name=loopback` or `/interface vlan add name=loopback`
  - Router ID derived from an unstable interface IP
**Rationale**: A loopback interface provides a stable router ID that does not change when physical interfaces go up or down. This prevents BGP/OSPF session resets during interface flaps. It also simplifies ACL and monitoring configuration.
**Remediation**:
  ```
  /interface bridge add name=loopback
  /ip address add address=<loopback-ip>/32 interface=loopback
  /routing ospf instance set [find] router-id=<loopback-ip>
  ```
**Compliance**: N/A (operational hardening)

### ROUTE-009: ECMP load balancing without connection marking
**Severity**: Medium (CVSS 4.0)
**Category**: Routing Security
**Path**: `/ip route`, `/ip firewall mangle`
**What to look for**: Equal-cost multipath (ECMP) routes without per-connection routing
**Detection**:
  - `/ip route add ... gateway=a,b,c` with multiple equal-cost gateways
  - No `/ip firewall mangle` rules with `connection-mark` and `routing-mark` for ECMP
  - `ip route set ... routing-mark=...` not using per-connection marking
**Rationale**: Basic ECMP distributes packets per flow without state awareness. For proper session persistence and load balancing, use connection marking with per-connection routing. Otherwise, asymmetric routing can cause stateful firewall drops and NAT issues.
**Remediation**:
  ```
  /ip firewall mangle add chain=prerouting connection-state=new dst-address-type=!local \
      in-interface=<wan> nth=1,1 action=mark-connection new-connection-mark=wan1
  /ip firewall mangle add chain=prerouting connection-state=new dst-address-type=!local \
      in-interface=<wan> nth=2,1 action=mark-connection new-connection-mark=wan2
  /ip route add dst-address=0.0.0.0/0 gateway=<wan1> routing-mark=wan1
  /ip route add dst-address=0.0.0.0/0 gateway=<wan2> routing-mark=wan2
  ```
**Compliance**: N/A (operational hardening)

---

## WIFI — WiFi Security (13 checks)

### WIFI-001: Insecure encryption (WEP/TKIP) configured
**Severity**: Critical (CVSS 9.2)
**Category**: WiFi Security
**Path**: `/interface wireless security-profile`, `/interface wifi security`
**What to look for**: WiFi security profile using WEP or TKIP encryption
**Detection**:
  - `/interface wireless security-profile set ... authentication-types=wep-xxx` or `=tkip`
  - RouterOS v7: `/interface wifi security set ... authentication-types=...` with `wep` or `tkip`
  - `/interface wireless security-profile set ... wpa-pre-shared-key=...` with only wpa1/tkip
**Rationale**: WEP and TKIP are fundamentally broken. WEP can be cracked in minutes with publicly available tools. TKIP (WPA1) has known MIC vulnerabilities and is deprecated in the 802.11 standard. Only WPA2/WPA3 with CCMP/AES is acceptable.
**Remediation**:
  ```
  /interface wireless security-profile set [find] authentication-types=wpa2-psk mode=dynamic-keys
  # RouterOS v7:
  /interface wifi security set [find] authentication-types=wpa2-psk,wpa3-psk encryption=aes
  ```
**Compliance**: NIST AC-17(2), ISO 27001 A.13.2.1, PCI-DSS 4.1

### WIFI-002: WPS enabled
**Severity**: High (CVSS 7.6)
**Category**: WiFi Security
**Path**: `/interface wireless`, `/interface wifi`
**What to look for**: WiFi Protected Setup enabled
**Detection**:
  - `/interface wireless set ... wps-mode=...` where mode is not `disabled`
  - `/interface wireless set ... wps-mode=push-button` or `=pin`
  - RouterOS v7: `/interface wifi set ... wps=yes`
**Rationale**: WPS PIN mode is vulnerable to brute-force attacks (the PIN is 7 digits, and the checksum reduces effective keyspace). An attacker can recover the WPA2 PSK by brute-forcing the WPS PIN in hours using tools like Reaver or PixieWPS.
**Remediation**:
  ```
  /interface wireless set [find] wps-mode=disabled
  # RouterOS v7:
  /interface wifi set [find] wps=disabled
  ```
**Compliance**: NIST AC-17(2), ISO 27001 A.13.2.1, PCI-DSS 4.1

### WIFI-003: Guest network without isolation
**Severity**: High (CVSS 7.2)
**Category**: WiFi Security
**Path**: `/interface wifi configuration`, `/interface wireless`
**What to look for**: Guest SSID without client isolation
**Detection**:
  - `/interface wifi configuration set ... mode=ap name=<guest-ssid>` with `client-isolation=no`
  - `/interface wireless set ... name=<guest-ssid>` without `security-profile` or forward chain rules isolating guest traffic
  - Guest SSID on same bridge as internal VLAN without firewall separation
**Rationale**: Without client isolation, guests can see and attack each other's devices on the same SSID. They can also potentially reach internal resources if the bridge/subnet is shared. Guest clients must be isolated from each other and from internal networks.
**Remediation**:
  ```
  # RouterOS v7:
  /interface wifi configuration set [find name=<guest-ssid>] client-isolation=yes
  # Firewall separation:
  /interface bridge add name=bridge-guest
  /interface wifi set [find] bridge=bridge-guest
  /ip firewall filter add chain=forward in-interface=bridge-guest out-interface=bridge-lan action=drop
  ```
**Compliance**: NIST AC-17(2), ISO 27001 A.13.2.1, PCI-DSS 1.3.3

### WIFI-004: Broadcast SSID disabled (hidden SSID)
**Severity**: Low (CVSS 2.9)
**Category**: WiFi Security
**Path**: `/interface wireless`, `/interface wifi configuration`
**What to look for**: SSID broadcasting disabled for security purposes
**Detection**:
  - `/interface wireless set ... hide-ssid=yes`
  - `/interface wifi configuration set ... hide-ssid=yes`
**Rationale**: Hiding the SSID is not a security measure. The SSID is still broadcast in probe requests and is easily discoverable with tools like Kismet or Wireshark. Hiding the SSID can actually degrade security by causing clients to broadcast the network name in probe requests.
**Remediation**:
  ```
  /interface wireless set [find] hide-ssid=no
  ```
**Compliance**: NIST SC-7 (information), ISO 27001 A.13.2.1
**Note**: Informational — hidden SSIDs should not be relied upon for security.

### WIFI-005: Same security profile across bands
**Severity**: Medium (CVSS 4.5)
**Category**: WiFi Security
**Path**: `/interface wireless security-profile`, `/interface wifi configuration`
**What to look for**: 2.4GHz and 5GHz interfaces using the same security profile
**Detection**:
  - `/interface wireless set ... security-profile=same-profile` on both bands
  - `/interface wifi configuration set ... security=same-profile` on both `band=2ghz-ax` and `band=5ghz-ax`
**Rationale**: Different bands have different security and performance requirements. 2.4GHz may need legacy compatibility (lower encryption options), while 5GHz should use highest security. Using separate profiles allows per-band security optimization.
**Remediation**:
  ```
  /interface wireless security-profile add name=security-5ghz authentication-types=wpa2-psk
  /interface wireless security-profile add name=security-24ghz authentication-types=wpa2-psk
  /interface wireless set [find band=5ghz-ax] security-profile=security-5ghz
  /interface wireless set [find band=2ghz] security-profile=security-24ghz
  ```
**Compliance**: NIST AC-17(2), ISO 27001 A.13.2.1

### WIFI-006: Client isolation not configured on guest SSID
**Severity**: High (CVSS 7.5)
**Category**: WiFi Security
**Path**: `/interface wifi configuration`
**What to look for**: Guest SSID without client-to-client isolation
**Detection**:
  - `/interface wifi configuration set ... client-isolation=no` or absent on guest network
  - `/interface wireless` without `isolation-forwarding=no` or `bridge-forwarding=no`
**Rationale**: Guest clients should never communicate with each other. Without isolation, a compromised guest device can attack other guests. This is the primary security control for open/public WiFi networks.
**Remediation**:
  ```
  /interface wifi configuration set [find name=<guest>] client-isolation=yes
  # OR legacy wireless:
  /interface wireless set [find name=<guest>] isolate=yes
  ```
**Compliance**: NIST AC-17(2), ISO 27001 A.13.2.1, PCI-DSS 1.3.3

### WIFI-007: CAPsMAN without encryption
**Severity**: High (CVSS 7.8)
**Category**: WiFi Security
**Path**: `/interface wifi capsman`
**What to look for**: CAPsMAN control channel not encrypted
**Detection**:
  - `/interface wifi capsman set ... ca-certificate=...` without `certificate=...` or `client-certificate=...`
  - `/interface wifi capsman set ... certificate=no` or absent
  - `/cap`/`caps-man` (legacy) without `certificate=...`
**Rationale**: Unencrypted CAPsMAN traffic allows attackers to capture provisioning data, including SSIDs and PSKs. CAPsMAN access points authenticate the CAPsMAN server via certificates. Without TLS, the entire management channel is plaintext.
**Remediation**:
  ```
  /certificate add name=capsman-ca common-name=capsman-ca key-usage=key-cert-sign,crl-sign
  /certificate sign capsman-ca
  /certificate add name=capsman-cert common-name=capsman template=capsman-ca
  /interface wifi capsman set ca-certificate=capsman-ca certificate=capsman-cert enabled=yes
  ```
**Compliance**: NIST SC-8, ISO 27001 A.13.2.3, PCI-DSS 4.1

### WIFI-008: WiFi access list not configured
**Severity**: Medium (CVSS 5.5)
**Category**: WiFi Security
**Path**: `/interface wifi access-list`, `/interface wireless access-list`
**What to look for**: No MAC-based access control configured
**Detection**:
  - `/interface wifi access-list` empty or not present
  - `/interface wireless access-list` empty or not present
  - No entries allowing or denying specific clients
**Rationale**: Without an access-list, any client with the correct PSK can connect. MAC ACL provides defense in depth by restricting which devices are permitted. While MAC addresses can be spoofed, this adds a barrier.
**Remediation**:
  ```
  # RouterOS v7:
  /interface wifi access-list add mac-address=<client-mac> action=accept ssid=<ssid>
  /interface wifi configuration set [find] access-list-override=yes
  ```
**Compliance**: NIST AC-17(2), ISO 27001 A.13.2.1, PCI-DSS 8.1.2

### WIFI-009: Management frame protection (PMF) not enabled
**Severity**: High (CVSS 7.4)
**Category**: WiFi Security
**Path**: `/interface wireless security-profile`, `/interface wifi security`
**What to look for**: Protected Management Frames not configured
**Detection**:
  - `/interface wireless security-profile set ... management-protection=disabled` or absent
  - `/interface wifi security set ... pmf=disabled` or `=optional` (should be `=required`)
  - No `management-protection-key` set
**Rationale**: Without PMF, an attacker can forge deauthentication and disassociation frames (Deauth attacks). This allows denial of service and can force clients to reconnect to a rogue AP. PMF (802.11w) cryptographically protects management frames.
**Remediation**:
  ```
  # RouterOS v7:
  /interface wifi security set [find] pmf=required
  # Legacy wireless:
  /interface wireless security-profile set [find] management-protection=key management-protection-key=<key>
  ```
**Note**: For home/SOHO environments, `pmf=optional` is recommended instead of `required`. Some older IoT devices do not support PMF (802.11w) and will fail to connect when set to `required`. Use `required` only in enterprise environments where all clients are validated to support PMF.
**Compliance**: NIST AC-17(2), ISO 27001 A.13.2.1

### WIFI-010: WiFi password too weak or default
**Severity**: Critical (CVSS 9.2)
**Category**: WiFi Security
**Path**: `/interface wireless security-profile`, `/interface wifi security`
**What to look for**: WiFi password is weak, short, or set to a common default
**Detection**:
  - `/interface wireless security-profile set ... wpa2-pre-shared-key=<weak>` where value is <8 chars, dictionary word, or common default
  - `/interface wifi security set ... passphrase=<weak>`
  - Common defaults: `mikrotik`, `admin`, `12345678`, `password`, SSID name
**Rationale**: A weak WiFi PSK allows unauthorized access and decryption of captured traffic. With GPU-accelerated cracking (hashcat), 8-character PSKs can be cracked in days. Minimum 12-16 character PSKs with complexity are recommended.
**Remediation**:
  ```
  /interface wireless security-profile set [find] wpa2-pre-shared-key=<strong-passphrase-16+chars>
  ```
**Compliance**: NIST AC-17(2), ISO 27001 A.13.2.1, PCI-DSS 4.1

### WIFI-011: DFS channels configured without radar handling consideration
**Severity**: Low (CVSS 2.5)
**Category**: WiFi Security
**Path**: `/interface wireless`, `/interface wifi configuration`
**What to look for**: DFS channels configured without radar detection awareness
**Detection**:
  - `/interface wireless set ... frequency=52-64` or `=100-140` (DFS channels)
  - `/interface wifi configuration set ... channel.band=5ghz` with `channel.frequency=<dfs-channel>`
  - No channel selection strategy defined
**Rationale**: DFS channels require radar detection. When radar is detected, the AP must switch channels, causing service interruption. This is an operational concern — but misconfigured DFS (setting a fixed DFS channel) can cause repeated disconnections in radar-prone areas.
**Remediation**:
  ```
  /interface wifi configuration set [find] channel.frequency=auto channel.skip-dfs-channels=all
  # Or use non-DFS channels:
  /interface wifi configuration set [find] channel.frequency=5180,5200
  ```
**Compliance**: N/A (regulatory compliance)

### WIFI-012: hAP ac² wifi-qcom-ac package present
**Severity**: Medium (CVSS 5.0)
**Category**: WiFi Security
**Path**: `/system package`
**What to look for**: The `wifi-qcom-ac` package is present on hAP ac² devices
**Detection**:
  - `/system package` contains `name=wifi-qcom-ac`
  - Export header or `/system resource` shows hAP ac² model (RB952Ui-5ac2nD)
**Rationale**: The `wifi-qcom-ac` package is the legacy wireless driver on hAP ac². It consumes significant flash (several MB on a 16MB device). If other packages are installed, flash exhaustion can cause boot failures and configuration loss.
**Remediation**:
  ```
  # Assess available flash:
  /system resource print
  # If flash is critically low, remove unnecessary packages:
  /system package remove wifi-qcom-ac
  # Then reboot
  ```
**Compliance**: N/A (operational constraint)
**Note**: Only applies to hAP ac². Device model must be verified from export header.

### WIFI-013: Too many SSIDs configured affecting performance
**Severity**: Low (CVSS 2.1)
**Category**: WiFi Security
**Path**: `/interface wifi`, `/interface wireless`
**What to look for**: Excessive number of SSIDs configured on a single radio
**Detection**:
  - More than 4-6 SSIDs on a single wireless interface (virtual APs)
  - `/interface wireless` entries with `master-interface=...` creating many virtual interfaces
  - `/interface wifi configuration` entries with same `radio`
**Rationale**: Each virtual AP sends beacon frames at the lowest mandatory rate (1-12Mbps). Too many SSIDs reduces available airtime for data, degrades performance for all clients, and increases power consumption. The industry recommendation is maximum 4-6 SSIDs per radio.
**Remediation**:
  ```
  # Remove unnecessary virtual APs:
  /interface wireless remove [find master-interface=wlan1 where name~"unused"]
  # RouterOS v7:
  /interface wifi configuration remove [find where disabled=no and ...]
  ```
**Compliance**: N/A (operational hardening)

---

## SCRIPT — Script & Automation (9 checks)

### SCRIPT-001: Scripts with excessive permissions
**Severity**: High (CVSS 7.8)
**Category**: Script & Automation
**Path**: `/system script`
**What to look for**: Scripts with excessive policy permissions
**Detection**:
  - `/system script add ... policy=full,...`
  - `/system script add ... policy=read,write,policy,test,sniff,sensitive,reboot`
  - `/system script set ... policy=full`
**Rationale**: Scripts inherit the policy of their creator or are explicitly granted policies. A script with `full` policy can execute any command, including reading secrets, capturing traffic, and resetting the system. If an attacker compromises a script (via SCRIPT-002), they gain full control.
**Remediation**:
  ```
  /system script set [find] policy=read,write,test
  # Audit each script's policy — grant only required permissions
  ```
**Compliance**: NIST AC-6, ISO 27001 A.9.2.3, PCI-DSS 7.2.1

### SCRIPT-002: Hardcoded credentials in scripts
**Severity**: Critical (CVSS 9.0)
**Category**: Script & Automation
**Path**: `/system script` (source field)
**What to look for**: Script source containing plaintext credentials
**Detection**:
  - `/system script ... source=` containing `password=`, `passphrase=`, `secret=`, `user=... password=...`
  - `/system script ... source=` containing `ip cloud set ddns-enabled=yes ddns-password=...`
  - Scripts with RADIUS secrets, BGP MD5 keys, or SNMP communities in plaintext
**Rationale**: Hardcoded credentials in scripts can be read by anyone with `read` policy on the router. If an attacker gains read access (e.g., via SNMP public community or exported config), they capture these credentials. All scripts should reference credentials from environment variables or external secure stores.
**Remediation**:
  ```
  # Remove hardcoded credentials:
  /system script set [find] source=""
  # Use credential fetch from file or :global variables
  :global admin-password [/file get auth.cfg contents]
  ```
**Compliance**: NIST IA-5(7), ISO 27001 A.9.2.4, PCI-DSS 8.2.1

### SCRIPT-003: Scheduled scripts without single-instance guards
**Severity**: Medium (CVSS 5.0)
**Category**: Script & Automation
**Path**: `/system scheduler`
**What to look for**: Scheduler events that may start overlapping executions of the same script
**Detection**:
  - `/system scheduler add ... on-event="..."` without `:if ([:jobname ...])` or file-lock check
  - `/system scheduler` with intervals shorter than expected execution time
  - No `:jobname` overlap detection in script source
**Rationale**: Without single-instance guards, a long-running script can be started again by the next scheduler tick. Multiple concurrent instances can exhaust CPU, corrupt shared state, or cause duplicate actions.
**Remediation**:
  ```
  # RouterOS v7 syntax for single-instance guard:
  :if ([/system script job find where jobname=$[:jobname]] > 1) do={
    :log warning "Instance already running: $[:jobname]"
    :error "Already running"
  }
  # Or using :jobname in scheduler:
  /system scheduler add name=backup-scheduler interval=1d \
      policy=read,write,local \
      on-event="/system script run backup-router" \
      jobname=backup-router
  ```
**Compliance**: NIST SI-7, ISO 27001 A.12.6.1

### SCRIPT-004: Scheduler scripts without error handling
**Severity**: Medium (CVSS 4.5)
**Category**: Script & Automation
**Path**: `/system scheduler`, `/system script`
**What to look for**: Scheduled scripts without error handling
**Detection**:
  - `/system scheduler ... on-event="..."` without `:onerror` or `:do { ... } on-error={ ... }`
  - Script source without any error handling or logging on failure
  - No `:log error` on script failure conditions
**Rationale**: Unhandled errors in scheduled scripts can halt automation, leave the router in an inconsistent state, or silently fail without alerting the administrator. All automation scripts must handle errors and log failures.
**Remediation**:
  ```
  :do {
    # script body
  } on-error={
    :log error ("Scheduled script " . $scriptName . " failed")
  }
  ```
**Compliance**: NIST SI-7, ISO 27001 A.12.6.1

### SCRIPT-005: Global variable namespace pollution
**Severity**: Low (CVSS 3.0)
**Category**: Script & Automation
**Path**: `/system script` (source field)
**What to look for**: Many scripts using `:global` without coordination
**Detection**:
  - `/system script ... source=` with multiple `:global` variable declarations
  - Same `:global` variable names used across different scripts
  - No prefix naming convention for `:global` variables (e.g., `$ScriptName_varName`)
**Rationale**: RouterOS global variables are shared across all scripts. Without naming conventions, scripts can accidentally overwrite each other's variables, causing unexpected behavior. Using unqualified short global names (`$count`, `$status`) increases collision risk.
**Remediation**:
  ```
  # Use scoped conventions:
  :local backupStatus "ok"
  # Or namespace globals:
  :global BackupJob_status "ok"
  ```
**Compliance**: N/A (operational hardening)

### SCRIPT-006: Destructive commands in scripts
**Severity**: High (CVSS 7.2)
**Category**: Script & Automation
**Path**: `/system script` (source field)
**What to look for**: Scripts containing commands that can cause service disruption or data loss
**Detection**:
  - `/system script ... source=` containing `/system reset-configuration`
  - Script source containing `/system backup load`
  - Script source containing `/file remove` (targeting critical files)
  - Script source containing `/interface disable` on management interfaces
**Rationale**: Destructive commands in automation scripts can cause accidental outages if triggered at the wrong time or if input validation fails. Such commands should require manual confirmation and should never be in unattended scheduled scripts.
**Remediation**:
  ```
  # Remove destructive commands from automated scripts:
  /system script set [find] source=""
  # Document required manual procedures separately
  ```
**Compliance**: NIST CP-2, ISO 27001 A.17.1.2

### SCRIPT-007: Unscheduled scripts with high run counts
**Severity**: Low (CVSS 2.5)
**Category**: Script & Automation
**Path**: `/system script`
**What to look for**: Scripts with high run counts that are not in any scheduler
**Detection**:
  - `/system script print` shows `.run-count=...` high value
  - Script not referenced in `/system scheduler` entries
  - Script referenced only in `:execute` calls from other scripts
**Rationale**: A script with high run counts but no scheduler entry is being executed programmatically or manually at a high rate. This could indicate an automaton loop, runaway process, or excessive polling. Investigate why the script is running and whether it should be optimized.
**Remediation**:
  ```
  # Investigate and review script:
  /system script print where run-count>1000
  ```
**Compliance**: N/A (operational monitoring)

### SCRIPT-008: Logging not configured in scheduled scripts
**Severity**: Medium (CVSS 4.5)
**Category**: Script & Automation
**Path**: `/system script` (source field)
**What to look for**: Scheduled scripts that do not log their execution status
**Detection**:
  - `/system script ... source=` without `:log` statements
  - `/system scheduler ... on-event=...` script content without start/finish logging
  - No structured logging messages with script name and status
**Rationale**: Without logging, it is impossible to verify that scheduled scripts are running correctly or to debug failures. Security-critical automation (backup, update checks, firewall updates) must produce audit trails of their execution.
**Remediation**:
  ```
  :log info ("Script " . $scriptName . " started")
  :do {
    # ... script body ...
    :log info ("Script " . $scriptName . " completed successfully")
  } on-error={
    :log error ("Script " . $scriptName . " failed")
  }
  ```
**Compliance**: NIST AU-3, ISO 27001 A.12.4.1

### SCRIPT-010: Scripts with dont-require-permissions=yes
**Severity**: Critical (CVSS 9.0)
**Category**: Script & Automation
**Path**: `/system script`
**What to look for**: Scripts configured with `dont-require-permissions=yes` — arbitrary command execution risk
**Detection**:
  - `/system script add ... dont-require-permissions=yes`
  - `/system script set ... dont-require-permissions=yes`
**Rationale**: Scripts with `dont-require-permissions=yes` bypass the RouterOS permission system. Any user who can run the script can execute arbitrary commands with the script owner's permissions. This is a critical privilege escalation vector.
**Remediation**:
  ```
  /system script set [find name=<script>] dont-require-permissions=no
  # Ensure the script's policy list grants only the minimum permissions needed:
  /system script set [find name=<script>] policy=read,write,test
  ```
**Compliance**: CIS 11.4, NIST AC-6, ISO 27001 A.8.25, PCI-DSS 6.3

---

## COMP — Compliance Mapping (6 checks)

The COMP checks are informational. They validate that the audit output includes compliance framework mappings for each finding.

### COMP-001: CIS mapping provided per finding
**Severity**: Info (CVSS 0.0)
**Category**: Compliance Mapping
**Path**: Audit report (meta)
**What to look for**: Each finding includes mapping to CIS RouterOS Benchmark controls
**Detection**: Verify audit output contains `compliance.cis` references
**Rationale**: CIS RouterOS Benchmark is the primary industry standard for secure RouterOS configuration. Mapping findings to CIS controls enables organizations to track compliance against this benchmark.
**Remediation**: N/A — this is an output requirement for the auditor.
**Compliance**: CIS RouterOS Benchmark v1.x

### COMP-002: NIST SP 800-53 mapping provided per finding
**Severity**: Info (CVSS 0.0)
**Category**: Compliance Mapping
**Path**: Audit report (meta)
**What to look for**: Each finding includes mapping to NIST SP 800-53 controls
**Detection**: Verify audit output contains `compliance.nist` references (e.g., AC-2, SC-7, IA-5)
**Rationale**: NIST SP 800-53 is the standard for US federal information systems. Mapping RouterOS findings to NIST controls supports FedRAMP and FISMA compliance efforts.
**Remediation**: N/A — this is an output requirement for the auditor.
**Compliance**: NIST SP 800-53 Rev 5

### COMP-003: ISO 27001 mapping provided per finding
**Severity**: Info (CVSS 0.0)
**Category**: Compliance Mapping
**Path**: Audit report (meta)
**What to look for**: Each finding includes mapping to ISO 27001 Annex A controls
**Detection**: Verify audit output contains `compliance.iso` references (e.g., A.9.2.1, A.13.1.1)
**Rationale**: ISO 27001 is the international standard for information security management systems. Mapping to Annex A controls enables integration with existing ISMS compliance frameworks.
**Remediation**: N/A — this is an output requirement for the auditor.
**Compliance**: ISO 27001:2022

### COMP-004: PCI-DSS mapping provided per finding
**Severity**: Info (CVSS 0.0)
**Category**: Compliance Mapping
**Path**: Audit report (meta)
**What to look for**: Each finding includes mapping to PCI DSS requirements
**Detection**: Verify audit output contains `compliance.pci` references (e.g., PCI-DSS 1.3, 4.1, 8.1.6)
**Rationale**: PCI DSS applies to any organization handling cardholder data. RouterOS configurations that secure the network perimeter are subject to PCI DSS requirements for network security, access control, and logging.
**Remediation**: N/A — this is an output requirement for the auditor.
**Compliance**: PCI DSS v4.0

### COMP-005: Mitre ATT&CK mapping provided per finding
**Severity**: Info (CVSS 0.0)
**Category**: Compliance Mapping
**Path**: Audit report (meta)
**What to look for**: Each finding includes mapping to Mitre ATT&CK techniques
**Detection**: Verify audit output contains `compliance.attack` references (e.g., T1190, T1046, T1110)
**Rationale**: Mitre ATT&CK provides a common taxonomy for adversary behaviors. Mapping findings to ATT&CK techniques helps security teams understand the real-world attack impact of misconfigurations.
**Remediation**: N/A — this is an output requirement for the auditor.
**Compliance**: Mitre ATT&CK v15

### COMP-006: CVSS scoring matrix provided per finding
**Severity**: Info (CVSS 0.0)
**Category**: Compliance Mapping
**Path**: Audit report (meta)
**What to look for**: Each finding includes CVSS v3.1 scoring with vector string
**Detection**: Verify audit output contains `cvss.score`, `cvss.vector`, and `cvss.severity` for each finding
**Rationale**: CVSS provides a standardized severity rating. The vector string documents the specific scoring criteria (attack vector, complexity, privileges required, etc.). This enables prioritization and risk-based remediation planning.
**Remediation**: N/A — this is an output requirement for the auditor.
**Compliance**: CVSS v3.1

---

## Appendix A: CVSS Scoring Guide

The following metrics are used for configuration-based CVSS scoring:

| Metric | Value | Description |
|--------|-------|-------------|
| AV (Attack Vector) | N / A / L / P | Network / Adjacent / Local / Physical |
| AC (Attack Complexity) | L / H | Low / High |
| PR (Privileges Required) | N / L / H | None / Low / High |
| UI (User Interaction) | N / R | None / Required |
| S (Scope) | U / C | Unchanged / Changed |
| C (Confidentiality) | H / L / N | High / Low / None |
| I (Integrity) | H / L / N | High / Low / None |
| A (Availability) | H / L / N | High / Low / None |

Severity ranges: Critical 9.0-10.0, High 7.0-8.9, Medium 4.0-6.9, Low 0.1-3.9, Info 0.0

Configuration CVSS nuances:
- **AV:P** (Physical) — used for LCD, physical port access
- **PR:N** (No privileges) — used when no authentication is needed to exploit
- **S:C** (Scope Changed) — used when the finding impacts a resource beyond the router (e.g., open DNS resolver affects third parties)

## Appendix B: Check Index by ID

| ID | Title | Severity |
|----|-------|----------|
| AUTH-001 | Default admin user present | Critical |
| AUTH-002 | No password set on admin | Critical |
| AUTH-003 | Weak password patterns | Critical |
| AUTH-004 | Users in 'full' group without IP restrictions | High |
| AUTH-005 | SSH weak-crypto enabled | High |
| AUTH-006 | MAC-Telnet service enabled | High |
| AUTH-007 | MAC-WinBox service enabled | High |
| AUTH-008 | MAC-Ping service enabled | Medium |
| AUTH-009 | WinBox service exposed on WAN | Critical |
| AUTH-010 | API/REST-API exposed on WAN | Critical |
| AUTH-011 | No login attempt restrictions | High |
| AUTH-012 | Default management ports unchanged | Medium |
| AUTH-013 | RoMON enabled | High |
| AUTH-014 | No password policy configured | Medium |
| AUTH-015 | User accounts without expiry configured | Medium |
| AUTH-016 | Sensitive policies too permissive | High |
| AUTH-017 | SSH idle timeout not configured | Medium |
| AUTH-018 | RADIUS AAA not configured for admin auth | Medium |
| SRV-001 | DNS remote requests allowed | High |
| SRV-002 | Bandwidth server enabled | High |
| SRV-003 | Proxy service enabled | High |
| SRV-004 | SOCKS service enabled | High |
| SRV-005 | UPnP enabled | High |
| SRV-006 | Neighbor discovery enabled on WAN | Medium |
| SRV-007 | SNMP v1/v2c with public community | High |
| SRV-008 | Telnet service enabled | High |
| SRV-009 | FTP service enabled | High |
| SRV-010 | PPTP server enabled | High |
| SRV-011 | Cloud services enabled | Medium |
| SRV-012 | SMB service enabled | High |
| SRV-013 | Unused interfaces not disabled | Low |
| SRV-014 | WebFig/HTTP enabled without HTTPS | High |
| SRV-015 | LCD not secured | Low |
| SRV-016 | DNS cache size not configured | Low |
| SRV-017 | Graphing service enabled | Low |
| FW-001 | No firewall filter rules at all | Critical |
| FW-002 | WAN input chain without default drop | Critical |
| FW-003 | No established/related connection rule | Critical |
| FW-004 | No brute-force protection | High |
| FW-005 | No bogon filtering in RAW table | High |
| FW-006 | IPv6 firewall not configured | High |
| FW-007 | FastTrack not configured | Medium |
| FW-008 | Port knocking not configured for WAN | Medium |
| FW-009 | WAN-side management access unrestricted | Critical |
| FW-010 | Forward chain rules too permissive | High |
| FW-011 | NAT rules with too broad source | Medium |
| FW-012 | No ICMP rate limiting | Medium |
| FW-013 | DSTNAT without restriction | High |
| FW-014 | Broadcast/multicast not blocked | Medium |
| FW-015 | RAW table not configured at all | Medium |
| FW-016 | Connection tracking limits not configured | High |
| FW-017 | No address-lists for dynamic threat blocking | Medium |
| SYS-001 | RouterOS version not found | High |
| SYS-002 | System identity not set | Low |
| SYS-003 | NTP not configured | High |
| SYS-004 | Local logging not configured | Medium |
| SYS-005 | Remote syslog not configured | Medium |
| SYS-006 | Auto-update check not configured | Medium |
| SYS-007 | Unsigned packages allowed | High |
| SYS-008 | Support output not secured | Low |
| SYS-009 | System backup not configured | Medium |
| SYS-010 | System watchdog not configured | Medium |
| NET-001 | Bridge VLAN filtering not enabled | High |
| NET-002 | DHCP server without secure options | Medium |
| NET-003 | DHCP lease storage on flash-constrained | Medium |
| NET-004 | DNS cache poisoning protection not configured | Medium |
| NET-005 | DNS forwarders not configured | Low |
| NET-006 | Bridge HW offload misconfiguration | High |
| NET-007 | MTU/fragmentation issues | Medium |
| NET-008 | VRRP/HA not configured for critical gateways | Medium |
| NET-009 | IGMP snooping not configured | Medium |
| ROUTE-001 | BGP without MD5 authentication | High |
| ROUTE-002 | OSPF without authentication | High |
| ROUTE-003 | Routing filters not applied | High |
| ROUTE-004 | BGP TTL security not configured | Medium |
| ROUTE-005 | BGP prefix limits not configured | High |
| ROUTE-006 | Dynamic routing on WAN-facing interfaces | High |
| ROUTE-007 | Default route without backup/check | Medium |
| ROUTE-008 | Loopback interface not configured for router ID | Low |
| ROUTE-009 | ECMP without connection marking | Medium |
| WIFI-001 | Insecure encryption (WEP/TKIP) configured | Critical |
| WIFI-002 | WPS enabled | High |
| WIFI-003 | Guest network without isolation | High |
| WIFI-004 | Broadcast SSID disabled (hidden SSID) | Low |
| WIFI-005 | Same security profile across bands | Medium |
| WIFI-006 | Client isolation not configured on guest | High |
| WIFI-007 | CAPsMAN without encryption | High |
| WIFI-008 | WiFi access list not configured | Medium |
| WIFI-009 | Management frame protection not enabled | High |
| WIFI-010 | WiFi password too weak or default | Critical |
| WIFI-011 | DFS channels without radar handling | Low |
| WIFI-012 | hAP ac² wifi-qcom-ac package present | Medium |
| WIFI-013 | Too many SSIDs configured | Low |
| SCRIPT-001 | Scripts with excessive permissions | High |
| SCRIPT-002 | Hardcoded credentials in scripts | Critical |
| SCRIPT-003 | Scripts without single-instance guards | Medium |
| SCRIPT-004 | Scheduler scripts without error handling | Medium |
| SCRIPT-005 | Global variable namespace pollution | Low |
| SCRIPT-006 | Destructive commands in scripts | High |
| SCRIPT-007 | Unscheduled scripts with high run counts | Low |
| SCRIPT-008 | Logging not configured in scheduled scripts | Medium |
| SCRIPT-010 | Scripts with dont-require-permissions=yes | Critical |
| COMP-001 | CIS mapping provided per finding | Info |
| COMP-002 | NIST SP 800-53 mapping provided per finding | Info |
| COMP-003 | ISO 27001 mapping provided per finding | Info |
| COMP-004 | PCI-DSS mapping provided per finding | Info |
| COMP-005 | Mitre ATT&CK mapping provided per finding | Info |
| COMP-006 | CVSS scoring matrix provided per finding | Info |
