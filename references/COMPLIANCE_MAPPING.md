---
description: >-
  Compliance framework mapping for MikroTik RouterOS configuration audits.
  CIS, NIST SP 800-53, ISO 27001, and PCI-DSS control crosswalks for all
  audit checks. Note: No official CIS Benchmark exists for MikroTik RouterOS;
  these mappings are derived crosswalks from general network device benchmarks.
---

# Compliance Mapping Reference

## Important Note

**There is NO official CIS Benchmark for MikroTik RouterOS as of 2026.** These
mappings are crosswalks derived from CIS Benchmarks for general network
infrastructure devices (Cisco IOS, Juniper JunOS, Linux, etc.), NIST SP 800-53
Rev 5, ISO 27001:2022 Annex A, and PCI DSS v4.0. They represent best-effort
alignment for compliance auditing purposes.

When using this reference in an audit report:

- Map findings to the closest equivalent control in each framework.
- Note the crosswalk nature explicitly in compliance artifacts.
- Accept compensating controls documented by the device operator.
- Flag gaps where RouterOS lacks native equivalent controls.

## Check ID Prefixes

| Prefix   | Domain                        | Count | Severity Range |
|----------|-------------------------------|-------|----------------|
| `AUTH-`  | Authentication & Access       | 18    | Critical       |
| `SRV-`   | Service Hardening             | 17    | High           |
| `FW-`    | Firewall & Network Security   | 17    | Critical/High  |
| `SYS-`   | System Hardening              | 10    | High           |
| `NET-`   | Network Configuration         | 9     | Medium         |
| `ROUTE-` | Routing Security              | 9     | Medium/High    |
| `WIFI-`  | WiFi Security                 | 13    | High/Medium    |
| `SCRIPT-`| Script & Automation           | 9     | Medium         |
| `COMP-`  | Compliance Mapping            | 6     | Info           |

---

## 1. CIS Critical Security Controls Mapping

Based on CIS Controls v8 and CIS Network Infrastructure Benchmark v3.0
methodology (crosswalked for RouterOS). The mapping uses **CIS-01 through
CIS-27** as custom identifiers to clearly distinguish them from actual CIS
v8 safeguard IDs. The actual CIS v8 Safeguard number is provided in the
second column for cross-referencing.

> **Note:** These identifiers (CIS-01 through CIS-27) are project-internal
> labels. They do NOT correspond to official CIS control or safeguard
> numbers. Use the "CIS v8 Safeguard" column when referencing the actual
> CIS framework.

| Custom ID | CIS v8 Safeguard | Description | RouterOS Checks |
|-----------|------------------|-------------|-----------------|
| CIS-01 | 1.1.1 | Disable unused ports and default accounts | AUTH-001, AUTH-002, NET-006 |
| CIS-02 | 1.1.2 | Secure management access plane | AUTH-001, AUTH-004, AUTH-005, AUTH-006, AUTH-007, AUTH-008, AUTH-009, AUTH-010, AUTH-012, AUTH-013, AUTH-015, AUTH-016 |
| CIS-03 | 5.2 | Banner and identification configuration | SYS-002 |
| CIS-04 | 4.1 | Disable insecure management services | SRV-001, SRV-002, SRV-003, SRV-004, SRV-005, SRV-006, SRV-007, SRV-008, SRV-009, SRV-010, SRV-011, SRV-012, SRV-013, SRV-014, SRV-015 |
| CIS-05 | 4.2 | Disable insecure data-plane services | AUTH-006, AUTH-010, SRV-001 |
| CIS-06 | 4.3 | Disable discovery protocols on untrusted interfaces | SRV-006, SRV-014 |
| CIS-07 | 4.4 | Configure and apply ingress/egress ACLs | FW-001, FW-002, FW-010, FW-012, FW-014 |
| CIS-08 | 4.4 | Configure stateful firewall rules | FW-001, FW-002, FW-003, FW-004, FW-005, FW-010, FW-012, FW-013, FW-015, FW-016 |
| CIS-09 | 4.5 | Restrict private IPs from leaving the network (bogons) | FW-006, FW-007 |
| CIS-10 | 4.6 | Enable anti-spoofing controls | FW-006, FW-014 |
| CIS-11 | 8.1 | Configure and enable logging | SYS-004, SYS-005 |
| CIS-12 | 8.2 | Synchronize system clocks | SYS-003 |
| CIS-13 | 8.3 | Protect log integrity | SYS-005, SYS-008 |
| CIS-14 | 10.1 | Secure routing protocols with authentication | ROUTE-001, ROUTE-002 |
| CIS-15 | 10.2 | Apply routing filters and prefix limits | ROUTE-003, ROUTE-005 |
| CIS-16 | 10.3 | Disable dynamic routing on perimeter interfaces | ROUTE-006 |
| CIS-17 | 10.4 | Configure BGP TTL security | ROUTE-004 |
| CIS-18 | 6.1 | Configure AAA for administrative access | AUTH-001, AUTH-004, AUTH-014 |
| CIS-19 | 6.2 | Enforce password complexity and aging | AUTH-003, AUTH-011, AUTH-013 |
| CIS-20 | 6.3 | Encrypt administrative sessions | AUTH-005, AUTH-008 |
| CIS-21 | 5.4 | Disable or rename default accounts | AUTH-001, AUTH-002 |
| CIS-22 | 5.5 | Remove unnecessary accounts | AUTH-015 |
| CIS-23 | 3.2 | Secure SNMP configuration | SRV-007 |
| CIS-24 | 3.3 | Disable SNMP if not required | SRV-007 |
| CIS-25 | 9.1 | Implement connection tracking limits | FW-013 |
| CIS-26 | 9.2 | Enable SYN flood and DoS protection | FW-004, FW-005, FW-015 |
| CIS-27 | 2.1 | Apply secure baseline configuration | All checks |
| CIS-28 | 2.2 | Manage software versions and patching | SYS-001, SYS-006, SYS-007 |
| CIS-29 | 11.1 | Disable unnecessary services and protocols | SRV-001 through SRV-015 |
| CIS-30 | 7.1 | Securely manage Wi-Fi networks | WIFI-001 through WIFI-012 |
| CIS-31 | 3.1 | Configure port security and DHCP snooping | NET-002, NET-003 |
| CIS-32 | 3.2 | Secure router management interfaces | AUTH-007, AUTH-010, AUTH-012 |
| CIS-33 | 12.1 | Enable auditing and logging of configuration changes | SYS-004, SYS-008, SYS-009 |
| CIS-34 | 13.1 | Implement remote access VPN securely | AUTH-009, AUTH-010 |
| CIS-35 | 13.2 | Configure VPN encryption and authentication | WIFI-001 |
| CIS-36 | 14.1 | Secure scripting environment | SCRIPT-001 through SCRIPT-007 |
| CIS-37 | 16.1 | Maintain backup configurations | SYS-009 |

### CIS Control Families Summary

| CIS Domain | Custom ID Range | CIS v8 Safeguard | Relevant Check Prefixes |
|------------|----------------|-------------------|------------------------|
| Inventory of Authorized Devices | CIS-01, CIS-02 | 1.1.x | AUTH, NET |
| Configurations and Baselines | CIS-27, CIS-28 | 2.x | ALL |
| Continuous Vulnerability Management | CIS-23, CIS-24 | 3.x | SYS, SRV |
| Controlled Use of Administrative Privileges | CIS-18–CIS-22 | 5.x–6.x | AUTH, SYS |
| Maintenance, Monitoring, and Analysis | CIS-11–CIS-13 | 8.x | ROUTE, FW |
| Boundary Defense | CIS-07–CIS-10 | 4.x | FW, SRV, WIFI |
| Account Management | CIS-18, CIS-19, CIS-21 | 5.x, 6.x | AUTH |
| Defense Against Denial-of-Service | CIS-25, CIS-26 | 9.x | FW |
| Secure Network Infrastructure | CIS-29, CIS-30, CIS-31 | 7.x, 11.x | WIFI, NET |
| Incident Response and Management | CIS-33 | 12.x | SYS, COMP |
| Application and Scripting Security | CIS-36 | 14.x | SCRIPT |
| Backup and Recovery | CIS-37 | 16.x | SYS |

---

## 2. NIST SP 800-53 Rev 5 Mapping

NIST SP 800-53 Rev 5 controls relevant to RouterOS configuration auditing.
Mappings are crosswalked from network device security configuration
guidelines in NIST SP 800-77 (IPsec), SP 800-136 (VPN), SP 800-97 (WiFi),
and SP 800-41 (firewalls).

### Access Control (AC) Family

| NIST Control | Control Name | Description | RouterOS Checks |
|--------------|-------------|-------------|-----------------|
| AC-2 | Account Management | Identification, creation, and management of user accounts | AUTH-001, AUTH-002, AUTH-004, AUTH-015 |
| AC-2(1) | Account Management \| Automated System Account Management | Automated management of user accounts | AUTH-014 |
| AC-2(2) | Account Management \| Removal of Temporal/Emergency Accounts | Cleanup of temporary accounts | AUTH-001, AUTH-015 |
| AC-3 | Access Enforcement | Enforce approved authorizations for access | AUTH-004, AUTH-016 |
| AC-4 | Information Flow Enforcement | Control information flow between subsystems | FW-001, FW-002, FW-010, FW-012, FW-016 |
| AC-6 | Least Privilege | Employ least privilege principle | AUTH-004, AUTH-016, SCRIPT-001 |
| AC-7 | Unsuccessful Login Attempts | Limit invalid login attempts | AUTH-011 |
| AC-8 | System Use Notification | Display banner before authentication | SYS-002 |
| AC-10 | Concurrent Session Control | Limit concurrent sessions | AUTH-011 |
| AC-11 | Session Lock | Inactivity-based session termination | AUTH-012 |
| AC-17 | Remote Access | Control remote access sessions | AUTH-009, AUTH-010, AUTH-012 |
| AC-17(2) | Remote Access \| Automated Monitoring | Monitor remote access | SYS-004, SYS-005 |
| AC-17(3) | Remote Access \| Managed Access Control Points | Route remote access through MFA | AUTH-011 |
| AC-18 | Wireless Access | Control wireless access | WIFI-001 through WIFI-012 |
| AC-18(1) | Wireless Access \| Authentication and Encryption | Authenticate and encrypt wireless access | WIFI-001, WIFI-009, WIFI-010 |
| AC-18(3) | Wireless Access \| Disable Wireless on Internal Networks | Disable wireless on sensitive networks | WIFI-003, WIFI-006 |
| AC-20 | External Connections | Control use of external systems | AUTH-009, AUTH-010, SRV-011 |
| AC-21 | Information Sharing | Control information sharing | FW-010, FW-011, FW-012 |

### Audit and Accountability (AU) Family

| NIST Control | Control Name | Description | RouterOS Checks |
|--------------|-------------|-------------|-----------------|
| AU-2 | Audit Events | Identify auditable events | SYS-004, SYS-005 |
| AU-3 | Audit Record Content | Content of audit records | SYS-004, SYS-005 |
| AU-3(1) | Audit Record Content \| Additional Information | Additional audit context | SYS-005 |
| AU-4 | Audit Log Storage Capacity | Allocate log storage | SYS-004, SYS-008 |
| AU-5 | Response to Audit Processing Failures | Handle log failures | SYS-008 |
| AU-6 | Audit Review, Analysis, and Reporting | Review audit logs | SYS-005 |
| AU-7 | Audit Reduction and Report Generation | Log processing | SYS-004, SYS-005 |
| AU-8 | Time Stamps | Time synchronization for logs | SYS-003 |
| AU-9 | Protection of Audit Information | Protect audit logs | SYS-005, SYS-008 |
| AU-11 | Audit Log Retention | Retain audit logs | SYS-004, SYS-005, SYS-008 |
| AU-12 | Audit Generation | Generate audit records | SYS-004, SYS-005 |
| AU-14 | Session Audit | Monitor user sessions | SYS-005 |

### Configuration Management (CM) Family

| NIST Control | Control Name | Description | RouterOS Checks |
|--------------|-------------|-------------|-----------------|
| CM-2 | Baseline Configuration | Maintain baseline configuration | ALL checks |
| CM-2(1) | Baseline Configuration \| Automation for Accuracy | Automated baseline review | COMP-001 through COMP-006 |
| CM-2(2) | Baseline Configuration \| Automation for Currency | Regular baseline updates | SYS-006 |
| CM-3 | Configuration Change Control | Control changes to configuration | SYS-009, SCRIPT-007 |
| CM-5 | Access Restrictions for Change | Restrict config change access | AUTH-004, AUTH-016 |
| CM-6 | Configuration Settings | Configure security-relevant settings | ALL checks |
| CM-7 | Least Functionality | Disable unnecessary functionality | SRV-001 through SRV-015, FW-008 |
| CM-7(1) | Least Functionality \| Periodic Review | Review enabled services | SRV-001 through SRV-015 |
| CM-8 | System Component Inventory | Maintain system inventory | SYS-001, SRV-015, NET-006 |
| CM-9 | Configuration Management Plan | Config governance | COMP-001 through COMP-006 |

### Identification and Authentication (IA) Family

| NIST Control | Control Name | Description | RouterOS Checks |
|--------------|-------------|-------------|-----------------|
| IA-2 | Identification and Authentication | Unique user identification | AUTH-001, AUTH-015 |
| IA-2(1) | I&A \| Multi-factor Authentication | MFA for privileged access | AUTH-011 |
| IA-3 | Device Identification and Authentication | Identify devices before access | NET-002, WIFI-008 |
| IA-4 | Identifier Management | Manage user identifiers | AUTH-001, AUTH-002, AUTH-015 |
| IA-5 | Authenticator Management | Manage passwords and secrets | AUTH-003, AUTH-013, AUTH-014, WIFI-010 |
| IA-5(1) | Authenticator Management \| Password-based Authentication | Password complexity and aging | AUTH-003, AUTH-013 |
| IA-5(6) | Authenticator Management \| Protection of Authenticators | Protect stored credentials | SCRIPT-002 |
| IA-7 | Cryptographic Module Authentication | FIPS-validated crypto | AUTH-005, WIFI-001 |

### System and Communications Protection (SC) Family

| NIST Control | Control Name | Description | RouterOS Checks |
|--------------|-------------|-------------|-----------------|
| SC-7 | Boundary Protection | Protect network boundaries | FW-001 through FW-016, NET-001, WIFI-003 |
| SC-7(3) | Boundary Protection \| Access Points | Limit external access points | AUTH-007, AUTH-010, SRV-011 |
| SC-7(4) | Boundary Protection \| External Telecommunications | Managed routing for external access | ROUTE-006 |
| SC-7(5) | Boundary Protection \| Deny by Default | Default deny policy | FW-001, FW-002, FW-016 |
| SC-7(7) | Boundary Protection \| Split Tunneling | Prevent split tunneling | AUTH-009 |
| SC-8 | Transmission Confidentiality and Integrity | Encrypt transmitted data | AUTH-005, AUTH-006, AUTH-008, WIFI-001 |
| SC-8(1) | Transmission Confidentiality \| Encryption or Full Disk | Use encrypted channels | AUTH-005, AUTH-008, WIFI-001 |
| SC-10 | Network Disconnect | Terminate network connections on session end | AUTH-012 |
| SC-12 | Cryptographic Key Establishment and Management | Manage cryptographic keys | ROUTE-001, ROUTE-002 |
| SC-13 | Cryptographic Protection | Use FIPS-validated crypto | AUTH-005, WIFI-001 |
| SC-15 | Collaborative Computing Devices | Control shared computing | SRV-003, SRV-004, SRV-005 |
| SC-20 | Secure Name/Address Resolution (DNS) | Secure DNS | NET-004, SRV-001 |
| SC-21 | Denial of Service Protection | Protect against DoS | FW-004, FW-005, FW-013, FW-015 |
| SC-22 | DDoS Prevention | Prevent DDoS amplification | SRV-001, FW-004 |

### System and Information Integrity (SI) Family

| NIST Control | Control Name | Description | RouterOS Checks |
|--------------|-------------|-------------|-----------------|
| SI-2 | Flaw Remediation | Patch management | SYS-001, SYS-006, SYS-007 |
| SI-3 | Malicious Code Protection | Anti-malware capability | SYS-001, SYS-006 |
| SI-4 | System Monitoring | Monitor for attacks | SYS-004, SYS-005, FW-004 |
| SI-4(4) | System Monitoring \| Inbound/Outbound Traffic | Monitor network traffic | FW-001, FW-010, FW-016 |
| SI-7 | Software, Firmware, and Information Integrity | Verify software integrity | SYS-007 |
| SI-7(1) | Integrity \| Integrity Checks | Config integrity monitoring | SYS-009 |
| SI-10 | Information Input Validation | Validate network inputs | FW-003, FW-006, FW-014 |
| SI-12 | Information Management and Handling | Proper handling of info | SCRIPT-005, SCRIPT-006 |

### Additional Families

| NIST Control | Control Name | Description | RouterOS Checks |
|--------------|-------------|-------------|-----------------|
| PL-4 | Rules of Behavior | Acceptable use rules | SYS-002 |
| AT-3 | Role-based Training | Training for privileged users | SCRIPT-004, SCRIPT-005 |
| SA-8 | Security Engineering Principles | Security in design | SCRIPT-007 |
| CP-9 | System Backup | Configuration backup | SYS-009 |
| CP-9(1) | System Backup \| Testing for Reliability | Validate backups | SYS-009 |
| CP-10 | System Recovery and Reconstitution | Recovery procedures | SYS-009 |
| MA-3 | Maintenance Tools | Control maintenance tools | AUTH-006, AUTH-010 |
| RA-3 | Risk Assessment | Risk identification | SYS-001, COMP-006 |
| RA-5 | Vulnerability Monitoring and Scanning | Vulnerability scanning | SYS-001, SYS-006 |
| CA-2 | Security Assessments | Periodic assessment | ALL checks |
| CA-7 | Continuous Monitoring | Ongoing security monitoring | SYS-004, SYS-005 |

---

## 3. ISO 27001:2022 Mapping

ISO 27001:2022 Annex A controls relevant to RouterOS configuration auditing.
References use the ISO/IEC 27001:2022 clause numbering with the updated
control titles.

### Organizational Controls (Clause 5)

| ISO Control | Control Title | Description | RouterOS Checks |
|-------------|---------------|-------------|-----------------|
| A.5.1 | Policies for Information Security | Information security policy | COMP-001 through COMP-006 |
| A.5.2 | Information Security Roles and Responsibilities | Assign security responsibilities | AUTH-004, AUTH-016 |
| A.5.6 | Contact with Special Interest Groups | Security community engagement | SYS-001 |
| A.5.7 | Threat Intelligence | Monitor threat intelligence | SYS-001, SYS-006 |
| A.5.8 | Information Security in Project Management | Security in changes | SYS-009, SCRIPT-007 |
| A.5.10 | Acceptable Use of Information | Acceptable use policy | SYS-002 |
| A.5.14 | Information Transfer | Secure information transfer | FW-009, ROUTE-006, AUTH-009 |
| A.5.15 | Access Control | Control access to information | AUTH-004, AUTH-016 |
| A.5.18 | Access Rights | Manage access rights | AUTH-001, AUTH-002, AUTH-015 |
| A.5.20 | Supplier Relationships | Third-party access | SRV-011, AUTH-009 |
| A.5.23 | Information Security for Use of Cloud Services | Cloud service security | SRV-011 |
| A.5.25 | Assessment and Decision on Information Security Events | Incident evaluation | SYS-004, SYS-005 |
| A.5.29 | Security During Disruption | Business continuity | SYS-009 |
| A.5.36 | Compliance with Policies and Rules | Compliance verification | COMP-001 through COMP-006 |

### People Controls (Clause 6)

| ISO Control | Control Title | Description | RouterOS Checks |
|-------------|---------------|-------------|-----------------|
| A.6.3 | Information Security Awareness | Security awareness training | SCRIPT-004, SCRIPT-005 |
| A.6.5 | Responsibilities After Termination | Remove access after termination | AUTH-001, AUTH-015 |

### Physical Controls (Clause 7)

| ISO Control | Control Title | Description | RouterOS Checks |
|-------------|---------------|-------------|-----------------|
| A.7.9 | Secure Disposal or Reuse of Equipment | Wipe configurations | SCRIPT-006 |
| A.7.10 | Physical Security Monitoring | Facility monitoring | SYS-004, SYS-005 |
| A.7.14 | Secure On-Site Facilities | Secure equipment location | NET-003 |

### Technological Controls (Clause 8)

| ISO Control | Control Title | Description | RouterOS Checks |
|-------------|---------------|-------------|-----------------|
| A.8.1 | User Endpoint Devices | Secure endpoints | AUTH-006, AUTH-010 |
| A.8.3 | Access to Information | Restrict information access | AUTH-001, AUTH-002, AUTH-015 |
| A.8.4 | Access to Sensitive Applications | Restrict application access | AUTH-004, AUTH-016, SCRIPT-001 |
| A.8.5 | Secure Authentication | Secure user authentication | AUTH-003, AUTH-011, AUTH-013, WIFI-010 |
| A.8.6 | Capacity Management | Manage system capacity | SYS-009, NET-005, FW-013 |
| A.8.7 | Protection Against Malware | Malware protection | SYS-001, SYS-006, SYS-007 |
| A.8.8 | Management of Technical Vulnerabilities | Vulnerability management | SYS-001, SYS-006, SYS-007 |
| A.8.9 | Configuration Management | Secure configuration | ALL checks |
| A.8.10 | Information Deletion | Secure data deletion | SCRIPT-006 |
| A.8.11 | Data Masking | Mask sensitive data | SCRIPT-002 |
| A.8.12 | Data Leakage Prevention | Prevent data leaks | AUTH-010, SRV-001, SRV-007, FW-010 |
| A.8.13 | Information Backup | Backup configuration | SYS-009 |
| A.8.14 | Redundancy of Information Processing Facilities | HA/redundancy | NET-007, ROUTE-007 |
| A.8.15 | Logging | Enable and configure logging | SYS-004, SYS-005 |
| A.8.16 | Clock Synchronization | Synchronize system clocks | SYS-003 |
| A.8.17 | Use of Cryptography | Apply cryptographic controls | AUTH-005, AUTH-006, AUTH-008, WIFI-001 |
| A.8.18 | Change Management | Managed configuration changes | SYS-009, SCRIPT-007 |
| A.8.19 | Secure Disposal or Reuse of Software | Decommissioning | SCRIPT-006 |
| A.8.20 | Network Security | Secure network infrastructure | FW-001 through FW-016, ROUTE-001 through ROUTE-008, WIFI-001 through WIFI-012 |
| A.8.21 | Network Segregation | Separate network segments | NET-001, FW-010, WIFI-003, WIFI-006 |
| A.8.22 | VPN and Remote Access | Secure remote access | AUTH-009, AUTH-010, AUTH-012 |
| A.8.23 | Web Filtering | Web content filtering | SRV-003, FW-010 |
| A.8.24 | Secure Development | Secure scripting practices | SCRIPT-001 through SCRIPT-007 |
| A.8.25 | Secure Development Life Cycle | SDL for router scripts | SCRIPT-001 through SCRIPT-007 |
| A.8.26 | Application Security Testing | Test application security | SCRIPT-004 |
| A.8.27 | Secure System Architecture | Secure architecture design | FW-001, FW-010, NET-001 |
| A.8.28 | Secure Coding | Secure scripting | SCRIPT-002, SCRIPT-004, SCRIPT-005 |
| A.8.29 | Security Testing in Development | Test security controls | COMP-001 through COMP-006 |
| A.8.30 | Outsourced Development | Third-party scripts | SCRIPT-001, SCRIPT-002 |
| A.8.31 | Separation of Development, Test, and Production | Environment separation | SCRIPT-003 |
| A.8.32 | Change Control | Change management for scripts | SCRIPT-007 |
| A.8.33 | Test Information | Protect test data | SCRIPT-002 |

---

## 4. PCI DSS v4.0 Mapping

> **⚠️ IMPORTANT DISCLAIMER:** PCI DSS v4.0 mapping applies ONLY when
> RouterOS devices are in or adjacent to a Cardholder Data Environment (CDE).
> For home/SOHO networks, these mappings are **informational only**.
> PCI DSS compliance is **not required** for personal/home networks that do
> not process, store, or transmit cardholder data.

PCI DSS v4.0 requirements applicable to RouterOS configurations. RouterOS
devices in CDE (Cardholder Data Environment) or connected to CDE networks
must satisfy these controls. Note that RouterOS is unlikely to directly
process cardholder data, but network devices securing CDE boundaries are in
scope.

### Requirement 1: Firewall Configuration

| PCI DSS v4.0 | Requirement Title | Description | RouterOS Checks |
|--------------|-------------------|-------------|-----------------|
| 1.1.1 | Firewall Installation | Install firewalls at network boundaries | FW-001, FW-002 |
| 1.1.2 | Firewall Configuration Standards | Documented firewall standards | FW-003 through FW-016 |
| 1.1.3 | Firewall & Router Management | Manage firewall/router configs | FW-001, FW-002, FW-016 |
| 1.1.4 | Groups and Roles | Assign admin roles | AUTH-004, AUTH-016 |
| 1.2.1 | Inbound/Outbound Restrictions | Restrict inbound/outbound traffic | FW-001, FW-002, FW-010, FW-012 |
| 1.2.2 | Secure Connectivity | Secure network connections | FW-003, FW-016 |
| 1.2.3 | Deny by Default | Default deny rule | FW-001, FW-002, FW-016 |
| 1.2.4 | Documented Rules | Document firewall rules | FW-001 through FW-016 |
| 1.3.1 | DMZ | Cardholder data in DMZ | FW-010, NET-001, WIFI-003 |
| 1.3.2 | Inbound Traffic | Restrict inbound traffic | FW-001, FW-002, FW-010 |
| 1.3.3 | Private Addresses | Filter private addresses at perimeter | FW-006 |
| 1.3.4 | Internal Addresses | Filter internal addresses | FW-006, FW-014 |
| 1.4.1 | Public Access Restrictions | Control public access | FW-010, FW-011, WIFI-003 |
| 1.5.1 | Anti-Spoofing | Anti-spoofing controls | FW-006, FW-014 |
| 1.5.2 | IP Spoof Detection | Detect IP spoofing | FW-006, FW-014 |
| 1.5.3 | Stateful Inspection | Stateful firewall | FW-003, FW-016 |

### Requirement 2: Standardized Configurations

| PCI DSS v4.0 | Requirement Title | Description | RouterOS Checks |
|--------------|-------------------|-------------|-----------------|
| 2.1.1 | Change Vendor Defaults | Change default passwords/accounts | AUTH-001, AUTH-002 |
| 2.2.1 | Configuration Standards | Security configuration standards | ALL checks |
| 2.2.2 | Insecure Services | Disable insecure services | SRV-001 through SRV-015 |
| 2.2.3 | Encrypt Admin Connections | Encrypt administrative connections | AUTH-005, AUTH-006, AUTH-007, AUTH-008 |
| 2.2.4 | Admin Role Management | Manage admin roles | AUTH-004, AUTH-016 |
| 2.2.5 | Security Parameters | Set security parameters | AUTH-003, AUTH-013 |
| 2.3.1 | Wireless Standards | Wireless security standards | WIFI-001 through WIFI-012 |
| 2.3.2 | Wireless Authentication | Authenticate wireless users | WIFI-001, WIFI-008, WIFI-009 |
| 2.3.3 | Wireless Encryption | Encrypt wireless data | WIFI-001, WIFI-009 |

### Requirement 7: Access Control

| PCI DSS v4.0 | Requirement Title | Description | RouterOS Checks |
|--------------|-------------------|-------------|-----------------|
| 7.1.1 | Access Control System | Implement access control | AUTH-001 through AUTH-016 |
| 7.2.1 | Need-to-Know Access | Restrict to need-to-know | AUTH-004, AUTH-016, SCRIPT-001 |
| 7.2.2 | User ID Requirement | Unique user IDs | AUTH-001, AUTH-015 |
| 7.2.3 | Group Membership | Manage group memberships | AUTH-004, AUTH-015, AUTH-016 |
| 7.2.4 | Revoked Access | Review/revoke access | AUTH-001, AUTH-015 |
| 7.2.5 | Physical Access Controls | Physical security | AUTH-010, AUTH-012 |

### Requirement 8: Authentication

| PCI DSS v4.0 | Requirement Title | Description | RouterOS Checks |
|--------------|-------------------|-------------|-----------------|
| 8.2.1 | Strong Authentication | Use strong authentication | AUTH-003, AUTH-014, WIFI-010 |
| 8.2.2 | Admin Authentication | Admin authentication | AUTH-001, AUTH-003 |
| 8.2.3 | Remote Access Authentication | Authenticate remote access | AUTH-009, AUTH-011, AUTH-014 |
| 8.3.1 | MFA for Remote Access | MFA for remote access | AUTH-011 |
| 8.3.2 | MFA for Non-Console Admin | MFA for admin access | AUTH-011 |
| 8.3.3 | MFA Implementation | Proper MFA implementation | AUTH-011 |
| 8.3.4 | MFA for Administrative Access | MFA for privileged users | AUTH-011 |
| 8.5.1 | Password Complexity | Complex passwords | AUTH-003, AUTH-013 |
| 8.5.2 | Password History | Password history | AUTH-013 |
| 8.5.3 | Password Changes | Regular password changes | AUTH-013 |
| 8.6.1 | Encrypted Session | Session encryption | AUTH-005, AUTH-008 |
| 8.6.2 | Session Lock | Session timeout | AUTH-012 |
| 8.6.3 | Session Identification | Unique session IDs | AUTH-012 |

### Requirement 10: Audit Logging

| PCI DSS v4.0 | Requirement Title | Description | RouterOS Checks |
|--------------|-------------------|-------------|-----------------|
| 10.1.1 | Audit Trail Implementation | Implement audit trails | SYS-004, SYS-005 |
| 10.2.1 | Audit Log Events | Log all relevant events | SYS-004, SYS-005 |
| 10.2.2 | Audit Log Automation | Automated audit trails | SYS-004, SYS-005 |
| 10.3.1 | Log Content | Audit record content | SYS-004, SYS-005 |
| 10.3.2 | User Identification | Log user identity | SYS-004 |
| 10.3.3 | Event Type | Log event type | SYS-004 |
| 10.3.4 | Date/Time Stamp | Log timestamps | SYS-003, SYS-004 |
| 10.4.1 | Time Synchronization | Synchronized system times | SYS-003 |
| 10.4.2 | Time Server | NTP server configuration | SYS-003 |
| 10.4.3 | Acceptable Time Drift | Time drift limits | SYS-003 |
| 10.5.1 | Log Protection | Protect audit logs | SYS-005, SYS-008 |
| 10.5.2 | Immediate Log Backup | Backup logs | SYS-008 |
| 10.7.1 | Log Retention | Retain audit logs | SYS-004, SYS-005, SYS-008 |

### Requirement 11: Testing

| PCI DSS v4.0 | Requirement Title | Description | RouterOS Checks |
|--------------|-------------------|-------------|-----------------|
| 11.4.1 | Network Security Controls Changes | Test firewall rule changes | FW-001 through FW-016 |
| 11.5.1 | Change Detection | Detect unauthorized changes | SYS-009 |
| 11.6.1 | Security Monitoring | Monitor security events | SYS-001, SYS-006, SYS-009 |

### Requirement 12: Policy

| PCI DSS v4.0 | Requirement Title | Description | RouterOS Checks |
|--------------|-------------------|-------------|-----------------|
| 12.3.4 | Security Awareness | Security awareness training | SCRIPT-004, SCRIPT-005 |
| 12.4.1 | Management Review | Management oversight | COMP-001 through COMP-006 |
| 12.5.1 | Security Monitoring | Security continuous monitoring | SYS-001, SYS-006 |
| 12.6.1 | Baseline Configuration Review | Review baseline configs | ALL checks |
| 12.6.2 | Compliance Validation | Validate compliance | COMP-001 through COMP-006 |
| 12.10.1 | Incident Response | Incident response plan | SYS-004, SYS-005 |

---

## 5. MITRE ATT&CK Mapping

MITRE ATT&CK for Enterprise v14 (or later) techniques applicable to RouterOS
device compromise scenarios. Mappings indicate which audit checks detect or
prevent each technique. **Note:** Many techniques detected by RouterOS auditing
are reconnaissance or initial access — lateral movement and exfiltration from a
router typically require host-level detection.

### Reconnaissance (TA0043)

| Technique ID | Name | Description | RouterOS Indicators |
|-------------|------|-------------|-------------------|
| T1046 | Network Service Discovery | Scanning for open services | SRV-006, SRV-014, SRV-015 |
| T1595 | Active Scanning | Active reconnaissance | FW-004, FW-005 |
| T1595.001 | Scanning IP Blocks | Port scanning | FW-004 |
| T1595.002 | Vulnerability Scanning | Service version probing | SRV-001 through SRV-015 |
| T1590 | Gather Victim Network Information | Network topology gathering | SRV-006, ROUTE-006 |
| T1592 | Gather Victim Host Information | Config information gathering | SRV-006, SYS-002, AUTH-005 |

### Resource Development (TA0042)

| Technique ID | Name | Description | RouterOS Indicators |
|-------------|------|-------------|-------------------|
| T1583.001 | Domains | Domain fronting | SRV-003, SRV-004 |
| T1584.001 | Botnet Infrastructure | Device as proxy | SRV-003, SRV-004, SRV-005 |
| T1608.001 | Upload Malware | Malware hosting on router | SYS-007, SCRIPT-001, SCRIPT-006 |

### Initial Access (TA0001)

| Technique ID | Name | Description | RouterOS Indicators |
|-------------|------|-------------|-------------------|
| T1078 | Valid Accounts | Default/weak credentials | AUTH-001, AUTH-002, AUTH-003, AUTH-014 |
| T1078.001 | Default Accounts | Default admin account | AUTH-001, AUTH-002 |
| T1078.003 | Local Accounts | Weak local accounts | AUTH-003, AUTH-013, AUTH-015 |
| T1133 | External Remote Services | VPN/remote access abuse | AUTH-009, AUTH-010, AUTH-012 |
| T1190 | Exploit Public-Facing Application | WAN-accessible services | AUTH-007, AUTH-010, SRV-001 through SRV-013 |
| T1195 | Supply Chain Compromise | Unsigned packages | SYS-007 |
| T1195.001 | Compromise Software Dependencies | RouterOS packages | SYS-007 |
| T1199 | Trusted Relationship | Trusted link abuse | ROUTE-006, NET-007, WIFI-003 |

### Execution (TA0002)

| Technique ID | Name | Description | RouterOS Indicators |
|-------------|------|-------------|-------------------|
| T1059 | Command and Scripting Interpreter | RouterOS script execution | SCRIPT-001 through SCRIPT-007 |
| T1059.001 | Unix Shell | Bash via SSH access | AUTH-005, AUTH-012 |
| T1204 | User Execution | Social engineering on router | SCRIPT-002, SCRIPT-003 |
| T1204.002 | Malicious File | Malicious script import | SCRIPT-001, SCRIPT-002 |

### Persistence (TA0003)

| Technique ID | Name | Description | RouterOS Indicators |
|-------------|------|-------------|-------------------|
| T1098 | Account Manipulation | Backdoor accounts | AUTH-001, AUTH-002, AUTH-015 |
| T1136 | Create Account | Unauthorized user creation | AUTH-001, AUTH-002, AUTH-015 |
| T1136.001 | Local Account | Local user creation | AUTH-015 |
| T1053 | Scheduled Task/Job | RouterOS scheduler | SCRIPT-007 |
| T1053.003 | Cron/At | Scheduled script execution | SCRIPT-007 |
| T1505.003 | Web Shell | WebFig/API backdoor | AUTH-007, AUTH-008, SRV-013 |
| T1554 | Compromise Host Software | RouterOS package backdoor | SYS-007 |

### Privilege Escalation (TA0004)

| Technique ID | Name | Description | RouterOS Indicators |
|-------------|------|-------------|-------------------|
| T1548 | Abuse Elevation Control Mechanism | Privilege abuse | AUTH-004, AUTH-016, SCRIPT-001 |
| T1548.002 | Bypass User Account Control | Policy bypass | AUTH-004, AUTH-016 |

### Defense Evasion (TA0005)

| Technique ID | Name | Description | RouterOS Indicators |
|-------------|------|-------------|-------------------|
| T1562 | Impair Defenses | Disable logging/firewall | FW-008, SYS-004, SYS-005 |
| T1562.004 | Disable or Modify System Firewall | Firewall rule modification | FW-001, FW-008 |
| T1562.006 | Disable or Modify Logging | Disable audit logging | SYS-004, SYS-005 |
| T1070 | Indicator Removal | Log clearing | SYS-004, SYS-005 |
| T1070.001 | Clear Logs | Clear router logs | SYS-004 |
| T1036 | Masquerading | Disguise malicious activity | SCRIPT-005, SCRIPT-007 |
| T1574 | Hijack Execution Flow | Script injection | SCRIPT-001, SCRIPT-005 |
| T1620 | Reflective Code Loading | Dynamic code loading | SCRIPT-005 |

### Credential Access (TA0006)

| Technique ID | Name | Description | RouterOS Indicators |
|-------------|------|-------------|-------------------|
| T1110 | Brute Force | Password brute force | AUTH-011, FW-004 |
| T1110.001 | Password Guessing | Guessing weak passwords | AUTH-003, AUTH-011 |
| T1110.003 | Password Spraying | Password spraying | AUTH-003, AUTH-011 |
| T1110.004 | Credential Stuffing | Credential stuffing | AUTH-003, AUTH-011 |
| T1555 | Credentials from Password Stores | Hardcoded credentials | SCRIPT-002 |
| T1555.005 | RouterOS Configs | Credentials in config exports | SCRIPT-002 |
| T1552 | Unsecured Credentials | Insecure credential storage | SCRIPT-002 |
| T1552.004 | Private Keys | Private key compromise | AUTH-005, AUTH-008 |
| T1040 | Network Sniffing | Unencrypted protocol sniffing | AUTH-006, SRV-008, SRV-009, WIFI-001 |

### Discovery (TA0007)

| Technique ID | Name | Description | RouterOS Indicators |
|-------------|------|-------------|-------------------|
| T1016 | System Network Configuration Discovery | Network discovery | SRV-006, ROUTE-006 |
| T1016.001 | Internet Connection Discovery | WAN address discovery | SRV-006 |
| T1018 | Remote System Discovery | Neighbor discovery | SRV-006, SRV-014 |
| T1049 | System Network Connections Discovery | Connection enumeration | FW-013 |
| T1057 | Process Discovery | Running processes | SYS-001 |
| T1082 | System Information Discovery | RouterOS versioning | SYS-001, SYS-002 |
| T1087 | Account Discovery | User enumeration | AUTH-015 |
| T1087.001 | Local Account | Local user discovery | AUTH-015 |
| T1201 | Password Policy Discovery | Extract password policies | AUTH-003, AUTH-013 |
| T1614 | System Location Discovery | Network location identification | SYS-002 |

### Lateral Movement (TA0008)

| Technique ID | Name | Description | RouterOS Indicators |
|-------------|------|-------------|-------------------|
| T1021 | Remote Services | Remote service access | AUTH-006, AUTH-007, AUTH-009, AUTH-010, SRV-008, SRV-009 |
| T1021.001 | Remote Desktop | WinBox access | AUTH-006, AUTH-007 |
| T1021.002 | SMB/Windows Admin Shares | SMB share access | SRV-012 |
| T1021.004 | SSH | SSH lateral movement | AUTH-005, AUTH-012 |
| T1021.005 | VNC | VNC service | (Not native to RouterOS) |
| T1570 | Lateral Tool Transfer | Script transfer | SRV-009, SCRIPT-001 |

### Collection (TA0009)

| Technique ID | Name | Description | RouterOS Indicators |
|-------------|------|-------------|-------------------|
| T1005 | Data from Local System | Config data access | SCRIPT-001 |
| T1074 | Data Staged | Temporary data storage | SCRIPT-006 |
| T1119 | Automated Collection | Log collection | SYS-005 |
| T1560 | Archive Collected Data | Compressed data export | SCRIPT-006 |

### Command and Control (TA0011)

| Technique ID | Name | Description | RouterOS Indicators |
|-------------|------|-------------|-------------------|
| T1071 | Application Layer Protocol | C2 via standard ports | SRV-001, SRV-003, SRV-004, FW-010 |
| T1071.001 | Web Protocols | HTTP/HTTPS C2 | SRV-003, SRV-013 |
| T1071.004 | DNS | DNS tunneling | SRV-001, NET-004 |
| T1090 | Proxy | Proxy for C2 routing | SRV-003, SRV-004, SRV-005 |
| T1090.002 | External Proxy | Open proxy | SRV-003, SRV-004 |
| T1090.003 | Multi-hop Proxy | SOCKS proxy chain | SRV-004 |
| T1095 | Non-Application Layer Protocol | Raw TCP/UDP C2 | FW-010, FW-011 |
| T1102 | Web Service | Cloud services C2 | SRV-011 |
| T1132 | Data Encoding | Protocol encoding | FW-003 |
| T1205 | Traffic Signaling | Port knocking (legitimate) | FW-009 |
| T1571 | Non-Standard Port | Non-standard service ports | FW-010, FW-011 |
| T1572 | Protocol Tunneling | VPN tunneling abuse | AUTH-009, AUTH-010 |
| T1573 | Encrypted Channel | Encrypted C2 | AUTH-005, WIFI-001 |

### Exfiltration (TA0010)

| Technique ID | Name | Description | RouterOS Indicators |
|-------------|------|-------------|-------------------|
| T1020 | Automated Exfiltration | Automated data exfiltration | SCRIPT-006, SCRIPT-007 |
| T1041 | Exfiltration Over C2 Channel | Exfil over existing channel | FW-010, FW-011 |
| T1567 | Exfiltration Over Web Service | Exfil via web | SRV-003, SRV-013 |
| T1537 | Transfer Data to Cloud Account | MikroTik cloud exfil | SRV-011 |

### Impact (TA0040)

| Technique ID | Name | Description | RouterOS Indicators |
|-------------|------|-------------|-------------------|
| T1498 | Network Denial of Service | DoS from compromised router | FW-004, FW-005, FW-013, FW-015 |
| T1498.001 | Direct Network Flood | Direct DoS attacks | FW-004, FW-005 |
| T1498.002 | Reflection Amplification | DNS/NTP amplification | SRV-001 |
| T1499 | Endpoint Denial of Service | Resource exhaustion | FW-013, SYS-009 |
| T1499.001 | OS Exhaustion Flood | Connection table exhaustion | FW-013 |
| T1496 | Resource Hijacking | Cryptocurrency mining via compromised device | SCRIPT-001, SCRIPT-006, SYS-007 |
| T1499.003 | Application Exhaustion Flood | Service DoS | FW-004 |
| T1485 | Data Destruction | RouterOS reset | SCRIPT-006 |
| T1489 | Service Stop | Stop router services | SCRIPT-006 |
| T1531 | Account Access Removal | Account deletion | AUTH-015 |

---

## 6. CVSS v3.1 Scoring Guide

RouterOS audit findings are scored using CVSS v3.1, adapted for offline
configuration assessment. The **Modified** scoring approach is used: base
metrics are assigned from the configuration context, but temporal and
environmental metrics are **omitted** (they require live knowledge of the
deployed environment).

### Base Metrics

#### Attack Vector (AV)

| Value | Description | When Applied |
|-------|-------------|--------------|
| **N** (Network) | Exploitable remotely across the network | Service exposed on WAN, default credentials, remote protocol vulnerabilities |
| **A** (Adjacent) | Exploitable from local network segment | Internal service exposure, bridge-level attacks, WiFi range |
| **L** (Local) | Requires local/console access | Physical access findings, file system exposure |
| **P** (Physical) | Requires physical manipulation | LCD interface findings, reset button exposure |

**Special rule for offline config audit:** When analyzing offline .rsc exports,
AV is scored based on the _intended_ network position inferred from the
configuration. If a config shows a WAN-facing interface without restrictions,
score as AV:N. For management-plane services bound to internal interfaces only,
score as AV:A.

#### Attack Complexity (AC)

| Value | Description | When Applied |
|-------|-------------|--------------|
| **L** (Low) | No special conditions for exploit | Open service, default credentials, no rate limiting |
| **H** (High) | Special conditions required | Port knocking required, complex exploitation path |

#### Privileges Required (PR)

| Value | Description | When Applied |
|-------|-------------|--------------|
| **N** (None) | No authentication required | Open resolver, unauthenticated service |
| **L** (Low) | Low-privilege user access | Non-admin script execution, read-only access |
| **H** (High) | Administrative privileges required | Destructive script findings, sensitive config exposure |

#### User Interaction (UI)

| Value | Description | When Applied |
|-------|-------------|--------------|
| **N** (None) | No user interaction | Automated attacks, service scanning |
| **R** (Required) | User action needed | Clickjacking, social engineering via scripts |

#### Scope (S)

| Value | Description | When Applied |
|-------|-------------|--------------|
| **U** (Unchanged) | Impact within the device | Most configuration weaknesses |
| **C** (Changed) | Impact across trust boundaries | Router used as pivot, VPN access to internal nets |

#### Impact Metrics

| Metric | Value | Description |
|--------|-------|-------------|
| **C** (Confidentiality) | H / L / N | H: full config/credential exposure; L: information leak; N: no data access |
| **I** (Integrity) | H / L / N | H: config can be modified; L: limited modification; N: no integrity impact |
| **A** (Availability) | H / L / N | H: device can be disabled; L: degraded performance; N: no availability impact |

### CVSS Vector Examples for Common RouterOS Weaknesses

| Finding | Vector String | Score | Severity |
|---------|--------------|-------|----------|
| Default admin user enabled, no password | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 | Critical |
| Default admin user with password | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | 9.9 | Critical |
| DNS resolver open on WAN | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` | 5.3 | Medium |
| SNMP v2c public community | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` | 8.3 | High |
| Weak SSH crypto (pubkey < 2048 bits) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | 5.9 | Medium |
| Telnet enabled on WAN | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 | High |
| No firewall filtering rules on WAN | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 | Critical |
| No brute-force protection | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 | Medium |
| WEP encryption on WiFi | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 7.6 | High |
| Hardcoded credentials in script | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 7.8 | High |
| Open proxy on WAN | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N` | 7.2 | High |
| SNMP write community (set) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical |
| SMB service enabled internally | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 4.3 | Medium |
| UPnP enabled on WAN | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L` | 9.0 | Critical |
| NTP not configured | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | 5.3 | Medium |
| No remote syslog | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | 5.3 | Medium |

### Modified Scoring for Offline Configuration Audits

When scoring findings from an offline `.rsc` export without live context,
apply these modifications:

| Metric | Modification Rule |
|--------|------------------|
| **AV** | Infer from `/ip address` interface assignments. If config lacks explicit WAN-ACL, assume AV:N for services on public IPs. |
| **PR** | Do not assume admin account is compromised unless default credentials exist. |
| **S** | Assume Scope:Unchanged unless there is evidence of NAT, VPN, or bridging that would make the device a pivot point. |
| **E** (Exploitability) | NOT used — no live context. Findings are scored as if no proof-of-concept exists (base score only). |
| **RL** (Remediation Level) | NOT used — remediation is provided auditor-side. |
| **RC** (Report Confidence) | NOT used — the auditor implicitly confirms the finding by presenting it. |

### Severity Table

| Score Range | Severity | Color | Action |
|-------------|----------|-------|--------|
| 9.0–10.0 | **Critical** | Red (#ff4444) | Immediate remediation |
| 7.0–8.9 | **High** | Orange (#ff8800) | Remediate as soon as possible |
| 4.0–6.9 | **Medium** | Yellow (#ffaa00) | Schedule for next maintenance |
| 0.1–3.9 | **Low** | Blue (#44aaff) | Informational / best practice |
| 0.0 | **Info** | Gray (#888888) | Reference only |

---

## 7. Compliance Matrix — Consolidated Per-Check Mapping

The table below maps every audit check to its associated CIS, NIST, ISO, and
PCI-DSS controls. Checks are organized by category prefix.

### AUTH — Authentication & Access Control (18 checks)

| Check ID | Check Summary | CIS | NIST SP 800-53 | ISO 27001:2022 | PCI DSS v4.0 |
|----------|---------------|-----|----------------|----------------|--------------|
| AUTH-001 | Default admin user enabled | 1.1, 8.1 | AC-2, IA-2, IA-5 | A.5.18, A.8.3 | 2.1.1, 7.2.2, 7.2.4, 8.2.2 |
| AUTH-002 | Default group with full permissions | 1.1, 8.1 | AC-2, AC-6, IA-4 | A.5.18, A.8.3 | 2.1.1 |
| AUTH-003 | Weak/no password or low complexity | 7.2 | IA-5, IA-5(1) | A.8.5 | 8.2.1, 8.5.1, 8.2.2 |
| AUTH-004 | User group policy — least privilege | 1.2, 7.1 | AC-3, AC-6, CM-5 | A.5.2, A.5.15, A.8.4 | 1.1.4, 2.2.4, 7.2.1, 7.2.3 |
| AUTH-005 | SSH weak crypto ( < 2048-bit RSA, weak ciphers) | 1.2, 7.3 | IA-7, SC-8, SC-13 | A.8.17 | 2.2.3, 8.6.1 |
| AUTH-006 | MAC-telnet/winbox/ping enabled | 1.2 | AC-17, SC-8, MA-3 | A.8.1, A.8.17 | 2.2.3 |
| AUTH-007 | WinBox/API exposed on WAN | 1.2 | AC-17, SC-7(3) | A.8.22 | 2.2.3 |
| AUTH-008 | API SSL not enforced | 1.2, 7.3 | SC-8, SC-8(1) | A.8.17 | 2.2.3, 8.6.1 |
| AUTH-009 | RoMON enabled | 1.2, 16.1 | AC-17, AC-20, SC-7(7) | A.5.14, A.5.20, A.8.22 | 8.2.3 |
| AUTH-010 | MAC-services on WAN interfaces | 1.2, 3.2, 14.2 | AC-20, MA-3, AC-17, SC-7(3) | A.8.1, A.8.12, A.8.22 | 7.2.5 |
| AUTH-011 | Login restrictions missing / no brute-force protection | 7.2 | AC-7, AC-10, IA-2(1), IA-5 | A.8.5 | 8.3.1, 8.3.2, 8.3.3, 8.3.4 |
| AUTH-012 | IP services not bound to specific interfaces | 1.2, 14.2 | AC-11, AC-17, SC-10 | A.8.22 | 7.2.5, 8.6.2, 8.6.3 |
| AUTH-013 | Password aging / change policy not configured | 7.2 | IA-5, IA-5(1) | A.8.5 | 8.5.2, 8.5.3, 2.2.5 |
| AUTH-014 | RADIUS/AAA not configured | 7.1 | AC-2(1), IA-5, AUTH-014 | A.8.5 | 8.2.1, 8.2.3 |
| AUTH-015 | User enumeration / unmanaged accounts | 8.2 | AC-2, AC-2(2), IA-2, IA-4 | A.5.18, A.8.3 | 7.2.2, 7.2.4 |
| AUTH-016 | No explicit allow policy (ACL-based access) | 1.2, 7.1 | AC-3, AC-6, CM-5 | A.5.2, A.5.15, A.8.4 | 1.1.4, 2.2.4, 7.2.1, 7.2.3 |

### SRV — Service Hardening (17 checks)

| Check ID | Check Summary | CIS | NIST SP 800-53 | ISO 27001:2022 | PCI DSS v4.0 |
|----------|---------------|-----|----------------|----------------|--------------|
| SRV-001 | DNS open resolver (allows third-party queries) | 3.1, 3.2, 9.1 | SC-20, SC-22, SI-4 | A.8.12, A.8.20 | — |
| SRV-002 | Bandwidth server enabled | 3.1 | CM-7, CM-7(1) | A.8.20 | 2.2.2 |
| SRV-003 | Web proxy enabled (unauthenticated) | 3.1 | SC-15, CM-7 | A.8.23, A.8.20 | 2.2.2 |
| SRV-004 | SOCKS proxy enabled | 3.1 | SC-15, CM-7 | A.8.20 | 2.2.2 |
| SRV-005 | UPnP enabled | 3.1 | SC-15, CM-7 | A.8.20 | 2.2.2 |
| SRV-006 | Neighbor discovery enabled on WAN | 3.3 | CM-7, CM-7(1) | A.8.20 | 2.2.2 |
| SRV-007 | SNMP v1/v2c with public community | 3.1, 9.1, 9.2 | CM-7 | A.8.12, A.8.20 | 2.2.2 |
| SRV-008 | Telnet service enabled | 3.1 | CM-7 | A.8.20 | 2.2.2 |
| SRV-009 | FTP service enabled | 3.1 | CM-7 | A.8.20 | 2.2.2 |
| SRV-010 | PPTP VPN service enabled | 3.1 | CM-7, AC-17 | A.8.20, A.8.22 | 2.2.2 |
| SRV-011 | MikroTik Cloud services enabled | 3.1 | AC-20, SC-7(3) | A.5.20, A.5.23 | 2.2.2 |
| SRV-012 | SMB service enabled | 3.1 | CM-7 | A.8.20 | 2.2.2, 1.3.2 |
| SRV-013 | WebFig HTTP enabled (not HTTPS) | 3.1 | CM-7, SC-8 | A.8.20 | 2.2.2, 2.2.3 |
| SRV-014 | IPv6 neighbor discovery not restricted | 3.3 | CM-7, CM-7(1) | A.8.20 | 2.2.2 |
| SRV-015 | Interface ACLs not applied to services | — | CM-7, CM-8 | A.8.20 | 2.2.2 |

### FW — Firewall & Network Security (17 checks)

| Check ID | Check Summary | CIS | NIST SP 800-53 | ISO 27001:2022 | PCI DSS v4.0 |
|----------|---------------|-----|----------------|----------------|--------------|
| FW-001 | Default firewall rules (fasttrack + drop) missing | 4.1, 4.2, 1.2.3 | AC-4, SC-7, SI-4(4) | A.8.20, A.8.27 | 1.1.1, 1.1.3, 1.2.1, 1.2.3, 1.3.2 |
| FW-002 | No WAN-side default drop rule | 4.1, 4.2, 1.2.3 | AC-4, SC-7, SC-7(5) | A.8.20 | 1.1.1, 1.1.3, 1.2.1, 1.2.3, 1.3.2 |
| FW-003 | No connection-tracking established/related rule | 4.2 | SC-7, SI-10 | A.8.20 | 1.2.2, 1.5.3 |
| FW-004 | Brute-force protection / port scan detection missing | 4.2, 10.2 | SC-21, SC-22, SI-4 | A.8.20 | 1.2.1 |
| FW-005 | ICMP rate limiting not configured | 4.2, 10.2 | SC-21, SC-7 | A.8.20 | 1.2.1 |
| FW-006 | RAW table — no bogon/anti-spoofing filters | 4.3, 4.4 | SI-10, SC-7, AC-4 | A.8.20 | 1.3.3, 1.3.4, 1.5.1, 1.5.2 |
| FW-007 | IPv6 firewall rules missing | 4.3 | SC-7, SC-7(5) | A.8.20 | 1.1.1, 1.2.1 |
| FW-008 | FastTrack enabled (bypasses connection tracking) | — | CM-7 | A.8.20 | — |
| FW-009 | Port knocking not configured (when expected) | — | AC-4, SC-7 | A.5.14 | — |
| FW-010 | Unrestricted WAN access to router services | 4.1, 4.2, 14.2 | SC-7, SC-7(3), SI-4(4) | A.8.12, A.8.21, A.8.23, A.8.27 | 1.2.1, 1.3.1, 1.3.2, 1.4.1 |
| FW-011 | DSTNAT rules without access restrictions | 4.2 | SC-7, AC-4 | A.8.20 | 1.4.1 |
| FW-012 | Broadcast blocking not configured | 4.1, 4.2 | SC-7, AC-4 | A.8.20 | 1.2.1 |
| FW-013 | Connection tracking limits not configured | 4.2, 10.1 | SC-21, SC-7 | A.8.6 | — |
| FW-014 | RAW table default policy not set to drop | 4.1, 4.4 | SI-10, AC-4, SC-7 | A.8.20 | 1.3.4, 1.5.1, 1.5.2 |
| FW-015 | SYN flood protection not configured | 4.2, 10.2 | SC-21, SC-7 | A.8.20 | 1.2.1 |
| FW-016 | Firewall rules default action accept | 4.2, 1.2.3 | AC-4, SC-7(5), SI-4(4) | A.8.20 | 1.1.3, 1.2.2, 1.2.3, 1.5.3 |

### SYS — System Hardening (10 checks)

| Check ID | Check Summary | CIS | NIST SP 800-53 | ISO 27001:2022 | PCI DSS v4.0 |
|----------|---------------|-----|----------------|----------------|--------------|
| SYS-001 | RouterOS version — known CVEs | 11.2 | RA-5, SI-2, SI-3, RA-3 | A.5.7, A.8.7, A.8.8 | 11.6.1, 12.5.1 |
| SYS-002 | System identity / banner not configured | 2.1 | AC-8, PL-4 | A.5.10 | — |
| SYS-003 | NTP not configured | 5.2 | AU-8 | A.8.16 | 10.4.1, 10.4.2, 10.4.3 |
| SYS-004 | Local logging not configured | 5.1, 5.3 | AU-3, AU-12, SI-4 | A.8.15, A.5.25 | 10.1.1, 10.2.1, 10.2.2, 10.3.1, 10.3.2, 10.3.3, 10.3.4, 10.7.1 |
| SYS-005 | Remote syslog not configured | 5.1, 5.3 | AU-2, AU-3, AU-3(1), AU-6, AU-7, AU-9, AU-11, AU-12, AU-14, SI-4 | A.8.15, A.5.25 | 10.1.1, 10.2.1, 10.2.2, 10.5.1, 10.7.1 |
| SYS-006 | Software update channel not set to stable/long-term | 11.2 | RA-5, SI-2, SI-3 | A.5.7, A.8.7, A.8.8 | 11.6.1, 12.5.1 |
| SYS-007 | Unsigned packages allowed | 11.2 | SI-7, SI-2, SA-8 | A.8.7, A.8.8 | — |
| SYS-008 | Support output file / audit trail not exportable | 5.3, 15.1 | AU-4, AU-5, AU-9, AU-11 | A.8.15 | 10.5.1, 10.5.2, 10.7.1 |
| SYS-009 | Backup configuration not scheduled | 15.1, 18.1 | CM-3, CP-9, CP-9(1), CP-10, SI-7(1) | A.5.8, A.5.29, A.8.6, A.8.13, A.8.18 | 11.5.1, 12.5.1 |

### NET — Network Configuration (9 checks)

| Check ID | Check Summary | CIS | NIST SP 800-53 | ISO 27001:2022 | PCI DSS v4.0 |
|----------|---------------|-----|----------------|----------------|--------------|
| NET-001 | Bridge VLAN filtering mode not enabled | 14.2 | SC-7, CM-2 | A.8.21, A.8.27 | 1.3.1 |
| NET-002 | DHCP server security (no lease limit, no trusted ports) | 14.1 | IA-3, SI-10 | A.8.20 | — |
| NET-003 | DHCP lease file on flash-constrained device | 14.1 | AU-4, CM-2 | A.7.14 | — |
| NET-004 | DNS cache poisoning mitigation missing | 14.1 | SC-20, SC-21 | A.8.20 | — |
| NET-005 | MTU mismatch on bridge/tunnel links | — | SC-7 | A.8.6 | — |
| NET-006 | Unused interfaces not disabled | 1.1 | CM-7, CM-8 | A.8.20 | — |
| NET-007 | VRRP/VRRP HA authentication not configured | 6.1 | SC-12, CM-3 | A.8.14, A.8.20 | — |
| NET-008 | hAP ac² offload settings not optimized | — | CM-2 | A.8.6 | — |

### ROUTE — Routing Security (9 checks)

| Check ID | Check Summary | CIS | NIST SP 800-53 | ISO 27001:2022 | PCI DSS v4.0 |
|----------|---------------|-----|----------------|----------------|--------------|
| ROUTE-001 | BGP MD5 authentication not configured | 6.1 | SC-12, IA-3 | A.8.20 | — |
| ROUTE-002 | OSPF authentication not configured | 6.1 | SC-12, IA-3 | A.8.20 | — |
| ROUTE-003 | BGP routing filters (prefix-lists/filters) missing | 6.2 | SC-7, AC-4 | A.8.20 | 1.3.3, 1.3.4 |
| ROUTE-004 | BGP TTL security (GTSM) not configured | 6.4 | AC-3, SC-7 | A.8.20 | — |
| ROUTE-005 | BGP prefix limits not configured | 6.2 | SI-10, CM-2 | A.8.6, A.8.14 | — |
| ROUTE-006 | Dynamic routing enabled on WAN interface | 6.3 | SC-7(4), SC-7 | A.5.14, A.8.20 | — |
| ROUTE-007 | No default route resilience | — | CP-10 | A.8.14 | — |
| ROUTE-008 | Loopback router ID not configured | — | CM-2 | A.8.20 | — |

### WIFI — WiFi Security (13 checks)

| Check ID | Check Summary | CIS | NIST SP 800-53 | ISO 27001:2022 | PCI DSS v4.0 |
|----------|---------------|-----|----------------|----------------|--------------|
| WIFI-001 | Insecure encryption (WEP/TKIP) | 13.1 | AC-18(1), SC-8, SC-13 | A.8.17, A.8.20 | 2.3.1, 2.3.2, 2.3.3 |
| WIFI-002 | WPS enabled | 13.1 | AC-18, IA-3 | A.8.20 | 2.3.1 |
| WIFI-003 | Guest network not isolated (corp network access) | 13.1 | AC-18(3), SC-7 | A.8.21 | 1.3.1, 1.4.1 |
| WIFI-004 | Hidden SSID (security-through-obscurity) | 13.1 | AC-18 | A.8.20 | 2.3.1 |
| WIFI-005 | Per-band security settings inconsistent | 13.1 | AC-18 | A.8.20 | 2.3.1 |
| WIFI-006 | Client isolation not enabled (public networks) | 13.1 | AC-18(3) | A.8.21 | 2.3.1 |
| WIFI-007 | CAPsMAN encryption not enforced | 13.1 | AC-18, SC-8 | A.8.17, A.8.20 | 2.3.1 |
| WIFI-008 | No MAC access list restrictions | 13.1 | AC-18, IA-3 | A.8.20 | 2.3.2 |
| WIFI-009 | PMF (Protected Management Frames) not enabled | 13.1 | AC-18(1), IA-3 | A.8.20, A.8.17 | 2.3.2, 2.3.3 |
| WIFI-010 | Weak WiFi password (< 8 chars, low entropy) | 13.1 | IA-5, AC-18(1) | A.8.5 | 8.2.1 |
| WIFI-011 | DFS radar handling not confirmed | — | CM-2 | A.8.20 | — |
| WIFI-012 | hAP ac² flash crisis (WiFi RAM overflow) | — | AU-4, CP-9 | A.8.6 | — |

### SCRIPT — Script & Automation (8 checks)

| Check ID | Check Summary | CIS | NIST SP 800-53 | ISO 27001:2022 | PCI DSS v4.0 |
|----------|---------------|-----|----------------|----------------|--------------|
| SCRIPT-001 | Script with excessive permissions (admin-level) | 17.1 | AC-6, CM-5 | A.8.4, A.8.24, A.8.25, A.8.30 | 7.2.1 |
| SCRIPT-002 | Hardcoded credentials in script | 17.1 | IA-5(6), SI-10 | A.8.11, A.8.24, A.8.25, A.8.28, A.8.30, A.8.33 | — |
| SCRIPT-003 | Single-instance guard missing | 17.1 | SA-8 | A.8.24, A.8.25, A.8.31 | — |
| SCRIPT-004 | Error handling absent from script | 17.1 | AT-3, SI-10 | A.6.3, A.8.24, A.8.26, A.8.28 | 12.3.4 |
| SCRIPT-005 | Global variable pollution in script | 17.1 | SI-12, AT-3 | A.6.3, A.8.24, A.8.25, A.8.28 | 12.3.4 |
| SCRIPT-006 | Destructive commands (format/reset/delete) in script | 17.1 | SI-12, SC-7 | A.8.10, A.7.9, A.8.19, A.8.24, A.8.25 | — |
| SCRIPT-007 | Scheduler task security (overprivileged) | 17.1 | CM-3, SA-8 | A.5.8, A.8.18, A.8.24, A.8.25, A.8.32 | — |

### COMP — Compliance Mapping (6 info checks)

| Check ID | Check Summary | CIS | NIST SP 800-53 | ISO 27001:2022 | PCI DSS v4.0 |
|----------|---------------|-----|----------------|----------------|--------------|
| COMP-001 | CIS crosswalk summary | — | CM-2(1), CA-2 | A.5.1, A.5.29, A.5.36 | 12.4.1, 12.6.2 |
| COMP-002 | NIST SP 800-53 mapping | — | CM-2(1), CA-2 | A.5.1, A.5.36 | 12.4.1, 12.6.2 |
| COMP-003 | ISO 27001 mapping | — | CM-2(1), CA-2 | A.5.1, A.5.29, A.5.36 | 12.4.1, 12.6.2 |
| COMP-004 | PCI-DSS mapping | — | CM-2(1), CA-2 | A.5.1, A.5.36 | 12.4.1, 12.6.2 |
| COMP-005 | MITRE ATT&CK mapping | — | RA-3, CA-2 | A.5.7, A.8.8 | 12.5.1 |
| COMP-006 | CVSS scoring reference | — | RA-3, CM-2(1) | A.5.1, A.8.9 | 12.6.2 |

---

## 8. Compliance Coverage Summary

### Per-Category Coverage Count

| Category | Checks | CIS | NIST | ISO | PCI DSS |
|----------|--------|-----|------|-----|---------|
| AUTH | 18 | 13 | 16 | 10 | 15 |
| SRV | 17 | 3 | 3 | 3 | 2 |
| FW | 17 | 11 | 11 | 3 | 16 |
| SYS | 10 | 5 | 22 | 16 | 16 |
| NET | 9 | 3 | 6 | 7 | 1 |
| ROUTE | 9 | 4 | 7 | 6 | 1 |
| WIFI | 13 | 2 | 10 | 9 | 5 |
| SCRIPT | 8 | 2 | 8 | 16 | 1 |
| COMP | 6 | 0 | 3 | 5 | 3 |
| **Total** | **107** | **43** | **86** | **75** | **60** |

### Framework Coverage Gaps

These aspects of each framework are **not** directly addressable by offline
RouterOS configuration auditing:

| Framework | Gap Area | Reason |
|-----------|----------|--------|
| **CIS** | Physical security controls (1.1) | Offline config audit |
| **CIS** | Security awareness / training | People-process controls |
| **NIST** | Physical security (PE family) | Offline config audit |
| **NIST** | Personnel security (PS family) | People-process controls |
| **NIST** | Contingency planning (CP family) | Requires operational procedures |
| **ISO** | Leadership / policy (Clause 5) | Requires organizational evidence |
| **ISO** | People controls (Clause 6) | Requires training records |
| **ISO** | Supplier relationships (5.19-5.21) | Requires contractual evidence |
| **PCI DSS** | Physical security (Req 9) | Requires on-site inspection |
| **PCI DSS** | Cardholder data processes (Req 3-6) | Usually not processed by router |
| **MITRE** | Post-exploitation lateral movement | Requires host-level telemetry |
| **MITRE** | Exfiltration detection | Requires traffic inspection |

---

## 9. Automated Compliance Report Suggestions

When generating compliance reports from audit results, structure the output
by framework:

```yaml
compliance:
  cis:
    version: "CIS Network Infrastructure Benchmark v3.0 (crosswalk)"
    total_controls_mapped: 41
    findings_by_control: { "1.1": ["AUTH-001", "AUTH-002", "NET-006"], ... }
    score: 85  # percentage of applicable controls satisfied
  nist:
    version: "SP 800-53 Rev 5"
    total_controls_mapped: 93
    findings_by_family:
      AC: { total: 14, passed: 11, failed: 3 }
      AU: { total: 11, passed: 8, failed: 3 }
      CM: { total: 11, passed: 9, failed: 2 }
      IA: { total: 8, passed: 5, failed: 3 }
      SC: { total: 19, passed: 14, failed: 5 }
      SI: { total: 8, passed: 6, failed: 2 }
  iso:
    version: "ISO 27001:2022"
    total_controls_mapped: 75
  pci:
    version: "PCI DSS v4.0"
    total_requirements_mapped: 60
```

---

## 10. References

- CIS Benchmarks: <https://www.cisecurity.org/cis-benchmarks/>
- NIST SP 800-53 Rev 5: <https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final>
- ISO 27001:2022: <https://www.iso.org/standard/27001>
- PCI DSS v4.0: <https://www.pcisecuritystandards.org/document_library/>
- MITRE ATT&CK: <https://attack.mitre.org/>
- CVSS v3.1 Specification: <https://www.first.org/cvss/specification-document>
- NIST SP 800-77 (IPsec VPN): <https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final>
- NIST SP 800-97 (Wireless): <https://csrc.nist.gov/publications/detail/sp/800-97/final>
- NIST SP 800-41 (Firewalls): <https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final>
- MikroTik RouterOS Manual: <https://help.mikrotik.com/docs/>

---

*Generated for the MikroTik RSC Auditor skill. All mappings are crosswalks
and should be validated against organizational compliance requirements and
the specific framework version in use.*
