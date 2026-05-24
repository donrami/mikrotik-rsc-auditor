---
description: >-
  Secure configuration baseline for MikroTik RouterOS devices. Service-by-service
  safe defaults, firewall architecture, user management, WiFi security, hAP-specific
  constraints, and hardening verification commands.
---

# Security Baseline Reference

## 1. Authentication & User Management

### 1.1 Admin User Hardening

The default `admin` account is a well-known target. It MUST be renamed or removed, and a new full-admin account created with IP restrictions.

```
/user set admin disabled=yes
/user add name=operator group=full address=192.168.88.0/24
/user set [find name=admin] disabled=yes comment="default admin disabled"
```

When additional privilege separation is needed, duplicate the `full` group policy and strip unnecessary permissions.

```
/user group add name=admin-hardened policy=\
    local,otp,read,write,policy,test,winbox,password,\
    web,sniff,sensitive,reboot,dude,telnet,ssh
# Then remove directly-granted policies that should go through sudo-style elevation
/user group set [find name=admin-hardened] policy=ssh,winbox,read,write
```

### 1.2 Password Policy

RouterOS supports password complexity enforcement only through administrative discipline — there is no native password complexity module. The baseline enforces:

| Requirement | Standard |
|---|---|
| Minimum length | 12 characters |
| Character classes | upper, lower, digit, symbol (≥3 of 4) |
| Dictionary words | Prohibited |
| Default/blank passwords | Forbidden — checked on `user` and `snmp-community` entries |
| Password change interval | 90 days (organizational policy — track externally) |
| Reuse prevention | 5 previous passwords (organizational policy — track externally) |

### 1.3 SSH Hardening

```
/ip ssh set strong-crypto=yes forwarding-enabled=no
/ip ssh set host-key-size=4096
/ip ssh set always-allow-password-login=no
/ip service set ssh port=2222 address=192.168.88.0/24
```

If host keys use SHA-1 signatures, regenerate:

```
/ip ssh remove-host-key [find]
/ip ssh regenerate-host-key
```

Verify SSH cipher and MAC negotiation:

```
/ip ssh print
/ip ssh show-identity
```

### 1.4 User Groups & Least Privilege

Define purpose-specific groups rather than using only `read` and `write`.

```
/user group add name=monitor policy=read,local,telnet,ssh,winbox
/user group add name=neteng policy=read,write,local,telnet,ssh,winbox,sniff,password,test
/user group add name=backup policy=read,local,ssh,ftp,api
```

Policy guidelines:

- `full` — reserved for < 3 authorized administrators, each with IP binding
- `read` — read-only monitoring, SNMP query access
- `write` — network operations (no `policy` or `reboot`)
- No user should have `policy` without individual `address` restriction
- Remove `telnet` and `ftp` from every group policy if the services are disabled

### 1.5 Login Restrictions Per User

Bind every administrative user to a management subnet:

```
/user set [find name=operator] address=10.0.0.0/24
/user set [find name=neteng] address=10.0.0.0/24
```

Users without an `address` set can authenticate from any reachable interface. The management subnet SHOULD be a dedicated VLAN with strict ACLs permitting only jumpbox IPs.

### 1.6 MAC-Based Services

RouterOS exposes MAC-telnet, MAC-winbox, and MAC-ping through `/tool mac-server`. These bypass IP ACLs and MUST be restricted.

```
/tool mac-server set allowed-interface-list=none
/tool mac-server ping set enabled=no
/tool mac-winbox set allowed-interface-list=none
```

---

## 2. Service Management

### 2.1 Service State Matrix

| Service | Default State | Secure State | Notes |
|---|---|---|---|
| SSH | enabled | enabled, strong-crypto, mgmt ACL | Port change optional; disable password auth |
| WinBox | enabled | restricted to LAN ACL | Port change optional; avoid WAN exposure |
| API | disabled | disabled or api-ssl only | Never expose on WAN; API-SSL with cert |
| Telnet | enabled | **DISABLED** | Complete replacement by SSH |
| FTP | enabled | **DISABLED** | Use SCP/SFTP via SSH |
| WWW | enabled | **DISABLED** or redirected to HTTPS | HTTP is cleartext; redirect chain only |
| WWW-SSL | disabled | enabled with valid cert | Use Let's Encrypt or self-signed for LAN mgmt |
| SNMP | enabled | **DISABLED** or SNMPv3 only | Never v1/v2c; community strings are shared keys |
| DNS | enabled | `allow-remote-requests=no` | Local caching only |
| BGP | disabled | per-ASN controlled | Route filtering mandatory |
| SOCKS | disabled | **DISABLED** | Proxied traffic hides source completely |
| UPnP | disabled | **DISABLED** | Internal network vulnerability |
| Neighbor Discovery | enabled | disabled on WAN interfaces | CDP/LLDP leak network topology |
| Bandwidth Server | enabled | **DISABLED** | DoS vector; no legitimate use outside testing |

### 2.2 Service Binding Enforcement

Every enabled service MUST have an explicit `address` restriction scoped to the minimum required subnet.

```
/ip service set ssh address=10.0.0.0/24
/ip service set winbox address=192.168.88.0/24,10.0.0.0/24
/ip service set api-ssl address=10.0.0.0/24
```

Services that cannot be bound to a specific subnet must be protected via firewall rules in the input chain (see Section 3).

### 2.3 Cloud Service

RouterOS Cloud services route traffic through MikroTik's infrastructure. Unless required for DDNS or remote management, disable:

```
/ip cloud set ddns-enabled=no ddns-update-interval=none
/ip cloud set update-time=no
```

If DDNS is required for VPN endpoint discovery, keep `ddns-enabled=yes` but disable update-time and restrict firewall access to the DDNS domain.

---

## 3. Firewall Architecture

### 3.1 Chain Structure and Responsibilities

MikroTik RouterOS uses four firewall tables, each with built-in chains:

```
                    ┌──────────┐
                    │   RAW    │
                    │──────────│
                    │prerouting│ interface/connection-based filtering
                    │  output  │  before conntrack
                    └──────────┘
                          │
                    ┌──────┴──────┐
                    ▼             ▼
              ┌──────────┐  ┌──────────┐
              │  FILTER  │  │  MANGLE  │
              │──────────│  │──────────│
              │  input   │  │prerouting│
              │ forward  │  │  input   │
              │  output  │  │ forward  │
              └──────────┘  │  output  │
                    │       │postrout.│
              ┌─────┘       └──────────┘
              ▼
        ┌──────────┐
        │   NAT    │
        │──────────│
        │ dstnat   │  before routing decision
        │ srcnat   │  after routing decision
        └──────────┘
```

| Table | Chain | Purpose |
|---|---|---|
| RAW | prerouting | Connection tracking bypass — bogon and DDoS filtering before state table |
| RAW | output | Router-originated traffic bypass (e.g., router itself to upstream) |
| FILTER | input | Traffic destined to the router itself (service protection) |
| FILTER | forward | Traffic traversing the router between networks |
| FILTER | output | Router-originated traffic (outbound connections from the router) |
| NAT | dstnat | Destination NAT (port forwarding) — processed before routing |
| NAT | srcnat | Source NAT (masquerade) — processed after routing decision |
| MANGLE | prerouting | Pre-routing packet marking for QoS, policy routing |
| MANGLE | input | Mark inbound router traffic |
| MANGLE | forward | Mark forwarded traffic |
| MANGLE | output | Mark router-originated traffic |
| MANGLE | postrouting | Post-routing changes before wire exit |

### 3.2 Recommended Input Chain (Minimal Production Set)

The input chain protects the router itself. Every rule below MUST be present in order.

```
/ip firewall filter
# 0 - Allow established/related (stateful inspection)
add chain=input connection-state=established,related action=accept comment="allow est,rel"

# 1 - Allow ICMP (rate-limited)
add chain=input protocol=icmp action=accept comment="allow ICMP"
# Alternative: rate-limit ICMP
# add chain=input protocol=icmp icmp-options=8:0-255 limit=5,5:packet action=accept
# add chain=input protocol=icmp action=drop comment="drop other ICMP"

# 2 - Allow management from mgmt subnet
add chain=input src-address=10.0.0.0/24 action=accept comment="allow mgmt subnet"

# 3 - Drop invalid packets
add chain=input connection-state=invalid action=drop comment="drop invalid"

# 4 - Drop everything else (catch-all)
add chain=input action=drop comment="drop all else input"
```

### 3.3 Forward Chain (Minimal Production Set)

```
/ip firewall filter
# 0 - Allow established/related
add chain=forward connection-state=established,related action=accept

# 1 - Drop invalid
add chain=forward connection-state=invalid action=drop

# 2 - Allow LAN to LAN
add chain=forward src-address=192.168.88.0/24 dst-address=192.168.88.0/24 \
    action=accept comment="LAN to LAN"

# 3 - Allow LAN to WAN (outbound internet)
add chain=forward src-address=192.168.88.0/24 out-interface=wan action=accept

# 4 - Drop inter-VLAN by default (enable only required flows)
# add chain=forward src-address=192.168.89.0/24 dst-address=192.168.88.0/24 \
#     action=accept comment="guest to LAN (pinhole)"

# 5 - Drop all else forward
add chain=forward action=drop comment="drop all else forward"
```

### 3.4 RAW Table Rules (Before Conntrack)

Apply to WAN interface before connection tracking to reduce state table load and block bogon traffic.

```
/ip firewall raw
# Block bogon IPs (RFC1918) on WAN
add chain=prerouting in-interface=wan src-address=10.0.0.0/8 action=drop comment="bogon 10/8"
add chain=prerouting in-interface=wan src-address=172.16.0.0/12 action=drop comment="bogon 172.16/12"
add chain=prerouting in-interface=wan src-address=192.168.0.0/16 action=drop comment="bogon 192.168/16"
add chain=prerouting in-interface=wan src-address=100.64.0.0/10 action=drop comment="bogon CGNAT"
add chain=prerouting in-interface=wan src-address=127.0.0.0/8 action=drop comment="bogon loopback"

# Block multicast, reserved, and link-local
add chain=prerouting in-interface=wan src-address=224.0.0.0/4 action=drop comment="bogon multicast"
add chain=prerouting in-interface=wan src-address=240.0.0.0/4 action=drop comment="bogon reserved"
add chain=prerouting in-interface=wan src-address=169.254.0.0/16 action=drop comment="bogon link-local"
add chain=prerouting in-interface=wan dst-address=224.0.0.0/4 action=drop comment="bogon dst multicast"

# Drop invalid before conntrack
add chain=prerouting in-interface=wan connection-state=invalid action=drop comment="drop invalid RAW"

# Optional: allow known-good traffic to bypass conntrack (high-throughput flows)
# add chain=prerouting in-interface=lan src-address=192.168.88.0/24 dst-address=0.0.0.0/0 \
#     action=notrack comment="LAN to WAN notrack"
```

### 3.5 Brute-Force Protection Pattern

A complete address-list throttling system with detection and blocking. This pattern protects SSH, WinBox, API, and WWW-SSL from brute-force login attempts.

**Step 1 — Define scanner detection (input chain, early position after est/rel):**

```
/ip firewall filter
add chain=input protocol=tcp dst-port=22,8291,80,443 \
    connection-state=new src-address-list=ssh_blacklist \
    action=drop comment="drop brute-force blacklisted"

add chain=input protocol=tcp dst-port=22 connection-state=new \
    src-address-list=ssh_stage3 action=add-src-to-list \
    address-list=ssh_blacklist address-list-timeout=1h \
    comment="ssh stage3 → blacklist"

add chain=input protocol=tcp dst-port=22 connection-state=new \
    src-address-list=ssh_stage2 action=add-src-to-list \
    address-list=ssh_stage3 address-list-timeout=1m \
    comment="ssh stage2 → stage3"

add chain=input protocol=tcp dst-port=22 connection-state=new \
    src-address-list=ssh_stage1 action=add-src-to-list \
    address-list=ssh_stage2 address-list-timeout=1m \
    comment="ssh stage1 → stage2"

add chain=input protocol=tcp dst-port=22 connection-state=new \
    action=add-src-to-list address-list=ssh_stage1 \
    address-list-timeout=1m comment="ssh new → stage1"
```

**Step 2 — Repeat for each protected service:**

Replace `dst-port=22` with the target port(s). The three-stage escalation works as follows:

- **Stage 1**: First new connection — added to watch list (1 min timeout)
- **Stage 2**: Second new connection within expiry — moved to stage 2 (1 min timeout)
- **Stage 3**: Third new connection — moved to stage 3 (1 min timeout)
- **Blacklist**: Stage 3 timer expiry triggers blacklist membership (1 hour timeout)
- Subsequent connections from blacklisted IPs are silently dropped

For SSH specifically, also add connection rate limiting:

```
add chain=input protocol=tcp dst-port=22 connection-state=new \
    limit=3,60:packet action=accept comment="ssh rate limit"
add chain=input protocol=tcp dst-port=22 connection-state=new \
    action=drop comment="ssh drop excess"
```

**Step 3 — Clean up in forward chain (prevents forwarded traffic from brute-forcing):**

```
add chain=forward protocol=tcp dst-port=22,8291,80,443 \
    connection-state=new src-address-list=ssh_blacklist \
    action=drop comment="drop blacklist forward"
```

### 3.6 Port Knocking (Optional Defense-in-Depth)

For services that must be exposed on the internet (e.g., VPN), implement port knocking to obscure the service until a correct sequence is received.

```
/tool port-knock
add name=vpn sequence=7000,8000,9000 timeout=30s
```

Then use a firewall rule that enables access only from IPs that completed the knock sequence (uses `port-knock` dynamic address lists).

---

## 4. Network Configuration

### 4.1 VLAN Best Practices

**Bridge VLAN Filtering** is the modern approach (RouterOS v7). It replaces per-port VLANs with centralized filtering on the bridge.

```
/interface bridge
add name=bridge protocol-mode=rstp vlan-filtering=yes

/interface vlan
add interface=bridge vlan-id=10 name=vlan10
add interface=bridge vlan-id=20 name=vlan20

/interface bridge vlan
add bridge=bridge vlan-id=10 tagged=bridge,ether2 untagged=ether3
add bridge=bridge vlan-id=20 tagged=bridge,ether2 untagged=ether4

/interface bridge port
add bridge=bridge interface=ether2 frame-type=admit-only-vlan-tagged \
    ingress-filtering=yes
add bridge=bridge interface=ether3 frame-type=admit-only-untagged-and-priority-tagged
add bridge=bridge interface=ether4 frame-type=admit-only-untagged-and-priority-tagged
```

**Trunk ports**: `frame-type=admit-only-vlan-tagged, ingress-filtering=yes`
**Access ports**: `frame-type=admit-only-untagged-and-priority-tagged, ingress-filtering=yes`

### 4.2 DHCP Security

```
/ip dhcp-server
set [find] authoritative=yes use-radius=no

/ip dhcp-server network
add address=192.168.88.0/24 gateway=192.168.88.1 dns-server=192.168.88.1 \
    lease-time=00:30:00 comment="DHCP network"

/ip dhcp-server lease
# Set static leases for known MACs
add address=192.168.88.10 mac-address=AA:BB:CC:DD:EE:FF client-id=server1 \
    comment="server1 static lease"
```

**Lease limits** — critical on hAP ac² with flash constraints:

```
/ip dhcp-server set [find] lease-script="" lease-hold-time=00:00:15
```

On flash-constrained devices, ensure DHCP lease storage does not exhaust spare sectors:

**v6:**
- `/ip dhcp-server` leases are stored in the `dhcp` database on disk
- `store-leases-on-disk=yes` writes every lease change to flash
- Set `store-leases-on-disk=no` to reduce flash writes

**v7 (removed store-leases-on-disk):**
- RouterOS v7 removed `store-leases-on-disk`. Lease persistence is managed via
  `/ip dhcp-server config set lease-write-interval=...` (if available) or by
  database engine settings.
- For hAP ax³ (256MB NAND) this is not a concern — ample flash endurance.
- For hAP ac² (16MB flash):
  - Bind high-churn clients to **static leases only**
  - Set `lease-hold-time` to < 30 seconds to release entries promptly
  - Consider `lease-script` for logging rather than endless leases
  - Keep total active lease count low (< 50 recommended)

### 4.3 DNS Security

```
/ip dns set allow-remote-requests=no servers=1.1.1.1,8.8.8.8 \
    query-server-tcp=yes use-doh=yes \
    doh-server="https://cloudflare-dns.com/dns-query"
```

DoH (DNS-over-HTTPS) encrypts DNS queries to the upstream resolver. Configure with `use-doh=yes` and a valid `doh-server` URL. Fallback to plaintext DNS if DoH is unreachable depends on `query-server-tcp=yes`.

```
# Verify DoH operational
/ip dns print
# Check "DoH Server" status = "ok" or "failed"
```

### 4.4 Bridge Configuration

**MTU consistency**: All bridge member interfaces MUST have the same L2 MTU. Mismatched MTU causes packet drops on the bridge.

```
/interface bridge port print oid=mtu
# All ports should report same MTU
```

Set global bridge MTU to 1500 (or 9000 for datacenter):

```
/interface bridge set bridge mtu=1500
```

**HW offload awareness**: On hAP ac², enabling `vlan-filtering=yes` disables hardware offloading on the bridge. See Section 9 for mitigations.

---

## 5. System Hardening

### 5.1 NTP

```
/system ntp client set enabled=yes server-dns-ns=pool.ntp.org \
    primary-ntp=0.pool.ntp.org secondary-ntp=1.pool.ntp.org
```

For environments requiring authenticated NTP (NTS), use RouterOS v7.13+:

```
/system ntp client set enabled=yes use-nts=yes \
    server-dns-ns=time.cloudflare.com
```

### 5.2 Logging

```
/logging add topics=account,critical,error,firewall,info,ssh,winbox \
    action=memory prefix="sec"
/logging add topics=account,critical,error,firewall,info \
    action=disk prefix="sec"
/logging add topics=critical,error,firewall \
    action=remote remote=10.0.0.5:514
```

| Topic | Action | Purpose |
|---|---|---|
| account | memory, disk, remote | User authentication events |
| critical | memory, disk, remote | System-critical failures |
| error | memory, disk, remote | Operational errors |
| firewall | memory, disk, remote | FW rule hits, drops |
| info | memory, disk | Informational events |
| ssh | memory, remote | SSH login attempts |
| winbox | memory, remote | WinBox access attempts |

Set log buffer sizes and action parameters:

```
/logging action set memory memory-lines=10000
/logging action set disk disk-file-name=system-log disk-lines-per-file=1000
/logging action set remote remote=10.0.0.5:514 remote-log-throttle=100,10:time
```

### 5.3 Updates

```
/system package update set channel=stable
```

- `channel=stable` — production safety; `channel=testing` only in lab
- Schedule: check daily via scheduler or monitor via The Dude/Zabbix

**v6 only:** `allow-signed=yes` prevents unsigned (potentially malicious) package
installation.

**v7 change:** The `allow-signed` parameter is **removed** in RouterOS v7.
Package signing is now mandatory — all packages in v7 are verified against
MikroTik's signing key before installation. No configuration is needed.

### 5.4 Backup Strategy

Two backup methods with different purposes:

**Binary backup** — full system restore:

```
/system backup save name=20260523-router1.backup password="strong-password"
```

**Export script** — human-readable, version-controllable config:

```
/export file=20260523-router1.rsc
/export file=20260523-router1-hide-sensitive.rsc hide-sensitive=yes
```

Automation script for scheduled backups:

```
:local date [/system clock get date]
:local backupName ("router1-" . $date)
/system backup save name=$backupName password="[redacted]"
/export file=($backupName . ".rsc") hide-sensitive=yes
/tool fetch address=10.0.0.10 src-path=($backupName . ".backup") \
    dst-path=backups/ mode=ftp user=backupuser password="[redacted]"
```

Store binary backups off-device. Encrypt the backup file with a strong password. Store export scripts in version control.

### 5.5 System Identity

```
/system identity set name=DC1-RTR01-LAB
```

Naming convention:

| Segment | Position | Example |
|---|---|---|
| Site | First | DC1, BR1, HQ |
| Device type | Second | RTR (router), SW (switch), FW (firewall) |
| Number | Third | 01, 02 |
| Function | Optional | CORE, LAB, DMZ |

---

## 6. WiFi Security

### 6.1 Encryption

```
/interface wireless security-profiles
add name=secure mode=dynamic-keys \
    authentication-types=wpa2-psk,wpa3-psk \
    unicast-ciphers=ccmp group-ciphers=ccmp \
    management-protection=required

set [find] wpa2-pre-shared-key=0123456789abcdefghijklmnopqr0123 \
    wpa3-pre-shared-key=$wpa3Passphrase
```

- **WPA2**: minimum, not default
- **WPA3**: preferred where clients support it
- **TKIP**: NEVER used — breaks CCMP-only enforcement
- **WPA3-SAE**: use `authentication-types=wpa3-psk` with `sae-password` parameter
- **Management Protection (PMF)**: `required` for enterprise environments; `optional` for broad compatibility

### 6.2 WPS

```
/interface wireless set wps-mode=disabled
```

WPS PIN attack (Reaver) can recover PSK in 4–10 hours. Disable unconditionally.

### 6.3 Guest Network

```
/interface vlan add interface=bridge vlan-id=100 name=guest-vlan
/interface wireless set wlan2 master-interface=none ssid=Guest-Network \
    vlan-id=100 vlan-mode=use-tag

/ip address add address=192.168.100.1/24 interface=guest-vlan
/ip pool add name=guest-dhcp ranges=192.168.100.10-192.168.100.200
/ip dhcp-server add address-pool=guest-dhcp disabled=no interface=guest-vlan
/ip dhcp-server network add address=192.168.100.0/24 gateway=192.168.100.1

# Client isolation — prevent wireless clients from talking to each other
/interface wireless set wlan2 isolate=yes

# Firewall — guest to LAN block
/ip firewall filter add chain=forward src-address=192.168.100.0/24 \
    dst-address=192.168.88.0/24 action=drop comment="block guest to LAN"

# Bandwidth limit
/queue simple add name=guest-limit target=192.168.100.0/24 \
    max-limit=10M/10M queue=pcq-12-default/pcq-12-default
```

### 6.4 Protected Management Frames (PMF)

```
/interface wireless security-profiles set [find] management-protection=required
```

PMF protects against deauth attacks, forged management frames, and AP impersonation.

- `disabled` — no protection (default)
- `optional` — PMF attempted but not enforced
- `required` — PMF enforced; clients that don't support it are rejected

Check client PMF support:

```
/interface wireless registration-table print detail where interface=wlan1
# Look for "pmf" column
```

### 6.5 CAPsMAN

**CAPsMAN Control Channel Encryption**:

```
/caps-man manager set enabled=yes
/caps-man manager interface add interface=bridge disabled=no

/caps-man certificates
# Use CA-signed certs for TLS between CAP and CAPsMAN
/caps-man manager set tls-certificate=cert1 tls-mode=yes

/caps-man provisioning
add action=create-dynamic-enabled hw-supported-modes=ac master-configuration=provision \
    # Strong shared passphrase
    common-name-regex=".*"
```

Provisioning passphrase for CAP discovery:

```
/caps-man manager set passphrase="strong-capsman-provisioning-key"
```

CAP client configuration:

```
/interface wireless cap set enabled=yes \
    certificate=cert1 \
    addresses=10.0.0.10 \
    bridge=bridge \
    interfaces=wlan1,wlan2 \
    passphrase="strong-capsman-provisioning-key"
```

### 6.6 hAP ac² Flash Crisis

The hAP ac² has **16 MB total flash** (SPI NOR). After RouterOS install (~8–10 MB), remaining space is ~6–8 MB for:

- Log files
- DHCP leases database
- CAPsMAN provisioning data
- Package upgrades
- User scripts

This is **insufficient** for `wifi-qcom-ac` package on RouterOS v7. The `wifi-qcom-ac` package provides the native WiFi driver but requires approximately 11 MB leaving only ~5 MB for everything else. In practice, this means:

- **RouterOS 6**: use the legacy `wireless` (802.11) package — functional, full-featured, flash-efficient
- **RouterOS 7**: the `wifi-qcom-ac` package exists but upgrading to it may cause `out-of-flash-space` errors
- Some hAP ac² units can install `wifi-qcom-ac` after a clean netinstall; others cannot
- **Recommendation**: stay on RouterOS 6.49.x (latest stable) for hAP ac², or verify flash space before upgrading to ROS7 with wifi-qcom-ac

Check flash availability:

```
/system resource print
# Look for "free-flash" value — must be > size of any package being installed
```

---

## 7. Routing Security

### 7.1 BGP

**eBGP Session Security**:

```
/routing bgp connection
add name=ebgp-upstream1 remote.address=203.0.113.1 remote.as=64501 \
    local.address=198.51.100.1 local.role=provider \
    tcp.md5key="strong-md5-key" \
    ttl=1 \
    address-families=ipv4 \
    hold-time=30s keepalive-time=10s

add name=ebgp-upstream2 remote.address=198.51.100.2 remote.as=64502 \
    local.address=203.0.113.2 local.role=provider \
    tcp.md5key="strong-md5-key" \
    ttl=1 \
    address-families=ipv4 \
    hold-time=30s keepalive-time=10s
```

**Max Prefix Limits**:

```
/routing bgp connection
set ebgp-upstream1 remote.capabilities=dynamic-capability=no \
    routing-table=main \
    input.max-prefix=1000 \
    input.restart-time=5m
```

**Routing Filters**:

```
/routing filter rule
# Reject bogon origin ASNs
add chain=bgp-in rule="if (bgp-as-path ~ \"^(64512|64513|64514)\") { reject }"
# Reject private ASNs in path
add chain=bgp-in rule="if (bgp-as-path ~ \"(64512|64513|64514)\") { reject }"
# Reject martian prefixes
add chain=bgp-in rule="if (dst in 10.0.0.0/8) { reject }"
add chain=bgp-in rule="if (dst in 172.16.0.0/12) { reject }"
add chain=bgp-in rule="if (dst in 192.168.0.0/16) { reject }"
add chain=bgp-in rule="if (dst in 224.0.0.0/4) { reject }"
add chain=bgp-in rule="if (dst in 240.0.0.0/4) { reject }"
# Limit prefix length
add chain=bgp-in rule="if (dst-len > 24) { reject }"
# Accept
add chain=bgp-in rule="accept"
```

### 7.2 OSPF

```
/routing ospf interface-template
add authentication=md5 authentication-key="strong-md5-key" \
    area=backbone networks=10.0.1.0/24
add authentication=sha256 authentication-key="strong-sha-key" \
    area=backbone networks=10.0.2.0/24

# Passive interfaces — no OSPF adjacencies expected
/routing ospf interface-template
add area=backbone networks=10.0.0.0/24 passive=yes disabled=no
add area=backbone networks=10.0.3.0/24 passive=yes disabled=no
```

Always set passive on:

- Loopback interfaces
- Management interfaces
- Stub network interfaces (LAN segments not running OSPF)

### 7.3 Default Route

```
/ip route
add dst-address=0.0.0.0/0 gateway=203.0.113.1 \
    check-gateway=ping \
    comment="default via upstream1"

add dst-address=0.0.0.0/0 gateway=198.51.100.2 \
    check-gateway=ping distance=2 \
    comment="default via upstream2"
```

**BFD (Bidirectional Forwarding Detection)** for faster failover:

```
/routing bfd interface
add interface=ether1 interval=100ms min-rx=100ms multiplier=3

/ip route
add dst-address=0.0.0.0/0 gateway=203.0.113.1 bfd=yes \
    distance=1 comment="default w/ BFD"
```

**Recursive nexthop** for dynamic next-hop resolution (useful when upstream IP is reachable via a transport network):

```
/ip route
add dst-address=0.0.0.0/0 gateway=203.0.113.1 \
    routing-table=main scope=30
/ip route
add dst-address=203.0.113.0/30 gateway=198.51.100.2 \
    scope=10
```

### 7.4 Loopback Interface

```
/interface bridge add name=loopback
/ip address add address=10.255.255.1/32 interface=loopback

/routing id add select-dynamic=no id=10.255.255.1
```

Benefits:

- Stable router ID for BGP/OSPF — survives physical interface flaps
- Management endpoint independent of specific WAN/LAN IPs
- Source address for service bindings (`/ip service set ssh address=10.255.255.1/32`)
- iBGP sessions rely on loopback for next-hop reachability

---

## 8. Scripting & Automation Security

### 8.1 Minimal Script Permissions

Every script should request only the policies it actually executes. Avoid granting `policy`, `reboot`, `sensitive`, or `test` unless explicitly needed.

```
/system script
add name=backup-router owner=admin policy=read,write,local \
    source="..." \
    dont-require-permissions=no
```

- `dont-require-permissions=no` — enforce policy checking
- `policy` field enumerates required permissions — be as restrictive as possible
- **CRITICAL**: Revoke `dont-require-permissions=yes` from all scripts immediately.
  This setting bypasses ALL permission checks — any user who can run the script can
  execute arbitrary commands. See audit check SCRIPT-010.
- Scripts with `dont-require-permissions=yes` are a Critical (CVSS 9.0) finding.

### 8.2 No Hardcoded Credentials

```
# BAD — hardcoded password
:local backupPassword "Str0ng!Pass"

# GOOD — global variable set once at device provisioning
:global backupPassword [/system script user get [find name=password-storage]]
```

Store sensitive values in `:global` variables populated from a secure bootstrap script, or use `/system script user` for personal credentials. Avoid embedding passwords in `source` text that appears in `/export` output.

### 8.3 Error Handling

```
:local success false
:do {
    /system backup save name="test"
    :set success true
} onerror={
    :log error "Backup failed"
    /tool e-mail send to="admin@example.com" subject="Backup FAILED" \
        body="Router backup failed at [$[/system clock get date]]"
}
```

Always wrap destructive or dependent operations in `:do { … } onerror={ … }`.

### 8.4 Single-Instance Guard

Prevent concurrent execution of scheduler scripts (e.g., backup running twice due to long runtime):

**RouterOS v7 syntax (preferred):**
```
:if ([/system script job find where jobname=$[:jobname]] > 1) do={
    :log warning "Instance already running: $[:jobname]"
    :error "Already running"
}
```

**Alternative using :jobname in scheduler (v7):**
```
/system scheduler add name=backup-scheduler interval=1d \
    policy=read,write,local \
    on-event="/system script run backup-router" \
    jobname=backup-router
```

**Legacy v6 syntax (avoid in v7):**
```
:local jobName "backup-router"
:local count [/system script job count-as who="scheduler" where="script = $jobName"]
:if ($count > 1) do={
    :log warning "Backup script already running — skipping"
    :delay 1
    :error "Already running"
}
```

> **Note:** The `running` property does NOT exist on `/system scheduler`. Use
> `/system script job` to detect running script instances in v7.

### 8.5 Safe Scripting Practices

- **DO NOT** use `/system reset-configuration` or `/system routerboard reset` in any automated script
- **DO NOT** execute `/interface disable` on the management interface without confirmation
- **DO NOT** run recursive loops without `:delay` or connection-loss protection
- **DO** validate conditions before making network changes:

```
:if ([/ping 8.8.8.8 count=3] > 2) do={
    :log info "Connectivity verified — proceeding"
    ... change operations ...
} else={
    :log error "No connectivity — aborting"
}
```

- **DO** limit log growth in scripts:

```
:local logSize [/log file print count-only]
:if ($logSize > 1000) do={
    /log file remove [find]
}
```

---

## 9. hAP-Specific Considerations

### 9.1 hAP ac² 16 MB Flash Crisis

The hAP ac² (RB952Ui-5ac2nD) is constrained by a 16 MB SPI NOR flash chip. After the base RouterOS image (~8–10 MB), the remaining capacity is ~6–8 MB.

| Component | Approximate Size |
|---|---|
| RouterOS v6.49.x | 8 MB |
| RouterOS v7 (minimal) | 10 MB |
| `wifi-qcom-ac` package (ROS7) | 11 MB |
| Log files | variable — runs out of space quickly |
| DHCP leases database | variable — grows with active leases |
| CAPsMAN provisioning data | 100 KB+ per CAP |
| Free space (ROS6) | ~6 MB |
| Free space (ROS7 + wifi-qcom-ac) | NOT POSSIBLE in practice |

**Consequences**:

- ROS7 with `wifi-qcom-ac` cannot coexist with adequate logging and DHCP lease storage
- Firmware upgrades may fail with "not enough space" unless flash is cleaned first
- `wifi-qcom-ac` is NOT recommended on hAP ac² — use the legacy `wireless` (802.11) package instead
- If ROS7 is required, consider: netinstall minimal (remove unused packages), disable logging to disk, use static DHCP leases only, run from microSD slot if available

### 9.2 Bridge VLAN Filtering Disables HW Offload

On hAP ac² (and many other MikroTik devices), enabling `vlan-filtering=yes` on the bridge **disables hardware offload** for the bridge ports.

```
/interface bridge port print
# H = HW offloaded; check "H" column
# Expect: all ports lose "H" when vlan-filtering=yes
```

**Impact**:

- All traffic through the bridge is CPU-switched (software bridge)
- Maximum throughput drops from ~950 Mbps (HW offload) to ~150–300 Mbps
- CPU usage increases proportionally with throughput
- This affects ALL traffic that traverses the bridge (including non-VLAN traffic)

**Mitigation** — Dual-bridge workaround:

Create two bridges — one for VLAN-filtered traffic and one for non-VLAN-traffic:

```
/interface bridge
add name=bridge-vlan vlan-filtering=yes
add name=bridge-native vlan-filtering=no

/interface bridge port
# Put VLAN-requiring ports on bridge-vlan
add bridge=bridge-vlan interface=ether2
add bridge=bridge-vlan interface=ether3

# Put non-VLAN ports on bridge-native (preserves HW offload)
add bridge=bridge-native interface=ether4
add bridge=bridge-native interface=ether5
```

This is a **workaround** with limitations:
- Inter-bridge routing requires the CPU (/router)
- Native bridge ports are effectively on a separate L2 domain
- Management IP must exist on both bridges or routing must be configured

For most hAP ac² deployments, hardware offload is acceptable for the performance gain, so `vlan-filtering=no` is preferred unless VLAN separation is a strict security requirement.

### 9.3 hAP ax²/ax³ AX WiFi Stability

| Model | Minimum ROS Version for AX Stability |
|---|---|
| hAP ax² (L41G-2axD) | 7.19.2+ |
| hAP ax³ (L46UGS-5axD2axD) | 7.19.2+ |

The `wifi` package (native AX/Wave2 driver) in RouterOS versions before 7.19.2 has known issues:

- Frequent wireless client disconnects on AX networks
- DFS channel stability problems
- CAPsMAN provisioning failures with mixed-generation APs
- Memory leaks in the WiFi management process

**Verification**:

```
/system package print where name=wifi
# Check version — must be ≥ 7.19.2
/system routerboard print
# Confirm model is ax² or ax³
```

### 9.4 hAP ax³ 2.4 GHz Range Limitations

The hAP ax³ uses internal antennas and the 2.4 GHz radio has notably shorter range than competing enterprise APs. This is a physical limitation — not a configuration fix.

- 2.4 GHz range: approximately 15–25 meters (obstructed indoor)
- 5 GHz range: approximately 20–30 meters (obstructed indoor, better due to antenna geometry)
- Real-world throughput at 15 m (2.4 GHz, single client): 50–100 Mbps

**Recommendation**: Position the hAP ax³ centrally and prefer 5 GHz for clients within 20 m.

### 9.5 CAPsMAN Generation Incompatibilities

CAPsMAN v2 (RouterOS v7) is NOT compatible with CAPsMAN v1 (RouterOS v6).

- A ROS6 CAP cannot register with a ROS7 CAPsMAN manager
- A ROS7 CAP cannot register with a ROS6 CAPsMAN manager
- Mixed-generation deployments require separate CAPsMAN instances or AP groups

If replacing an existing CAPsMAN deployment:

```
# On ROS7 CAPsMAN — verify connected CAPs support level
/caps-man remote-cap print
# Look for "version" column — must match CAP's ROS version

# Alternatively, check CAP side
/interface wireless cap print
# Shows connected-to CAPsMAN IP and registration status
```

---

## 10. Verification Commands

### 10.1 Authentication & User Management

```
# List all users with group membership and IP restrictions
/user print detail

# Verify no default admin account is enabled
/user print where name=admin and disabled=no

# Check user group policies
/user group print detail

# Verify SSH configuration
/ip ssh print
/ip ssh show-identity

# Check service binding IP restrictions
/ip service print

# Verify no MAC-services exposed
/tool mac-server print
/tool mac-server ping print
/tool mac-winbox print
```

### 10.2 Service Surface

```
# List all enabled services with their address bindings
/ip service print where disabled=no

# Check for dangerous services
/ip service print where name~"telnet|ftp|www$|api$"
/ip cloud print
/ip socks print
/ip upnp print
/tool bandwidth-server print
```

### 10.3 Firewall

```
# Full filter rules (input chain focus)
/ip firewall filter print where chain=input

# Verify established/related allow-drop chain position
/ip firewall filter print chain=input where action~"accept|drop"

# Count rule hits (packets/bytes counters)
/ip firewall filter print stats

# Check connection tracking limits
/ip firewall connection tracking print

# RAW table bogon rules
/ip firewall raw print

# Address lists for brute-force protection
/ip firewall address-list print where list~"blacklist|stage"

# NAT rules audit
/ip firewall nat print
/ip firewall nat print stats
```

### 10.4 System Hardening

```
# Check RouterOS version
/system resource print

# Verify NTP synchronization
/system ntp client print
/system ntp client status

# Logging configuration
/logging print detail
/logging action print

# Update channel
/system package update print

# Backup verification — check for recent backup files
/file print where name~"\\.backup$"
/file print where name~"\\.rsc$"

# System identity
/system identity print
```

### 10.5 Network Configuration

```
# Bridge VLAN filtering status
/interface bridge print
/interface bridge vlan print

# DHCP server configuration
/ip dhcp-server print detail
/ip dhcp-server lease print count-only
/ip dhcp-server network print

# DNS configuration
/ip dns print

# Interface MTU
/interface print oid=mtu
```

### 10.6 WiFi Security

```
# Wireless security profiles
/interface wireless security-profiles print detail

# WPS status
/interface wireless print where wps-mode=disabled

# CAPsMAN manager config
/caps-man manager print
/caps-man provisioning print

# Connected clients and PMF support
/interface wireless registration-table print detail

# Client isolation
/interface wireless print where isolate=yes

# Queue limits for guest networks
/queue simple print
```

### 10.6.5 Queue / QoS Baseline

```
# List all queue trees
/queue tree print detail

# List simple queues
/queue simple print detail

# Check FastTrack compatibility (FastTrack bypasses queues)
/ip firewall filter print where action=fasttrack-connection

# PCQ types available
/queue type print where kind=pcq
```

**Best practices:**
- **FastTrack + queue trees are incompatible.** FastTrack bypasses all queues.
  If you need QoS, disable FastTrack for those connections or use simple queues
  with `fasttrack-interface=...` exclusion.
- **Use PCQ for per-client fairness** on shared links. Simple queue with `queue=pcq-
  rate-default/pcq-rate-default` ensures each client gets a fair share.
- **HTB burst** should always have a `max-limit` — burst without max-limit allows
  unlimited throughput.
- **Bufferbloat mitigation:** Use `queue=pfifo50-fast` or CoDel-based queue types
  on WAN interfaces to reduce latency under load.
- **Connection marking** (mangle) must be placed before FastTrack rules in the
  forward chain, or FastTrack will bypass the marks.
- **hAP ac²** has limited queue performance in software — prefer simple queues
  over complex queue trees on this hardware.

### 10.7 Routing Security

```
# BGP connections and state
/routing bgp connection print detail
/routing bgp session print

# BGP filters
/routing filter rule print

# OSPF authentication
/routing ospf interface-template print detail

# Default route verification (gateway state, distance)
/ip route print where dst-address=0.0.0.0/0
/ip route print detail where dst-address=0.0.0.0/0

# BFD interfaces
/routing bfd interface print

# Loopback interface
/interface print where name=loopback
/ip address print where interface=loopback
```

### 10.8 Scripting & Automation

```
# List all scripts with their policies
/system script print detail

# Active script jobs (check for runaway scripts)
/system script job print

# Scheduler entries
/system scheduler print detail

# Global variable export (manually)
:put "Global variables exported — run :global to list"
```

### 10.9 hAP-Specific

```
# Flash space check
/system resource print
# Look for "free-flash" — critical for package upgrades

# Bridge HW offload status
/interface bridge port print
# "H" column indicates hardware offload

# RouterOS version for AX stability (hAP ax²/ax³)
/system package print where name=wifi

# CAPsMAN version compatibility
/caps-man manager print

# Model identification
/system routerboard print
```
