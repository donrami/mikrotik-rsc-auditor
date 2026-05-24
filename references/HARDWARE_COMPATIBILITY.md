# Hardware Compatibility Reference

> Device profile system for tailoring audit checks to specific MikroTik hardware platforms.
> RouterOS versions covered: v6.49.x – v7.22.3

---

## Table of Contents

1. [Device Profile System Overview](#1-device-profile-system-overview)
2. [Supported Hardware Families](#2-supported-hardware-families)
3. [Model Detection](#3-model-detection)
4. [How Checks Are Tailored](#4-how-checks-are-tailored)
5. [Severity Adjustment Rules](#5-severity-adjustment-rules)
6. [Known Hardware-Specific False Positive Patterns](#6-known-hardware-specific-false-positive-patterns)
7. [Per-Family Check Applicability](#7-per-family-check-applicability)
8. [Container-Capable Devices](#8-container-capable-devices)
9. [RouterOS Feature Levels by Platform](#9-routeros-feature-levels-by-platform)
10. [Adding New Device Profiles](#10-adding-new-device-profiles)

---

## 1. Device Profile System Overview

The auditor uses a device profile system to tailor its 108 security checks to the specific MikroTik hardware model detected in the export header.

### How It Works

```
┌─ Export Header ─────────────────────────────────┐
│ # 2026-05-24 by RouterOS 7.22.3                 │
│ # model = C53UiG+5HPaxD2HPaxD                  │
│ # serial = [REDACTED]                           │
└─────────────────────────────────────────────────┘
                         ↓
               Model Detection Regex
              ┌──────────────────┐
              │ Pattern: C53UiG  │
              │ Family: hAP      │
              │ Subfamily: ax³   │
              └──────────────────┘
                         ↓
               Device Profile Loaded
              ┌───────────────────────────────────┐
              │ cpu: IPQ-6010, ram: 1024MB        │
              │ wifi: wifi-qcom-ax, switch: MT7531│
              │ container: true, lcd: true        │
              └───────────────────────────────────┘
                         ↓
              Check Tailoring Applied
              ├─ N/A exclusions (no WiFi on CCR)
              ├─ Severity overrides (flash-critical on hAP ac²)
              └─ Special checks (AX stability on hAP ax²/ax³)
```

### Profile Schema

Each device profile is a YAML-structured definition with the following fields:

```yaml
# ——— Identity ———
model_pattern: "<regex>"      # Regex matching the export header model line
family: "<family>"            # hAP | CCR | CRS | RB | cAP | etc.
subfamily: "<subfamily>"      # ac² | ax² | ax³ | 3xx | etc.
arch: "<arch>"                # arm | arm64 | mipsbe | tile | x86_64

# ——— Hardware ———
cpu: "<model>"
cpu_cores: <int>
ram_mb: <int>
flash_mb: <int>
flash_type: "SPI NOR | NAND | eMMC"
storage_slot: false | "<type>"

# ——— Networking ———
ports: ["<N>x <speed> <type>", ...]
sfp: false | <count>
sfp_plus: false | <count>
sfp28: false | <count>
poe_in: false | "<type>"
poe_out: false | "<type>"

# ——— WiFi ———
wifi: false | "<driver>"
wifi_bands: false | "2.4" | "5" | "2.4+5" | "2.4+5+6"
wifi_standard: null | "n" | "ac" | "ax" | "be"

# ——— Switching ———
switch_chip: null | "<model>"
hardware_offload: true | false | "conditional"
hw_offload_limit: null | "<description>"

# ——— System ———
lcd: false | "<type>"
usb: false | <count>
serial_port: bool
container: false | "docker" | "podman"
tpm: false

# ——— Software ———
min_ros6: "<version>" | null
max_ros6: "<version>" | null
min_ros7: "<version>" | null
max_ros7: "<version>" | null
routeros_level: "Level0" | "Level1" | "Level3" | "Level4" | "Level5" | "Level6"
swos: false | "<version>"

# ——— CAPsMAN / ZTP ———
capsman_controller: bool
capsman_client: bool
ztp: bool

# ——— Audit Integration ———
special_checks: ["<CHECK_ID>: <description>", ...]
severity_overrides: {"<CHECK_ID>": "<adjusted_severity>", ...}
n_a_checks: ["<CHECK_ID>: <reason>", ...]
applicable_domains: ["AUTH", "SRV", "FW", "SYS", "NET", "ROUTE", "WIFI", "SCRIPT", "COMP"]
```

---

## 2. Supported Hardware Families

### 2.1 hAP Series — Home Access Points

| Model | Arch | CPU | RAM | Flash | WiFi | Switch | LCD | Container |
|-------|------|-----|-----|-------|------|--------|-----|-----------|
| hAP ac² (RBD52G/RB952Ui) | arm | IPQ-4018 (4× A7 @716MHz) | 128MB | 16MB SPI | ac (QCA9888) | IPQ-4018 internal | No | No |
| hAP ax² (C52iG) | arm64 | IPQ-5010 (2× A73 @1.0GHz) | 512MB | 128MB NAND | ax | MediaTek MT7531 | No | Yes |
| hAP ax³ (C53UiG) | arm64 | IPQ-6010 (4× A73 @1.8GHz) | 1GB | 128MB NAND+16MB SPI | ax (QCN5024+QCN5054) | MediaTek MT7531 | Yes | Yes |
| hAP lite (RB941) | mipsbe | QCA9533 (1× MIPS24Kc) | 64MB | 16MB SPI | n | QCA9533 internal | No | No |
| hAP (RB951) | mipsbe | AR9344 (1× MIPS74Kc) | 64MB | 16MB SPI | n | AR8327 | No | No |

**Key audit differences:**
- hAP ac²: 16MB SPI flash → NET-003 (DHCP lease storage) critical; DNS cache ≤2048; conntrack ≤16384; bridge VLAN filtering disables HW offload (NET-006)
- hAP ax²/ax³: AX stability concern below ROS 7.19.2 (WIFI-013); no flash constraints; container checks apply
- hAP lite: 64MB RAM, MIPS single-core, no ROS7; ICMP rate limiting important (FW-012)

### 2.2 CCR Series — Cloud Core Routers

| Model Range | Arch | CPU | RAM | Flash | WiFi | Container |
|-------------|------|-----|-----|-------|------|-----------|
| CCR1036 | tile (MIPS64) | Tilera TILE-Gx36 (36 cores) | 4-8GB | 1GB NAND | No | No |
| CCR1072 | tile (MIPS64) | Tilera TILE-Gx72 (72 cores) | 8-16GB | 1GB NAND | No | No |
| CCR2004 | arm64 | Annapurna Alpine AL324 (4× A72) | 4GB | 4GB eMMC | No | Yes |
| CCR2116 | arm64 | Annapurna Alpine AL334 (12× A72) | 8GB | 4GB eMMC | No | Yes |
| CCR2216 | arm64 | Annapurna Alpine AL536 (16× A72) | 16GB | 4GB eMMC | No | Yes |

**Key audit differences:**
- All WiFi checks → N/A (no wireless hardware)
- BGP/OSPF routing security → Critical severity (ROUTE-001 through ROUTE-009)
- Bogon filtering → Critical for ISP edge (FW-005)
- Remote syslog → Critical for ISP compliance (SYS-005)
- Conntrack exhaustion → Critical at ISP scale (FW-016)
- FastTrack not supported on TileGX models (CCR1036/1072)
- Container checks apply to CCR2004+

### 2.3 CRS Series — Cloud Router Switches

| Model Range | Arch | CPU | Switch Chip | HW Offload | WiFi | ROS Version |
|-------------|------|-----|-------------|------------|------|-------------|
| CRS1xx/2xx | mipsbe | AR9344/QCA9558 | AR8327/QCA8327 | L2 only | No | v6 only |
| CRS3xx | arm64 | 98DXxxx/Alpine | Marvell 98DX3xxx | L3 HW offload | No | v7+ |
| CRS354 | arm64 | Marvell ARMv8 | Marvell 98DX8208 | L3 HW offload | No | v7+ |

**Key audit differences:**
- All WiFi checks → N/A
- CRS3xx: bridge VLAN filtering IS the recommended method (not switch VLAN)
- CRS3xx: L3 HW offload is incompatible with FastTrack (FW-007)
- CRS3xx: switch ACL can bypass firewall forward chain for HW-offloaded flows
- CRS1xx/2xx: must use switch VLAN, not bridge VLAN filtering (v6 only)
- HW offload CLI is `/interface ethernet switch`, not bridge configuration
- CRS3xx: supports containers on higher-end models

### 2.4 RB Series — General Purpose Routers

| Model | Arch | CPU | RAM | Flash | WiFi | Container |
|-------|------|-----|-----|-------|------|-----------|
| RB750Gr3 (hEX) | mipsbe | MT7621 (2× MIPS1004Kc) | 256MB | 16MB SPI | No | No |
| RB4011iGS+ | arm64 | IPQ-8074 (4× A53 @1.4GHz) | 1GB | 128MB NAND | No (w/optional) | Yes |
| RB5009UG+S+ | arm64 | IPQ-6010 (4× A73 @1.8GHz) | 1GB | 128MB NAND | No | Yes |
| RB3011UiAS | mipsbe | MT7621A (2× MIPS1004Kc) | 1GB | 128MB NAND | No | No |
| RB1100AHx4 | mipsbe | QCA9563 (1× MIPS74Kc) | 1GB | 128MB NAND | No | No |

**Key audit differences:**
- All WiFi checks → N/A for non-WiFi models
- RB750Gr3: 16MB flash → NET-003 constraint (v6 only; v7 removed this check)
- RB4011: LCD present → SRV-015 applies; containers supported
- RB5009: no LCD, no WiFi, container-capable
- Routing security checks relevant for RB4011/RB5009 used as core gateways

### 2.5 cAP / wAP Series — Access Points

| Model | Arch | CPU | RAM | Flash | WiFi | Container |
|-------|------|-----|-----|-------|------|-----------|
| cAP ac (RBcAPGi-5acD2nD) | arm | IPQ-4018 (4× A7) | 128MB | 16MB SPI | ac (QCA9888) | No |
| cAP ax (RBcAPGi-5axD2axD) | arm64 | IPQ-6010 (4× A73) | 1GB | 128MB NAND | ax (QCN6102) | Yes |
| wAP ac (RBwAPG-5acD2nD) | arm | IPQ-4018 (4× A7) | 128MB | 16MB SPI | ac | No |
| wAP ax (RBwAPG-5axD2axD) | arm64 | IPQ-6010 (4× A73) | 1GB | 128MB NAND | ax | Yes |

**Key audit differences:**
- CAPsMAN client native → WIFI-007 (CAPsMAN encryption) applies
- cAP ac: 16MB flash constraint (same as hAP ac²)
- Designed for managed deployments → CAPsMAN provisioning checks relevant
- No PoE passthrough on most models

### 2.6 Wireless CPE & Links — LHG, SXT, mANTBox, disc

| Model Range | Arch | WiFi | Use Case | Special Constraints |
|-------------|------|------|----------|---------------------|
| LHG (LHGG-5acD) | arm | ac (high-gain) | PtMP CPE | Outdoor, GPS antenna |
| SXT (SXTsq 5acD) | arm | ac | PtP/PtMP CPE | Outdoor, specialized radio config |
| mANTBox (mANTBox 15s) | arm | ac/ax | Sector AP | Outdoor, multiple chains |
| disc (Disc Lite5) | mipsbe | ac | PtP backhaul | Outdoor, integrated dish |

**Key audit differences:**
- Wireless PtP/PtP encryption checks relevant
- Outdoor deployment → physical security not auditable from config
- CAPsMAN relevant for centrally managed deployments
- No LCD, no USB on most models
- Limited to ROS7 on newer models

### 2.7 Specialty Devices

| Model | Family | Key Feature | Audit Notes |
|-------|--------|-------------|-------------|
| Audience (RB Audience) | hAP | Mesh WiFi, Tri-band | CAPsMAN client, no LCD, containers supported |
| Chateau (RBD53iG) | RB | LTE/5G + WiFi | LTE modem checks when available, GPS |
| LtAP (RBLtAP-2HnD) | RB | Vehicle/industrial | GPS, dual-SIM LTE, vibration-resistant |
| KNOT (RB KNOT) | RB | IoT gateway | No WiFi, BLE/Zigbee, no container |
| Cube (Cube 60G) | CPE | 60GHz PtP | Wireless PtP checks, no WiFi |

### 2.8 Virtual Platforms

| Platform | Arch | License Levels | RouterOS Version | Special Constraints |
|----------|------|----------------|------------------|-------------------|
| CHR (Cloud Hosted Router) | x86_64 (amd64) | L3/L4/L5/L6 | v6 + v7 | Pay-per-throughput (L3=1Mbps, L4=200Mbps, L5=unlimited) |
| x86 (bare metal) | x86_64 | L0/L3/L4/L5/L6 | v6 + v7 | Requires physical NIC, limited driver support |

**Key audit differences (CHR):**
- No hardware constraints (no flash pressure, no LCD, no switch chip)
- All hardware-specific checks → N/A (no switch chip, no WiFi, no PoE)
- License throughput limiting → informational check
- No FastTrack limitation
- No container runtime (CHR cannot run containers)

---

## 3. Model Detection

### 3.1 Export Header Parsing

The auditor extracts the device model from the export file header:

```
# 2026-05-24 01:46:15 by RouterOS 7.22.3
# software id = PFNP-CUN7
# model = C53UiG+5HPaxD2HPaxD
# serial number = HDF08RMPMW9
```

The `# model = ...` line contains the board ID. The auditor strips the model string and matches it against device profile regex patterns.

### 3.2 Detection Regex Patterns

Profiles are matched in order (most specific first):

| Family | Subfamily | Regex Pattern | Example Match |
|--------|-----------|---------------|---------------|
| hAP | ac² | `RBD52G|RB952Ui|hAP ac²` | `RBD52G-5HacD2HnD` |
| hAP | ax² | `C52iG|L41G-2axD` | `C52iG-5axD2axD` |
| hAP | ax³ | `C53UiG|L46UGS-5axD2axD` | `C53UiG+5HPaxD2HPaxD` |
| hAP | lite | `RB941|RB951` | `RB941-2nD` |
| CCR | 1036 | `CCR1036` | `CCR1036-8G-2S+` |
| CCR | 1072 | `CCR1072` | `CCR1072-12G-4S` |
| CCR | 2004 | `CCR2004` | `CCR2004-16G-2S+PC` |
| CCR | 2116 | `CCR2116` | `CCR2116-12G-4S+` |
| CCR | 2216 | `CCR2216` | `CCR2216-1G-12S+2Q` |
| CRS | 1xx/2xx | `CRS1[0-9]{2}|CRS2[0-9]{2}` | `CRS125-24G-1S` |
| CRS | 3xx | `CRS[0-9]{3}` | `CRS326-24G-2S+RM` |
| RB | 750 | `RB750Gr3|hEX` | `RB750Gr3` |
| RB | 4011 | `RB4011` | `RB4011iGS+5HacQ2HnD` |
| RB | 5009 | `RB5009` | `RB5009UG+S+` |
| cAP | ac | `RBcAPGi-5ac` | `RBcAPGi-5acD2nD` |
| cAP | ax | `RBcAPGi-5ax` | `RBcAPGi-5axD2axD` |
| wAP | ac | `RBwAPG-5ac` | `RBwAPG-5acD2nD` |
| CHR | — | `CHR` | `CHR` |

### 3.3 Detection Priority

Profiles are checked in order from most specific to most general:

1. Exact board ID match (e.g., `C53UiG`, `CCR1036`)
2. Family prefix match (e.g., `CCR`, `CRS`, `RB`)
3. Generic fallback (generic ARM or MIPS profile)

If no profile matches, the auditor falls back to a generic RouterOS device profile that runs all checks with default severity.

### 3.4 Fallback Behavior

```
State: no profile match → fallback to generic
  - All 108 checks run
  - No severity overrides
  - No N/A exclusions
  - Warning: "Device model not recognized. Run with full check set."
```

---

## 4. How Checks Are Tailored

### 4.1 N/A Exclusion

When a device profile marks a check domain as N/A, the check is completely skipped:

```yaml
# Example: CCR profile marks all WiFi checks as N/A
n_a_checks:
  - "WIFI-001: No wireless hardware on CCR devices"
  - "WIFI-002: No wireless hardware on CCR devices"
  # ... all WIFI-* checks
```

### 4.2 Severity Adjustment

Severity can be overridden per device family:

| Check | Default Severity | Adjusted on hAP ac² | Adjusted on CCR |
|-------|-----------------|---------------------|-----------------|
| NET-006 (bridge VLAN offload) | Info (0.0) | High (7.0) | N/A (no bridge concern) |
| WIFI-012 (flash exhaustion) | Medium (5.0) | High (7.5) | N/A |
| WIFI-013 (AX stability) | Medium (5.0) | High (ax²/ax³ only) | N/A |
| NET-003 (DHCP lease) | Medium (4.9) | High (7.0) | N/A |
| ROUTE-001 (BGP auth) | High (8.2) | N/A | Critical (9.5) |
| FW-005 (bogon filtering) | High (7.8) | High | Critical (9.5) |
| SYS-005 (remote syslog) | Medium (5.5) | Medium | Critical (9.0) |

### 4.3 Severity also Adjusts by Device Role

The interactive onboarding (device_role) further adjusts severity:

| Device Role | Effect on Severity |
|-------------|-------------------|
| Home Router | WAN-side checks relaxed; UPnP → Info; management access → Medium |
| Office/SMB | Default — standard CVSS-based severity |
| Enterprise | RADIUS mandatory; logging → Critical; PMF → Required |
| ISP/DC | BGP/OSPF → Critical; bogon filtering → Critical; conntrack → Critical |

### 4.4 Special Hardware Checks

Some checks only apply to specific hardware:

| Check ID | Name | Applies To | Description |
|----------|------|-----------|-------------|
| WIFI-012 | hAP ac² flash exhaustion | hAP ac² only | 16MB flash + wifi-qcom-ac package = flash crisis risk |
| WIFI-013 | AX stability concern | hAP ax², hAP ax³ | Link-downs in ROS <7.19.2 on ax²/ax³ devices |
| NET-006 | Bridge HW offload | hAP ac², CRS1xx/2xx | VLAN filtering disables HW offload |
| SRV-015 | LCD PIN protection | LCD-equipped only | Physical access risk if LCD unlocked |
| NET-003 | DHCP lease storage | Flash-constrained only | 16MB SPI flash cannot store many leases |
| FW-016 | Conntrack limits | RAM-constrained only | 128MB/64MB devices need reduced max-entries |
| SRV-016 | DNS cache size | RAM-constrained only | 128MB devices should limit cache to 2048 |

---

## 5. Severity Adjustment Rules

### 5.1 RAM-Constrained Devices (<256MB)

Applies to: hAP ac² (128MB), hAP lite (64MB), CRS1xx/2xx (128-256MB), RB750Gr3 (256MB)

| Check | Default Severity | Adjusted |
|-------|-----------------|----------|
| FW-016 (conntrack limits) | High (7.8) | Critical (9.0) |
| SRV-016 (DNS cache size) | Low (3.7) | Medium (5.5) |
| NET-003 (DHCP lease storage) | Medium (4.9) | High (7.0) |
| FW-012 (ICMP rate limiting) | Medium (5.3) | High (7.0) — single core MIPS |

### 5.2 Flash-Constrained Devices (<32MB)

Applies to: hAP ac² (16MB), hAP lite (16MB), RB750Gr3 (16MB), CRS1xx/2xx (16-32MB)

| Check | Default Severity | Adjusted |
|-------|-----------------|----------|
| WIFI-012 (flash exhaustion) | Medium (5.0) | High (7.5) |
| NET-003 (DHCP lease on disk) | Medium (4.9) | High (7.0) |

### 5.3 WiFi Driver-Specific Adjustments

| Condition | Check | Severity |
|-----------|-------|----------|
| wifi-qcom-ac (hAP ac²) | WIFI-012 flash crisis | High (7.5) |
| wifi-qcom-ax (hAP ax²/ax³) with ROS <7.19.2 | WIFI-013 instability | High (7.0) |
| Legacy wireless (hAP lite, RB951) | WIFI-009 PMF | N/A (not supported) |
| Legacy wireless (hAP lite, RB951) | WIFI-007 CAPsMAN | N/A (ROS6 only) |

### 5.4 Role-Based Adjustments

| Device Role | UPnP (SRV-005) | BGP Auth (ROUTE-001) | Remote Syslog (SYS-005) | Bridge VLAN (NET-001) |
|-------------|----------------|----------------------|------------------------|----------------------|
| Home | Info | N/A | Info | Medium |
| Office/SMB | Low | N/A (unused) | Medium | High |
| Enterprise | Medium | High | High | High |
| ISP/DC | High | Critical | Critical | N/A |

---

## 6. Known Hardware-Specific False Positive Patterns

### 6.1 Bridge VLAN Filtering on CRS3xx

**Context:** On CRS3xx switches, bridge VLAN filtering IS the recommended method for VLAN configuration. The switch ACL (`/interface ethernet switch acl`) is for access control, not VLANs.

**False positive pattern:** Auditor flags missing bridge VLAN filtering → should be PASS for CRS3xx devices that use proper bridge VLAN configuration.

### 6.2 L3 HW Offload on CRS3xx

**Context:** CRS3xx with L3 HW offload bypasses the firewall forward chain for offloaded flows. A `chain=forward` rule that appears to block traffic may actually be bypassed.

**False negative pattern:** Auditor reports forward chain as secure → traffic may still flow via HW offload without firewall inspection.

### 6.3 FastTrack on CRS3xx

**Context:** CRS3xx L3 HW offload is incompatible with FastTrack. FastTrack finding should be N/A for CRS3xx.

**False positive pattern:** Auditor flags missing FastTrack as performance concern → on CRS3xx, L3 HW offload replaces FastTrack.

### 6.4 FastTrack on CCR TileGX

**Context:** TileGX-based CCR models (CCR1036, CCR1072) do not support FastTrack at all.

**False positive pattern:** Auditor flags missing FastTrack → should be N/A for TileGX CCRs.

### 6.5 AX Stability on Safe Versions

**Context:** The AX stability check (WIFI-013) must use AND logic: flag only when model IS ax²/ax³ AND version IS <7.19.2.

**False positive pattern:** Using OR logic would flag every hAP ax²/ax³ regardless of RouterOS version.

### 6.6 hAP ac² Flash Warning on Different Devices

**Context:** The WIFI-012 check regex `hAP\s+ac` also matches `hAP ax` due to substring matching.

**False positive pattern:** hAP ax devices incorrectly receive hAP ac² flash warnings.

### 6.7 LCD PIN on Non-LCD Devices

**Context:** The SRV-015 check fires on any `/lcd` configuration regardless of whether the device has a physical LCD.

**False positive pattern:** CHR, CRS, RB5009, and other LCD-less devices could trigger this if a config fragment with LCD settings is present.

### 6.8 WiFi Checks on Non-WiFi Devices

**Context:** All WIFI-* checks run on devices like CCR, CRS, RB5009, RB750Gr3 that have no wireless hardware.

**False positive pattern:** Multiple irrelevant WiFi findings on wired-only devices.

### 6.9 Connection Tracking on RAM-Constrained Devices

**Context:** The default connection tracking max-entries (65536) is too high for 128MB devices. But on 256MB+ devices it's fine.

**False positive pattern:** Auditor flags conntrack with default threshold → should adjust threshold based on device RAM.

---

## 7. Per-Family Check Applicability

| Domain | hAP ac² | hAP ax³ | CCR | CRS3xx | RB5009 | cAP ax | CHR |
|--------|---------|---------|-----|--------|--------|--------|-----|
| AUTH | All | All | All | All | All | All | All |
| SRV | All | All | All | All | All | All | All |
| FW | All | All | All | ⚠ ACL bypass | All | All | All |
| SYS | All | All | All | All | All | All | All |
| NET | ⚠ flash | All | All | ⚠ bridge VLAN | All | ⚠ flash | All |
| ROUTE | Few | Few | All | Many | Many | Few | All |
| WIFI | All | All | — | — | — | All | — |
| SCRIPT | All | All | All | All | All | All | All |
| COMP | All | All | All | All | All | All | All |

- **All**: All checks in domain apply with default or adjusted severity
- **Few/Many**: Subset applies based on typical routing role
- **⚠**: Some checks need special handling (see note)
- **—**: Domain excluded entirely (N/A)

---

## 8. Container-Capable Devices

Container support (via `/container` in RouterOS 7.13+) is available on:

| Device | Container Runtime | Notes |
|--------|-----------------|-------|
| hAP ax² | Docker | 512MB RAM, microSD storage |
| hAP ax³ | Docker | 1GB RAM, microSD storage |
| RB4011 | Docker | 1GB RAM, no SD slot |
| RB5009 | Docker | 1GB RAM, USB storage |
| CCR2004+ | Docker | 4-16GB RAM, USB/SATA |
| CRS3xx (select models) | Docker | Varies by model |
| cAP ax | Docker | 1GB RAM |
| wAP ax | Docker | 1GB RAM |
| Audience | Docker | 512MB RAM |
| LtAP | Docker | Varies |

**Container security considerations for auditor:**
- Container checks apply only to these devices
- Check for privileged containers, /flash mounts, /rw mounts
- Check for container environment variables that may contain secrets
- Check for exposed container ports

Non-container devices: hAP ac², hAP lite, RB750Gr3, CRS1xx/2xx, CHR (CHR cannot run containers)

---

## 9. RouterOS Feature Levels by Platform

| Feature | ARM (hAP ac²) | ARM64 (hAP ax³, RB5009) | TileGX (CCR1036) | MIPS-BE (hAP lite) | x86_64 (CHR) |
|---------|---------------|------------------------|-------------------|--------------------|---------------|
| ROS7 support | ✅ | ✅ | ✅ | ❌ (v6 only) | ✅ |
| FastTrack | ✅ | ✅ | ❌ | ✅ | ✅ |
| HW offload | ✅ conditional | ✅ | N/A | ✅ | N/A |
| L3 HW offload | ❌ | ❌ | ✅ (CCR) | ❌ | N/A |
| WireGuard | ✅ | ✅ | ✅ | ❌ | ✅ |
| CAPsMAN | ✅ | ✅ | ❌ | ✅ | ❌ |
| Containers | ❌ | ✅ | ✅ (2004+) | ❌ | ❌ (CHR) |
| BGP/OSPF | ✅ | ✅ | ✅ | ⚠ limited | ✅ |
| IPSec HW accel | ❌ | ❌ | ✅ | ❌ | ❌ |
| ZeroTier | ✅ | ✅ | ✅ | ❌ | ✅ |
| WiFi qcom-ac | ✅ | ❌ | N/A | N/A | N/A |
| WiFi qcom-ax | ❌ | ✅ | N/A | N/A | N/A |
| SNMP | ✅ | ✅ | ✅ | ✅ | ✅ |
| LCD | ❌ | ax³ only | CCR1036 only | ❌ | N/A |

---

## 10. Adding New Device Profiles

### 10.1 Profile Registration

To add support for a new MikroTik device:

1. **Identify the board ID** from the export header or `system routerboard print` output
2. **Determine the hardware specs** from the official MikroTik product page
3. **Create a device profile** entry with correct specifications
4. **Add detection regex** to the model matching table
5. **Define audit integration** (N/A exclusions, severity overrides, special checks)

### 10.2 Profile Template

```yaml
<device_key>:
  model_pattern: "<board-id-regex>"
  family: "<family>"
  subfamily: "<sub>"
  arch: "<arch>"
  cpu: "<model>"
  cpu_cores: <n>
  ram_mb: <n>
  flash_mb: <n>
  flash_type: "<type>"
  wifi: false | "<driver>"
  wifi_bands: false | "<bands>"
  switch_chip: null | "<model>"
  hardware_offload: true | false | "conditional"
  lcd: false | true
  container: false | "docker"
  min_ros7: "<version>"
  routeros_level: "Level<n>"
  capsman_controller: bool
  capsman_client: bool
  special_checks:
    - "<CHECK-ID>: description"
  severity_overrides:
    "<CHECK-ID>": "<severity>"
  n_a_checks:
    - "<CHECK-ID>: reason"
  applicable_domains:
    - "AUTH" | "SRV" | "FW" | "SYS" | "NET" | "ROUTE" | "WIFI" | "SCRIPT" | "COMP"
```

### 10.3 Testing New Profiles

After adding a profile:

1. Run the auditor against an export from the target device
2. Verify the device model is correctly detected
3. Verify N/A checks are excluded from the report
4. Verify severity overrides are applied
5. Verify no false positives from generic checks
6. Check that WiFi checks are excluded for non-WiFi devices
7. Check that routing checks are appropriately prioritized

### 10.4 Sources for Hardware Specifications

- Official MikroTik product pages: `https://mikrotik.com/product/<name>`
- RouterOS release notes for device-specific fixes
- `system routerboard print` on the live device
- `system resource print` for RAM/CPU/architecture
- `/export verbose` for full configuration dump

---

## References

- [AUDIT_CHECKS.md](AUDIT_CHECKS.md) — Check definitions with hardware notes
- [SECURITY_BASELINE.md](SECURITY_BASELINE.md) — Secure configuration baseline
- [SYNTAX_REFERENCE.md](SYNTAX_REFERENCE.md) — RouterOS syntax reference
- [device_profiles.py](../scripts/device_profiles.py) — Device profile data and detection logic
- MikroTik Product Pages: https://mikrotik.com/products
- RouterOS Manual: https://help.mikrotik.com/docs/
