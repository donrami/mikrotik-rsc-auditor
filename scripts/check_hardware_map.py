"""
check_hardware_map.py — Hardware-to-Check Applicability Map

Maps every audit check (AUTH-001 through COMP-006) to hardware-specific
behavior rules: which families/devices it applies to, severity overrides,
version thresholds, and N/A exclusions.

Most checks apply to ALL hardware. Only hardware-specific checks
(about 25 of 108) are explicitly listed with mapping rules.

Device families:
  hAP_ac2, hAP_ax2, hAP_ax3, hAP_lite, CCR_various, CRS_3xx,
  CRS_1xx_2xx, RB_750, RB_5009, RB_4011, RB_3011, Chateau,
  LtAP_wAP, mANT_LHG_SXTs, CHR_x86, CAP

Usage:
    from check_hardware_map import CHECK_HARDWARE_MAP, get_check_rules

    rules = get_check_rules("WIFI-012", device_family="hAP", device_model="hAP_ac2")
    if rules["na"]:
        print("N/A for this device")
    severity = rules["severity"]  # adjusted severity if applicable
"""

from typing import Any, Dict, Optional

# ── Device Family Constants ─────────────────────────────────────────────

FAMILY_HAP = "hAP"
FAMILY_CCR = "CCR"
FAMILY_CRS = "CRS"
FAMILY_RB = "RB"
FAMILY_CHR = "CHR"
FAMILY_CHATEAU = "Chateau"
FAMILY_LTAP = "LtAP_wAP"
FAMILY_MANT = "mANT_LHG_SXTs"
FAMILY_CAP = "CAP"

MODEL_HAP_AC2 = "hAP_ac2"
MODEL_HAP_AX2 = "hAP_ax2"
MODEL_HAP_AX3 = "hAP_ax3"
MODEL_HAP_LITE = "hAP_lite"
MODEL_CCR = "CCR_various"
MODEL_CRS_3XX = "CRS_3xx"
MODEL_CRS_1XX_2XX = "CRS_1xx_2xx"
MODEL_RB_750 = "RB_750"
MODEL_RB_5009 = "RB_5009"
MODEL_RB_4011 = "RB_4011"
MODEL_RB_3011 = "RB_3011"
MODEL_CHATEAU = "Chateau_various"
MODEL_LTAP = "LtAP_wAP"
MODEL_MANT = "mANT_LHG_SXTs"
MODEL_CHR = "CHR_x86"
MODEL_CAP = "CAP"

# ── Check Hardware Map ──────────────────────────────────────────────────

CHECK_HARDWARE_MAP: Dict[str, Dict[str, Any]] = {
    # ═══════════════════════════════════════════════════════════════════
    # WIFI DOMAIN — only applies to devices with WiFi radios
    # ═══════════════════════════════════════════════════════════════════
    "WIFI-001": {
        "applicable_families": [FAMILY_HAP, FAMILY_CHATEAU, FAMILY_LTAP, FAMILY_MANT, FAMILY_CAP],
        "applicable_models": None,  # all WiFi devices in those families
        "na_if_not_applicable": True,
        "notes": "Insecure encryption — only WiFi-capable devices"
    },
    "WIFI-002": {
        "applicable_families": [FAMILY_HAP, FAMILY_CHATEAU, FAMILY_LTAP, FAMILY_MANT, FAMILY_CAP],
        "na_if_not_applicable": True,
        "notes": "WPS — only WiFi devices"
    },
    "WIFI-003": {
        "applicable_families": [FAMILY_HAP, FAMILY_CHATEAU, FAMILY_LTAP, FAMILY_MANT, FAMILY_CAP],
        "na_if_not_applicable": True,
        "notes": "Guest isolation — only WiFi devices"
    },
    "WIFI-004": {
        "applicable_families": [FAMILY_HAP, FAMILY_CHATEAU, FAMILY_LTAP, FAMILY_MANT, FAMILY_CAP],
        "na_if_not_applicable": True,
        "notes": "Hidden SSID — only WiFi devices"
    },
    "WIFI-005": {
        "applicable_families": [FAMILY_HAP, FAMILY_CHATEAU, FAMILY_LTAP, FAMILY_MANT, FAMILY_CAP],
        "na_if_not_applicable": True,
        "notes": "Per-band profiles — only multi-band WiFi devices"
    },
    "WIFI-006": {
        "applicable_families": [FAMILY_HAP, FAMILY_CHATEAU, FAMILY_LTAP, FAMILY_MANT, FAMILY_CAP],
        "na_if_not_applicable": True,
        "notes": "Client isolation — only WiFi devices"
    },
    "WIFI-007": {
        "applicable_families": [FAMILY_HAP, FAMILY_CHATEAU, FAMILY_LTAP, FAMILY_CAP],
        "na_if_not_applicable": True,
        "notes": "CAPsMAN — only devices that can act as CAPsMAN controller"
    },
    "WIFI-008": {
        "applicable_families": [FAMILY_HAP, FAMILY_CHATEAU, FAMILY_LTAP, FAMILY_MANT, FAMILY_CAP],
        "na_if_not_applicable": True,
        "notes": "Access list — only WiFi devices"
    },
    "WIFI-009": {
        "applicable_families": [FAMILY_HAP, FAMILY_CHATEAU, FAMILY_LTAP, FAMILY_MANT, FAMILY_CAP],
        "na_if_not_applicable": True,
        "notes": "PMF — only WiFi devices"
    },
    "WIFI-010": {
        "applicable_families": [FAMILY_HAP, FAMILY_CHATEAU, FAMILY_LTAP, FAMILY_MANT, FAMILY_CAP],
        "na_if_not_applicable": True,
        "notes": "Password strength — only WiFi devices"
    },
    "WIFI-011": {
        "applicable_families": [FAMILY_HAP, FAMILY_CHATEAU, FAMILY_LTAP, FAMILY_MANT, FAMILY_CAP],
        "na_if_not_applicable": True,
        "notes": "DFS channels — only WiFi devices"
    },
    "WIFI-012": {
        "applicable_families": [FAMILY_HAP],
        "applicable_models": [MODEL_HAP_AC2],
        "severity_override": {"default": "High", MODEL_HAP_AC2: "High"},
        "na_if_not_applicable": True,
        "notes": "hAP ac² wifi-qcom-ac flash exhaustion — only on hAP ac²"
    },
    "WIFI-013": {
        "applicable_families": [FAMILY_HAP],
        "applicable_models": [MODEL_HAP_AX2, MODEL_HAP_AX3],
        "version_threshold": "7.19.2",
        "na_if_not_applicable": True,
        "notes": "Too many SSIDs — only relevant if device has WiFi radios"
    },

    # ═══════════════════════════════════════════════════════════════════
    # NETWORK DOMAIN — hardware-specific thresholds and exclusions
    # ═══════════════════════════════════════════════════════════════════
    "NET-001": {
        "severity_override": {
            "default": "High",
            MODEL_HAP_AC2: "Medium",  # enabling vlan-filtering DISABLES HW offload
            MODEL_CRS_3XX: "High",    # expected on switches
            MODEL_CRS_1XX_2XX: "Medium",
        },
        "notes": "Bridge VLAN filtering — hAP ac² loses HW offload when enabled"
    },
    "NET-003": {
        "applicable_families": [FAMILY_HAP],
        "applicable_models": [MODEL_HAP_AC2, MODEL_HAP_LITE],
        "severity_override": {"default": "Medium", MODEL_HAP_AC2: "Medium"},
        "na_if_not_applicable": True,
        "notes": "DHCP lease storage on flash-constrained — hAP ac², hAP lite only"
    },
    "NET-006": {
        "applicable_families": [FAMILY_HAP],
        "applicable_models": [MODEL_HAP_AC2],
        "severity_override": {"default": "High", MODEL_HAP_AC2: "High"},
        "na_if_not_applicable": True,
        "notes": "Bridge HW offload misconfiguration — hAP ac² only"
    },
    "NET-007": {
        "severity_override": {
            "default": "Medium",
            MODEL_CCR: "Low",  # CCR handles jumbo frames natively
        },
        "notes": "MTU/fragmentation — CCR has jumbo frame support"
    },

    # ═══════════════════════════════════════════════════════════════════
    # SYSTEM DOMAIN — hardware-dependent thresholds
    # ═══════════════════════════════════════════════════════════════════
    "SRV-015": {
        "applicable_families": [FAMILY_HAP, FAMILY_RB],
        "applicable_models": [MODEL_HAP_AC2, MODEL_HAP_AX3, MODEL_RB_4011],
        "na_if_not_applicable": True,
        "notes": "LCD not secured — only devices with physical LCD"
    },
    "SRV-016": {
        "threshold_ram_mb": 128,      # warn if cache-size > 2048 on ≤128MB devices
        "notes": "DNS cache size — 128MB RAM devices should limit to 2048KiB"
    },
    "FW-007": {
        "severity_override": {
            "default": "Medium",
            MODEL_HAP_AC2: "High",    # CPU-switched — massive benefit from FastTrack
            MODEL_CCR: "Low",         # HW offload already at line rate
            MODEL_CRS_3XX: "Low",     # switch chip offload, FastTrack irrelevant
            MODEL_CRS_1XX_2XX: "Low",
            MODEL_CHR: "Info",        # virtual — FastTrack has limited benefit
        },
        "notes": "FastTrack value varies dramatically by hardware"
    },
    "FW-016": {
        "threshold_ram_mb": 512,      # warn if max-entries too high for RAM
        "severity_override": {
            "default": "High",
            MODEL_HAP_AC2: "High",    # 128MB RAM — OOM risk at 32K entries
            MODEL_CCR: "Low",         # 4-16GB RAM — can handle 512K+
            MODEL_CHR: "Low",         # dynamic memory
        },
        "notes": "Connection tracking limits — RAM-dependent thresholds"
    },

    # ═══════════════════════════════════════════════════════════════════
    # ROUTING DOMAIN — severity varies by device role/capability
    # ═══════════════════════════════════════════════════════════════════
    "ROUTE-001": {
        "severity_override": {
            "default": "High",
            MODEL_HAP_LITE: "Info",   # hAP lite unlikely to run BGP
        },
        "notes": "BGP MD5 — enterprise feature, low severity on SOHO hardware"
    },
    "ROUTE-002": {
        "severity_override": {
            "default": "High",
            MODEL_HAP_LITE: "Info",
        },
        "notes": "OSPF auth — enterprise feature"
    },
    "ROUTE-003": {
        "severity_override": {
            "default": "High",
            MODEL_HAP_LITE: "Info",
        },
        "notes": "Routing filters — enterprise feature"
    },
    "ROUTE-004": {
        "severity_override": {
            "default": "Medium",
            MODEL_HAP_LITE: "Info",
        },
        "notes": "BGP TTL security — enterprise feature"
    },
    "ROUTE-005": {
        "severity_override": {
            "default": "High",
            MODEL_HAP_LITE: "Info",
        },
        "notes": "BGP prefix limits — enterprise feature"
    },
    "ROUTE-006": {
        "severity_override": {
            "default": "High",
            MODEL_HAP_LITE: "Info",
        },
        "notes": "Dynamic routing on WAN — enterprise concern"
    },
    "ROUTE-007": {
        "severity_override": {
            "default": "Medium",
            MODEL_CCR: "High",       # CCR as core router — critical
        },
        "notes": "Default route resilience — CCR as core router needs this"
    },
    "ROUTE-008": {
        "severity_override": {
            "default": "Low",
            MODEL_CCR: "Medium",
            MODEL_CRS_3XX: "Medium",
        },
        "notes": "Loopback router ID — important on routing-heavy platforms"
    },

    # ═══════════════════════════════════════════════════════════════════
    # SERVICE DOMAIN — LCD only
    # ═══════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════
    # FIREWALL DOMAIN — FastTrack varies by hardware
    # ═══════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════
    # SCRIPT & AUTH — apply to ALL hardware (no specializations needed)
    # ═══════════════════════════════════════════════════════════════════
}

# ── Lookup Function ─────────────────────────────────────────────────────

def get_check_rules(
    check_id: str,
    device_family: Optional[str] = None,
    device_model: Optional[str] = None,
) -> Dict[str, Any]:
    """Get effective rules for a check given device context.
    
    Returns:
        dict with keys:
            - na: bool — True if this check is N/A for this device
            - severity: str — adjusted severity (or None for default)
            - version_threshold: str — minimum version threshold (or None)
            - notes: str — rationale
    """
    rules = CHECK_HARDWARE_MAP.get(check_id, {})
    
    result = {
        "na": False,
        "severity": None,
        "version_threshold": rules.get("version_threshold"),
        "notes": rules.get("notes", ""),
    }
    
    # Check N/A applicability
    na_if_not = rules.get("na_if_not_applicable", False)
    if na_if_not and (device_family or device_model):
        applicable_families = rules.get("applicable_families")
        applicable_models = rules.get("applicable_models")
        
        family_match = applicable_families is None or (
            device_family and device_family in applicable_families
        )
        model_match = applicable_models is None or (
            device_model and device_model in applicable_models
        )
        
        if applicable_families and not family_match:
            result["na"] = True
        if applicable_models and not model_match:
            result["na"] = True
    
    # Check severity override
    severity_map = rules.get("severity_override", {})
    if severity_map and device_model and device_model in severity_map:
        result["severity"] = severity_map[device_model]
    elif severity_map and "default" in severity_map:
        result["severity"] = severity_map["default"]
    
    return result


def get_all_hardware_specific_checks() -> Dict[str, Dict[str, Any]]:
    """Return only the checks that have hardware-specific rules."""
    return {
        k: v for k, v in CHECK_HARDWARE_MAP.items()
        if v.get("na_if_not_applicable")
        or v.get("severity_override")
        or v.get("threshold_ram_mb")
        or v.get("version_threshold")
    }
