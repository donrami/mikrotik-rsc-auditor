"""
Device Profile Database for MikroTik RouterOS Hardware
=======================================================

Maps export header model strings to hardware profiles, enabling
hardware-aware audit check tailoring across 15+ device families.

Usage:
    from device_profiles import detect_device, get_profile

    device_key = detect_device(header_lines)
    profile = get_profile(device_key)
    if profile.wifi:
        # Run WiFi-specific checks
    if not profile.has_hw_offload:
        # Skip HW offload checks
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import re


# ──────────────────────────────────────────────────────────────────────────
# Data Model
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class DeviceProfile:
    """Hardware and capability profile for a MikroTik device family."""
    # Identity
    model_pattern: str               # Regex matching "# model = ..." in export header
    family: str                      # hAP | CCR | CRS | RB | cAP | wAP | LHG | CHR
    subfamily: str                   # ax³ | ax² | ac² | etc.

    # CPU / Architecture
    cpu: str                         # IPQ-6010, IPQ-5010, AL324, etc.
    cpu_arch: str                    # ARM | ARM64 | MIPS64 | x86_64 | TileGX
    cpu_cores: int = 0

    # Memory
    ram_mb: int = 0
    flash_mb: int = 0

    # WiFi
    wifi: Optional[str] = None       # None | legacy | wifi-qcom-ac | wifi-qcom-ax
    wifi_bands: Optional[str] = None # None | "2.4" | "5" | "2.4+5"

    # Switching
    switch_chip: Optional[str] = None
    has_hw_offload: bool = False

    # System
    has_lcd: bool = False
    has_container: bool = False
    routeros_level: str = "Level4"

    # Licenses
    fasttrack_supported: bool = True  # False for TileGX CCRs


# ──────────────────────────────────────────────────────────────────────────
# Device Profile Database
# ──────────────────────────────────────────────────────────────────────────

DEVICE_PROFILES: Dict[str, DeviceProfile] = {
    # ═══ hAP Series ═══════════════════════════════════════════════════════

    "hap_ax3": DeviceProfile(
        model_pattern=r"C53UiG\+5HPaxD2HPaxD",
        family="hAP",
        subfamily="ax³",
        cpu="IPQ-6010",
        cpu_arch="ARM64",
        cpu_cores=4,
        ram_mb=1024,
        flash_mb=128,
        wifi="wifi-qcom-ax",
        wifi_bands="2.4+5",
        switch_chip="MT7531",
        has_hw_offload=True,
        has_lcd=True,
        has_container=True,
        routeros_level="Level4",
    ),

    "hap_ax2": DeviceProfile(
        model_pattern=r"C52iG.*5HPaxD2HPaxD",
        family="hAP",
        subfamily="ax²",
        cpu="IPQ-5010",
        cpu_arch="ARM64",
        cpu_cores=2,
        ram_mb=512,
        flash_mb=128,
        wifi="wifi-qcom-ax",
        wifi_bands="2.4+5",
        switch_chip="MT7531",
        has_hw_offload=True,
        has_lcd=False,
        has_container=False,
        routeros_level="Level4",
    ),

    "hap_ac2": DeviceProfile(
        model_pattern=r"RBD52G",
        family="hAP",
        subfamily="ac²",
        cpu="IPQ-4018",
        cpu_arch="ARM",
        cpu_cores=4,
        ram_mb=128,
        flash_mb=16,
        wifi="wifi-qcom-ac",
        wifi_bands="2.4+5",
        switch_chip="QCA8337",
        has_hw_offload=True,
        has_lcd=False,
        has_container=False,
        routeros_level="Level4",
    ),

    # ═══ RB / Wired Series ═══════════════════════════════════════════════

    "rb5009": DeviceProfile(
        model_pattern=r"RB5009UG\+S\+IN",
        family="RB",
        subfamily="5009",
        cpu="IPQ-6010",
        cpu_arch="ARM64",
        cpu_cores=4,
        ram_mb=1024,
        flash_mb=128,
        wifi=None,
        wifi_bands=None,
        switch_chip="MT7531",
        has_hw_offload=True,
        has_lcd=False,
        has_container=True,
        routeros_level="Level5",
    ),

    "rb4011": DeviceProfile(
        model_pattern=r"RB4011iGS",
        family="RB",
        subfamily="4011",
        cpu="IPQ-8074",
        cpu_arch="ARM64",
        cpu_cores=4,
        ram_mb=1024,
        flash_mb=512,
        wifi=None,
        wifi_bands=None,
        switch_chip="IPQ-8074 internal",
        has_hw_offload=True,
        has_lcd=True,
        has_container=True,
        routeros_level="Level5",
    ),

    "hex_s": DeviceProfile(
        model_pattern=r"RB760iGS",
        family="RB",
        subfamily="hEX S",
        cpu="IPQ-4018",
        cpu_arch="ARM",
        cpu_cores=4,
        ram_mb=256,
        flash_mb=128,
        wifi=None,
        wifi_bands=None,
        switch_chip="QCA8337",
        has_hw_offload=True,
        has_lcd=False,
        has_container=False,
        routeros_level="Level5",
    ),

    # ═══ CCR Series ═══════════════════════════════════════════════════════

    "ccr1036": DeviceProfile(
        model_pattern=r"CCR1036",
        family="CCR",
        subfamily="1036",
        cpu="TLK10236 (TileGX)",
        cpu_arch="TileGX",
        cpu_cores=36,
        ram_mb=2048,
        flash_mb=1024,
        wifi=None,
        wifi_bands=None,
        switch_chip=None,
        has_hw_offload=False,
        has_lcd=False,
        has_container=False,
        routeros_level="Level6",
        fasttrack_supported=False,
    ),

    "ccr2004": DeviceProfile(
        model_pattern=r"CCR2004",
        family="CCR",
        subfamily="2004",
        cpu="AL324 (Alpine ARM64)",
        cpu_arch="ARM64",
        cpu_cores=4,
        ram_mb=4096,
        flash_mb=1024,
        wifi=None,
        wifi_bands=None,
        switch_chip=None,
        has_hw_offload=False,
        has_lcd=False,
        has_container=True,
        routeros_level="Level6",
    ),

    "ccr2116": DeviceProfile(
        model_pattern=r"CCR2116",
        family="CCR",
        subfamily="2116",
        cpu="AL736 (Alpine ARM64)",
        cpu_arch="ARM64",
        cpu_cores=16,
        ram_mb=8192,
        flash_mb=1024,
        wifi=None,
        wifi_bands=None,
        switch_chip=None,
        has_hw_offload=False,
        has_lcd=False,
        has_container=True,
        routeros_level="Level6",
    ),

    # ═══ CRS Series ══════════════════════════════════════════════════════

    "crs317": DeviceProfile(
        model_pattern=r"CRS317",
        family="CRS",
        subfamily="317",
        cpu="98DX8212",
        cpu_arch="ARM64",
        cpu_cores=2,
        ram_mb=1024,
        flash_mb=128,
        wifi=None,
        wifi_bands=None,
        switch_chip="Marvell 98DX8212",
        has_hw_offload=True,
        has_lcd=False,
        has_container=False,
        routeros_level="Level5",
    ),

    "crs326": DeviceProfile(
        model_pattern=r"CRS326",
        family="CRS",
        subfamily="326",
        cpu="98DX3236",
        cpu_arch="MIPS",
        cpu_cores=2,
        ram_mb=512,
        flash_mb=128,
        wifi=None,
        wifi_bands=None,
        switch_chip="Marvell 98DX3236",
        has_hw_offload=True,
        has_lcd=False,
        has_container=False,
        routeros_level="Level5",
    ),

    "crs309": DeviceProfile(
        model_pattern=r"CRS309",
        family="CRS",
        subfamily="309",
        cpu="98DX8208",
        cpu_arch="ARM64",
        cpu_cores=2,
        ram_mb=1024,
        flash_mb=128,
        wifi=None,
        wifi_bands=None,
        switch_chip="Marvell 98DX8208",
        has_hw_offload=True,
        has_lcd=False,
        has_container=False,
        routeros_level="Level5",
    ),

    # ═══ cAP Series ══════════════════════════════════════════════════════

    "cap_ax": DeviceProfile(
        model_pattern=r"cAPGi.*5HaxD2HaxD",
        family="cAP",
        subfamily="ax",
        cpu="IPQ-5010",
        cpu_arch="ARM64",
        cpu_cores=2,
        ram_mb=512,
        flash_mb=128,
        wifi="wifi-qcom-ax",
        wifi_bands="2.4+5",
        switch_chip=None,
        has_hw_offload=False,
        has_lcd=False,
        has_container=False,
        routeros_level="Level4",
    ),

    # ═══ CHR / Virtual ════════════════════════════════════════════════════

    "chr": DeviceProfile(
        model_pattern=r"CHR",
        family="CHR",
        subfamily="",
        cpu="x86_64 (variable)",
        cpu_arch="x86_64",
        cpu_cores=0,
        ram_mb=0,
        flash_mb=0,
        wifi=None,
        wifi_bands=None,
        switch_chip=None,
        has_hw_offload=False,
        has_lcd=False,
        has_container=True,
        routeros_level="Level3",
    ),

    # ═══ Wireless CPE ═════════════════════════════════════════════════════

    "lhg5ac": DeviceProfile(
        model_pattern=r"LHG.*5.*ac|RBLHG.*5nD",
        family="LHG",
        subfamily="5ac",
        cpu="QCA9563",
        cpu_arch="MIPS",
        cpu_cores=1,
        ram_mb=128,
        flash_mb=16,
        wifi="legacy",
        wifi_bands="5",
        switch_chip=None,
        has_hw_offload=False,
        has_lcd=False,
        has_container=False,
        routeros_level="Level4",
    ),

    "wap_ac": DeviceProfile(
        model_pattern=r"wAP.*5Hac2HnD|RBwAPG",
        family="wAP",
        subfamily="ac",
        cpu="IPQ-4018",
        cpu_arch="ARM",
        cpu_cores=4,
        ram_mb=128,
        flash_mb=16,
        wifi="legacy",
        wifi_bands="2.4+5",
        switch_chip=None,
        has_hw_offload=False,
        has_lcd=False,
        has_container=False,
        routeros_level="Level4",
    ),

    "wap_ax": DeviceProfile(
        model_pattern=r"wAP.*ax|RBwAP.*ax",
        family="wAP",
        subfamily="ax",
        cpu="IPQ-5010",
        cpu_arch="ARM64",
        cpu_cores=2,
        ram_mb=512,
        flash_mb=128,
        wifi="wifi-qcom-ax",
        wifi_bands="2.4+5",
        switch_chip=None,
        has_hw_offload=False,
        has_lcd=False,
        has_container=False,
        routeros_level="Level4",
    ),
}


# ──────────────────────────────────────────────────────────────────────────
# Detection Functions
# ──────────────────────────────────────────────────────────────────────────

def detect_from_model_line(model_line: str) -> Optional[str]:
    """Match a '# model = ...' line to a device profile key.
    
    Returns the device_key string or None if no match found.
    """
    if not model_line:
        return None
    
    # Strip '# model = ' or similar prefix
    model = model_line.strip()
    for prefix in ["# model = ", "# model: ", "model = ", "model: "]:
        if model.startswith(prefix):
            model = model[len(prefix):]
            break
    
    if not model:
        return None
    
    # Try exact match first
    for key, profile in DEVICE_PROFILES.items():
        if re.search(profile.model_pattern, model):
            return key
    
    return None


def detect_device(header_lines: List[str]) -> Optional[str]:
    """Parse export header lines to detect the device model.
    
    Expected format in export header:
        # 2026-05-24 01:46:15 by RouterOS 7.22.3
        # software id = PFNP-CUN7
        # model = C53UiG+5HPaxD2HPaxD
        # serial number = HDF08RMPMW9
    
    Returns device_key string or None.
    """
    if not header_lines:
        return None
    
    # First pass: look for explicit "# model = " line
    for line in header_lines:
        stripped = line.strip()
        for prefix in ["# model = ", "# model: "]:
            if stripped.startswith(prefix):
                return detect_from_model_line(stripped)
    
    # Second pass: check for model embedded in other header lines
    for line in header_lines:
        stripped = line.strip()
        for key, profile in DEVICE_PROFILES.items():
            if re.search(profile.model_pattern, stripped):
                return key
    
    return None


def get_profile(device_key: str) -> Optional[DeviceProfile]:
    """Look up a DeviceProfile by device_key string."""
    return DEVICE_PROFILES.get(device_key)


def get_profile_family(family: str) -> List[Tuple[str, DeviceProfile]]:
    """Return all profiles belonging to a device family."""
    return [(k, p) for k, p in DEVICE_PROFILES.items() if p.family == family]


def list_all_devices() -> List[str]:
    """Return all known device keys."""
    return sorted(DEVICE_PROFILES.keys())


# ──────────────────────────────────────────────────────────────────────────
# CLI Quick Check
# ──────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"Device profiles loaded: {len(DEVICE_PROFILES)}")
    for key, profile in sorted(DEVICE_PROFILES.items()):
        wifi = profile.wifi or "no WiFi"
        switch = profile.switch_chip or "CPU-bridged"
        lcd = " LCD" if profile.has_lcd else ""
        cont = " containers" if profile.has_container else ""
        print(f"  {key:12s} | {profile.family:6s} | {profile.cpu_arch:8s} | "
              f"{profile.ram_mb:5d}MB RAM | {wifi:15s} | {switch:20s} | "
              f"{profile.routeros_level}{lcd}{cont}")
