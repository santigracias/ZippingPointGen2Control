"""
Shared configuration for the Neo wireless communication system.

All tunable parameters (OUI, MAC, channel, TX rate, interface, etc.)
are centralised here so every module uses the same defaults.
"""

import os

# ---------------------------------------------------------------------------
# 802.11 / Vendor IE
# ---------------------------------------------------------------------------
TARGET_OUI = b"\x74\xb8\x0f"           # 74:b8:0f
TARGET_OUI_STR = "74:b8:0f"

VENDOR_IE_ID = 221                       # Dot11Elt ID for vendor-specific

# Vendor IE Type bytes — chosen to avoid collision with existing V2V types
# (0x01–0x06, 0x99 are taken). Confirm these with the team.
IE_TYPE_HANDOFF_COMMAND  = 0x10          # DroidZippingPointCommand
IE_TYPE_HANDOFF_RESPONSE = 0x11          # DroidZippingPointResponse

# ---------------------------------------------------------------------------
# MAC addresses
# ---------------------------------------------------------------------------
DEFAULT_SRC_MAC = "11:22:33:44:55:66"
BROADCAST_MAC   = "ff:ff:ff:ff:ff:ff"

# ---------------------------------------------------------------------------
# Radio
# ---------------------------------------------------------------------------
DEFAULT_INTERFACE = "mon0"
DEFAULT_CHANNEL   = 6
DEFAULT_TX_RATE_HZ = 10                  # Beacon transmit rate (Hz)

# ---------------------------------------------------------------------------
# ZMD
# ---------------------------------------------------------------------------
# Path to the flattened ZMD file.
# On the Neo this must be present at the path below (relative to the script).
DEFAULT_ZMD_FILE = os.path.join(os.path.dirname(__file__), "zmd", "droid_zipping_point.zmd")

# Struct names inside the ZMD (must match the ZMD file exactly)
ZMD_COMMAND_STRUCT  = "DroidZippingPointCommand"
ZMD_RESPONSE_STRUCT = "DroidZippingPointResponse"
