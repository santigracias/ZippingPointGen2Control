"""
ZMD-based encode / decode for the vendor-specific information element payload.

Vendor IE layout (inside Dot11Elt ID=221):
    [OUI  3 bytes][Type 1 byte][ZMD-serialized payload  N bytes]

Type bytes:
    0x10 — DroidZippingPointCommand
    0x11 — DroidZippingPointResponse

Both sides (ZP and droid) use the same ZMD runtime for serialization,
guaranteeing wire-compatible encoding.

Usage:
    zmd_codec = ZmdCodec()                          # loads the ZMD once
    ie_bytes  = zmd_codec.encode_command(cmd_dict)   # dict → vendor IE bytes
    cmd_dict  = zmd_codec.decode_command(ie_bytes)   # vendor IE bytes → dict
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from config import (
    DEFAULT_ZMD_FILE,
    IE_TYPE_HANDOFF_COMMAND,
    IE_TYPE_HANDOFF_RESPONSE,
    TARGET_OUI,
    ZMD_COMMAND_STRUCT,
    ZMD_RESPONSE_STRUCT,
)

from zmd_runtime import runtime_zipline_message as _runtime


# ---------------------------------------------------------------------------
# Vendor IE helpers
# ---------------------------------------------------------------------------

def build_vendor_ie(type_byte: int, payload: bytes) -> bytes:
    """Build the full vendor IE *info* field: OUI + Type + payload."""
    return TARGET_OUI + bytes([type_byte]) + payload


def parse_vendor_ie(info: bytes) -> tuple[bytes, int, bytes]:
    """Parse a vendor IE info field → (oui, type_byte, payload).

    Raises ``ValueError`` if the info field is too short.
    """
    if len(info) < 4:
        raise ValueError(f"Vendor IE info too short ({len(info)} bytes)")
    return info[:3], info[3], info[4:]


# ---------------------------------------------------------------------------
# ZMD Codec — single entry point for encode / decode
# ---------------------------------------------------------------------------

class ZmdCodec:
    """Encodes and decodes handoff messages using the ZMD runtime.

    Loads the flattened ZMD file once and provides symmetrical
    ``encode_*`` / ``decode_*`` methods for commands and responses.

    The encoded bytes include the OUI + type header, ready to be dropped
    into a ``Dot11Elt(ID=221, info=...)``.
    """

    def __init__(self, zmd_file: str = DEFAULT_ZMD_FILE) -> None:
        with open(zmd_file) as f:
            annotations = f.read()

        self._zmd = _runtime.from_annotations(annotations)

    # -- helpers --------------------------------------------------------------

    @property
    def zmd(self):
        """Expose the underlying ZMD runtime instance."""
        return self._zmd

    def create_command(self) -> Mapping[str, Any]:
        """Return a new empty DroidZippingPointCommand dict."""
        return self._zmd.create(ZMD_COMMAND_STRUCT)

    def create_response(self) -> Mapping[str, Any]:
        """Return a new empty DroidZippingPointResponse dict."""
        return self._zmd.create(ZMD_RESPONSE_STRUCT)

    # -- command encode / decode ----------------------------------------------

    def encode_command(self, msg: Mapping[str, Any]) -> bytes:
        """Serialize a command dict → full vendor IE info bytes."""
        payload = self._zmd.serialize(ZMD_COMMAND_STRUCT, msg)
        return build_vendor_ie(IE_TYPE_HANDOFF_COMMAND, payload)

    def encode_command_payload(self, msg: Mapping[str, Any]) -> bytes:
        """Serialize a command dict → raw ZMD payload bytes."""
        return self._zmd.serialize(ZMD_COMMAND_STRUCT, msg)

    def decode_command(self, ie_info: bytes) -> Mapping[str, Any]:
        """Deserialize vendor IE info bytes → command dict.

        Raises ``ValueError`` if the type byte doesn't match.
        """
        oui, type_byte, payload = parse_vendor_ie(ie_info)
        if type_byte != IE_TYPE_HANDOFF_COMMAND:
            raise ValueError(
                f"Expected command type {IE_TYPE_HANDOFF_COMMAND:#x}, "
                f"got {type_byte:#x}"
            )
        return self._zmd.deserialize(ZMD_COMMAND_STRUCT, payload)

    def decode_command_payload(self, payload: bytes) -> Mapping[str, Any]:
        """Deserialize raw ZMD payload bytes → command dict."""
        return self._zmd.deserialize(ZMD_COMMAND_STRUCT, payload)

    # -- response encode / decode ---------------------------------------------

    def encode_response(self, msg: Mapping[str, Any]) -> bytes:
        """Serialize a response dict → full vendor IE info bytes."""
        payload = self._zmd.serialize(ZMD_RESPONSE_STRUCT, msg)
        return build_vendor_ie(IE_TYPE_HANDOFF_RESPONSE, payload)

    def encode_response_payload(self, msg: Mapping[str, Any]) -> bytes:
        """Serialize a response dict → raw ZMD payload bytes."""
        return self._zmd.serialize(ZMD_RESPONSE_STRUCT, msg)

    def decode_response(self, ie_info: bytes) -> Mapping[str, Any]:
        """Deserialize vendor IE info bytes → response dict.

        Raises ``ValueError`` if the type byte doesn't match.
        """
        oui, type_byte, payload = parse_vendor_ie(ie_info)
        if type_byte != IE_TYPE_HANDOFF_RESPONSE:
            raise ValueError(
                f"Expected response type {IE_TYPE_HANDOFF_RESPONSE:#x}, "
                f"got {type_byte:#x}"
            )
        return self._zmd.deserialize(ZMD_RESPONSE_STRUCT, payload)

    def decode_response_payload(self, payload: bytes) -> Mapping[str, Any]:
        """Deserialize raw ZMD payload bytes → response dict."""
        return self._zmd.deserialize(ZMD_RESPONSE_STRUCT, payload)

    # -- generic decode (auto-detect type) ------------------------------------

    def decode(self, ie_info: bytes) -> tuple[str, Mapping[str, Any]]:
        """Auto-detect the message type and decode.

        Returns (struct_name, decoded_dict).
        Raises ``ValueError`` for unknown types.
        """
        oui, type_byte, payload = parse_vendor_ie(ie_info)
        if type_byte == IE_TYPE_HANDOFF_COMMAND:
            return ZMD_COMMAND_STRUCT, self._zmd.deserialize(ZMD_COMMAND_STRUCT, payload)
        elif type_byte == IE_TYPE_HANDOFF_RESPONSE:
            return ZMD_RESPONSE_STRUCT, self._zmd.deserialize(ZMD_RESPONSE_STRUCT, payload)
        else:
            raise ValueError(f"Unknown vendor IE type byte: {type_byte:#x}")

    # -- raw ZMD access (for ZipIPC bridge) -----------------------------------

    @property
    def zmd(self):
        """Direct access to the RuntimeZiplineMessage instance."""
        return self._zmd
