"""
High-level helpers for building ZP ↔ Droid handoff messages.

All messages are plain Python dicts produced by the ZMD runtime.
This module provides convenience functions to populate those dicts
without the caller needing to know the nested structure.

The canonical types are defined in ``zmd/droid_zipping_point.zmd``.
"""

from __future__ import annotations

import time
from typing import Any, Mapping, Optional

from protocol import ZmdCodec


# ---------------------------------------------------------------------------
# Enum string constants (must match the ZMD enum names exactly)
# ---------------------------------------------------------------------------

# DroidZippingPointCommandType
CMD_DESCEND_TO_DROID_CLEARANCE = "DESCEND_TO_DROID_CLEARANCE_HEIGHT"
CMD_HANDOFF_PACKAGE            = "HANDOFF_PACKAGE_TO_DROID"

# DroidCommandStatus
STATUS_PENDING     = "PENDING"
STATUS_IN_PROGRESS = "IN_PROGRESS"
STATUS_COMPLETED   = "COMPLETED"
STATUS_FAILED      = "FAILED"


# ---------------------------------------------------------------------------
# Command builder
# ---------------------------------------------------------------------------

def build_command(
    codec: ZmdCodec,
    command: str,
    *,
    mission_id: str = "",
    step_id: int = -1,
    task_id: int = 0,
    sequence_id: int = 0,
    droid_subsystem_id: str = "UNKNOWN",
    droid_step_id: int = 0,
    timestamp_ns: Optional[int] = None,
) -> Mapping[str, Any]:
    """Build a ``DroidZippingPointCommand`` dict ready for encoding.

    Parameters
    ----------
    codec : ZmdCodec
        The codec instance (provides ``create_command``).
    command : str
        One of the ``DroidZippingPointCommandType`` enum names.
    mission_id, step_id, task_id, sequence_id :
        Fields for the nested ``ExecutiveInterfaceId``.
    droid_subsystem_id : str
        ``DroidSubsystemId`` enum name.
    droid_step_id : int
        Step id for the droid command.
    timestamp_ns : int, optional
        Nanosecond timestamp; defaults to ``time.time_ns()``.
    """
    msg = codec.create_command()
    msg["timestamp_ns"] = timestamp_ns if timestamp_ns is not None else time.time_ns()
    msg["command"] = command

    # Build nested structs as plain dicts — the ZMD serializer accepts any Mapping.
    # Using plain dicts avoids issues with create() returning None-valued nested fields.
    zid = {
        "mission_id": mission_id.encode("ascii") if isinstance(mission_id, str) else mission_id,
        "step_id": step_id,
        "task_id": task_id,
        "sequence_id": sequence_id,
        "is_valid": True,
    }
    eid = {
        "zip_executive_id": zid,
        "droid_subsystem_id": droid_subsystem_id,
        "droid_step_id": droid_step_id,
    }
    msg["command_id"] = eid

    return msg


# ---------------------------------------------------------------------------
# Response builders
# ---------------------------------------------------------------------------

def build_response(
    codec: ZmdCodec,
    command_msg: Mapping[str, Any],
    status: str,
    *,
    package_mass_kg: float = 0.0,
    timestamp_ns: Optional[int] = None,
) -> Mapping[str, Any]:
    """Build a ``DroidZippingPointResponse`` that echoes back a command.

    Parameters
    ----------
    codec : ZmdCodec
        The codec instance.
    command_msg : dict
        The received command (its ``command_id`` and ``command`` are echoed).
    status : str
        One of the ``DroidCommandStatus`` enum names.
    package_mass_kg : float
        Package mass — populated on HANDOFF_PACKAGE_TO_DROID completion.
    timestamp_ns : int, optional
        Defaults to ``time.time_ns()``.
    """
    resp = codec.create_response()
    resp["timestamp_ns"] = timestamp_ns if timestamp_ns is not None else time.time_ns()
    resp["command_response"] = status
    resp["package_mass_kg"] = package_mass_kg

    # Echo back the command type and command_id from the original command
    resp["command"] = command_msg["command"]

    # Deep-copy the nested DroidExecutiveId as plain dicts
    _copy_executive_id(command_msg["command_id"], resp)

    return resp


def build_response_in_progress(
    codec: ZmdCodec,
    command_msg: Mapping[str, Any],
    **kwargs,
) -> Mapping[str, Any]:
    """Convenience: build an IN_PROGRESS response."""
    return build_response(codec, command_msg, STATUS_IN_PROGRESS, **kwargs)


def build_response_completed(
    codec: ZmdCodec,
    command_msg: Mapping[str, Any],
    package_mass_kg: float = 0.0,
    **kwargs,
) -> Mapping[str, Any]:
    """Convenience: build a COMPLETED response."""
    return build_response(
        codec, command_msg, STATUS_COMPLETED,
        package_mass_kg=package_mass_kg, **kwargs,
    )


def build_response_failed(
    codec: ZmdCodec,
    command_msg: Mapping[str, Any],
    **kwargs,
) -> Mapping[str, Any]:
    """Convenience: build a FAILED response."""
    return build_response(codec, command_msg, STATUS_FAILED, **kwargs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _copy_executive_id(src: Mapping[str, Any], dst_msg) -> None:
    """Deep-copy a DroidExecutiveId from *src* into *dst_msg*["command_id"].

    Builds plain Python dicts so we don't depend on codec.zmd.create()
    for intermediate struct types.
    """
    src_zid = src["zip_executive_id"]
    zid = {
        "mission_id": (
            bytearray(src_zid["mission_id"])
            if isinstance(src_zid["mission_id"], (bytes, bytearray))
            else src_zid["mission_id"]
        ),
        "step_id": src_zid["step_id"],
        "task_id": src_zid["task_id"],
        "sequence_id": src_zid["sequence_id"],
        "is_valid": src_zid["is_valid"],
    }
    eid = {
        "zip_executive_id": zid,
        "droid_subsystem_id": src["droid_subsystem_id"],
        "droid_step_id": src["droid_step_id"],
    }
    dst_msg["command_id"] = eid


def get_command_id_key(msg: Mapping[str, Any]) -> tuple:
    """Return a hashable key from the nested DroidExecutiveId for dedup."""
    eid = msg["command_id"]
    zid = eid["zip_executive_id"]
    return (
        bytes(zid["mission_id"]),
        zid["step_id"],
        zid["task_id"],
        zid["sequence_id"],
        eid["droid_subsystem_id"],
        eid["droid_step_id"],
    )
