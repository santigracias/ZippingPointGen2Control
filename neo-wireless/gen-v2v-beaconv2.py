#!/usr/bin/env python3
"""
Generate 802.11 beacon frames compatible with
avionics_platform/wireless_tunnel/src/framer_80211/mod.rs.

This builds:
  - FrameInjectionTransport (proto2) -> RTMP frame
  - Vendor-specific IEs for tunnel data (Zipline OUI, type 0x06)
  - Signature IE over the tunnel-data vendor IEs (Zipline OUI, type 0x03)
  - Beacon header + USA country IE
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import time
import zlib
from dataclasses import dataclass
from typing import Iterable, Sequence

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, get_if_list, sendp, wrpcap

from config import (
    BROADCAST_MAC,
    DEFAULT_INTERFACE,
    DEFAULT_SRC_MAC,
    DEFAULT_TX_RATE_HZ,
    TARGET_OUI,
    VENDOR_IE_ID,
)
from handoff_protocol import (
    CMD_DESCEND_TO_DROID_CLEARANCE,
    CMD_HANDOFF_PACKAGE,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_IN_PROGRESS,
    build_command,
    build_response,
)
from protocol import ZmdCodec

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except Exception:  # pragma: no cover - handled at runtime
    Ed25519PrivateKey = None


MAX_FRAME_SIZE = 1200
DEFAULT_RTMP_VERSION = 1
DEFAULT_RATE_KBPS = 6000

VENDOR_TYPE_SIGNATURE = 0x03
VENDOR_TYPE_TUNNEL_DATA = 0x06

USA_COUNTRY_INFO = b"US " + bytes([0x01, 0x0B, 0x14])

DEFAULT_V2V_KEY_HEX = (
    "c060a11c349a3b83d0fd0391d5310eae"
    "ab1dc648e5d7ed1a74edc636f04ad0bb"
)

# Matches p2_droid/droid_identifiers.yaml zipping-point entries.
DROID_TO_ZIP_BRIDGE_IDENTIFIER = "/droid.executive.zipping_point.command"
ZIP_TO_DROID_BRIDGE_IDENTIFIER = "zipping_point.executive.response"

DROID_IP_DEFAULT = "192.168.77.2"
DROID_PORT_DEFAULT = 50055
ZIP_IP_DEFAULT = "192.168.77.1"
ZIP_PORT_DEFAULT = 50056


def _ipv4_to_bytes(ip: str) -> bytes:
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(f"Invalid IPv4 address: {ip}")
    octets = []
    for part in parts:
        n = int(part)
        if n < 0 or n > 255:
            raise ValueError(f"Invalid IPv4 address: {ip}")
        octets.append(n)
    return bytes(octets)


def _checksum16(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_vertical_comms_ipv4_udp_packet(
    payload: bytes, src_ip: str, dst_ip: str, src_port: int, dst_port: int
) -> bytes:
    if not (0 <= src_port <= 65535 and 0 <= dst_port <= 65535):
        raise ValueError("UDP ports must be in [0, 65535]")

    src_ip_b = _ipv4_to_bytes(src_ip)
    dst_ip_b = _ipv4_to_bytes(dst_ip)

    udp_len = 8 + len(payload)
    udp_wo_checksum = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    pseudo = src_ip_b + dst_ip_b + struct.pack("!BBH", 0, 17, udp_len)
    udp_checksum = _checksum16(pseudo + udp_wo_checksum + payload)
    if udp_checksum == 0:
        udp_checksum = 0xFFFF
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, udp_checksum)

    total_len = 20 + udp_len
    ipv4_wo_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0,
        0,
        64,
        17,
        0,
        src_ip_b,
        dst_ip_b,
    )
    ip_checksum = _checksum16(ipv4_wo_checksum)
    ipv4_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0,
        0,
        64,
        17,
        ip_checksum,
        src_ip_b,
        dst_ip_b,
    )
    return ipv4_header + udp_header + payload


def parse_vertical_comms_ipv4_udp_packet(packet: bytes) -> dict:
    if len(packet) < 28:
        raise ValueError("Packet too short for IPv4+UDP")
    if packet[0] >> 4 != 4:
        raise ValueError("Not IPv4")
    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl + 8:
        raise ValueError("Invalid IPv4 header length")
    if packet[9] != 17:
        raise ValueError("Not UDP")

    src_ip = ".".join(str(b) for b in packet[12:16])
    dst_ip = ".".join(str(b) for b in packet[16:20])
    src_port, dst_port, udp_len, _udp_checksum = struct.unpack(
        "!HHHH", packet[ihl : ihl + 8]
    )
    payload = packet[ihl + 8 : ihl + udp_len]
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "payload": payload,
    }


def _encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint cannot be negative")
    out = bytearray()
    while True:
        to_write = value & 0x7F
        value >>= 7
        if value:
            out.append(to_write | 0x80)
        else:
            out.append(to_write)
            break
    return bytes(out)


def _field_varint(field_num: int, value: int) -> bytes:
    tag = (field_num << 3) | 0
    return _encode_varint(tag) + _encode_varint(value)


def _field_bytes(field_num: int, data: bytes) -> bytes:
    tag = (field_num << 3) | 2
    return _encode_varint(tag) + _encode_varint(len(data)) + data


def _field_message(field_num: int, data: bytes) -> bytes:
    return _field_bytes(field_num, data)


def _pack_be24(value: int) -> bytes:
    return bytes([(value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])


def _pack_le24(value: int) -> bytes:
    return bytes([value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF])


def _fnv32a(data: bytes) -> int:
    h = 2166136261
    for b in data:
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def _zmd_field_u32(hash_u16: int, value: int) -> bytes:
    return bytes([4]) + struct.pack("<H", hash_u16 & 0xFFFF) + struct.pack("<I", value & 0xFFFFFFFF)


def _zmd_field_bool(hash_u16: int, value: bool) -> bytes:
    return bytes([1]) + struct.pack("<H", hash_u16 & 0xFFFF) + bytes([1 if value else 0])


def encode_udp_zrtmp_transport_data(
    mailbox_id: int | None,
    bridge_identifier_fnv32a: int | None,
    admin_wrapped: bool | None,
) -> bytes:
    # Hash constants from generated UdpZrtmpTransportData serializer.
    MAILBOX_ID_HASH = 63255
    BRIDGE_IDENTIFIER_HASH = 53931
    ADMIN_WRAPPED_HASH = 9028

    parts: list[bytes] = []
    if mailbox_id is not None:
        parts.append(_zmd_field_u32(MAILBOX_ID_HASH, mailbox_id))
    if bridge_identifier_fnv32a is not None:
        parts.append(_zmd_field_u32(BRIDGE_IDENTIFIER_HASH, bridge_identifier_fnv32a))
    if admin_wrapped is not None:
        parts.append(_zmd_field_bool(ADMIN_WRAPPED_HASH, admin_wrapped))
    return b"".join(parts) if parts else b"\x00"


def encode_windowing_transport(
    windowed_reliable_seqnum: int | None = None,
    nack_windowed_seqnums: Sequence[int] | None = None,
    besteffort_seqnum: int | None = None,
    tx_window_name: int | None = None,
    nack_list_window_name: int | None = None,
) -> bytes:
    parts: list[bytes] = []
    if windowed_reliable_seqnum is not None:
        parts.append(_field_varint(1, windowed_reliable_seqnum))
    if nack_windowed_seqnums:
        for seq in nack_windowed_seqnums:
            parts.append(_field_varint(2, seq))
    if besteffort_seqnum is not None:
        parts.append(_field_varint(3, besteffort_seqnum))
    if tx_window_name is not None:
        parts.append(_field_varint(4, tx_window_name))
    if nack_list_window_name is not None:
        parts.append(_field_varint(5, nack_list_window_name))
    return b"".join(parts)


def encode_frame_injection_transport(
    session_id: int | None,
    destination_address: bytes | None,
    injection_counter: int | None,
    injection_antenna_index: int | None,
    windowing_transport: bytes | None,
) -> bytes:
    parts: list[bytes] = []
    if session_id is not None:
        parts.append(_field_varint(1, session_id))
    if destination_address is not None:
        parts.append(_field_bytes(2, destination_address))
    if injection_counter is not None:
        parts.append(_field_varint(3, injection_counter))
    if injection_antenna_index is not None:
        parts.append(_field_varint(4, injection_antenna_index))
    if windowing_transport is not None:
        parts.append(_field_message(5, windowing_transport))
    return b"".join(parts)


def pack_rtmp_frame(
    transport: bytes,
    payload: bytes,
    version: int,
    frame_count: int,
) -> bytes:
    header = struct.pack("<BB", version & 0xFF, len(transport) & 0xFF)
    header += _pack_be24(len(payload))
    header += struct.pack("<B", frame_count & 0xFF)
    body = header + transport + payload
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return body + struct.pack("<I", crc)


def pack_udp_bridge_rtmp_frame(
    transport: bytes,
    payload: bytes,
    version: int,
    frame_count: int,
) -> bytes:
    # Matches avionics_platform/udp_bridge ParseRtmp (C++): le24 message length.
    header = struct.pack("<BB", version & 0xFF, len(transport) & 0xFF)
    header += _pack_le24(len(payload))
    header += struct.pack("<B", frame_count & 0xFF)
    body = header + transport + payload
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return body + struct.pack("<I", crc)


def parse_rtmp_header(buf: bytes) -> dict:
    if len(buf) < 6:
        raise ValueError("RTMP frame too short for header")
    transport_version = buf[0]
    transport_len = buf[1]
    message_len = int.from_bytes(buf[2:5], "big")
    frame_count = buf[5]
    return {
        "transport_version": transport_version,
        "transport_len": transport_len,
        "message_len": message_len,
        "frame_count": frame_count,
        "header_bytes": buf[:6],
    }


def parse_udp_bridge_rtmp_header(buf: bytes) -> dict:
    if len(buf) < 6:
        raise ValueError("RTMP frame too short for header")
    transport_version = buf[0]
    transport_len = buf[1]
    message_len = int.from_bytes(buf[2:5], "little")
    frame_count = buf[5]
    return {
        "transport_version": transport_version,
        "transport_len": transport_len,
        "message_len": message_len,
        "frame_count": frame_count,
        "header_bytes": buf[:6],
    }


def chunk_bytes(data: bytes, size: int) -> Iterable[bytes]:
    for start in range(0, len(data), size):
        yield data[start : start + size]


def build_tunnel_vendor_elements(tunnel_data: bytes) -> list[Dot11Elt]:
    elements: list[Dot11Elt] = []
    for chunk in chunk_bytes(tunnel_data, 251):
        info = TARGET_OUI + bytes([VENDOR_TYPE_TUNNEL_DATA]) + chunk
        elements.append(Dot11Elt(ID=VENDOR_IE_ID, info=info))
    return elements


def sign_v2v(message: bytes, key_bytes: bytes) -> bytes:
    if Ed25519PrivateKey is None:
        raise RuntimeError(
            "cryptography is required for signing. "
            "Install with: pip install cryptography"
        )
    key = Ed25519PrivateKey.from_private_bytes(key_bytes)
    signature = key.sign(message)
    if len(signature) != 64:
        raise RuntimeError(f"Unexpected signature length: {len(signature)}")
    return signature


def parse_mac(mac: str) -> bytes:
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC: {mac}")
    return bytes(int(p, 16) for p in parts)


@dataclass
class V2VFrameConfig:
    src_mac: str
    dest_mac: str
    session_id: int
    injection_counter: int
    injection_antenna_index: int
    rtmp_version: int
    rtmp_frame_count: int | None
    payload: bytes
    windowed_reliable_seqnum: int | None
    nack_windowed_seqnums: Sequence[int] | None
    besteffort_seqnum: int | None
    tx_window_name: int | None
    nack_list_window_name: int | None
    v2v_key: bytes
    rate_kbps: int


class V2VBeaconGenerator:
    def __init__(self, cfg: V2VFrameConfig) -> None:
        self.cfg = cfg
        self._next_injection_counter = cfg.injection_counter
        self._next_rtmp_frame_count = cfg.rtmp_frame_count
        self._next_besteffort_seqnum = (
            cfg.besteffort_seqnum
            if cfg.besteffort_seqnum is not None
            else cfg.injection_counter
        )

    def build_frame(self):
        injection_counter = self._next_injection_counter
        if self._next_rtmp_frame_count is None:
            frame_count = injection_counter & 0xFF
        else:
            frame_count = self._next_rtmp_frame_count & 0xFF

        dest_bytes = parse_mac(self.cfg.dest_mac)
        if len(dest_bytes) != 6:
            raise ValueError("destination_address must be 6 bytes")

        windowing_transport = encode_windowing_transport(
            windowed_reliable_seqnum=self.cfg.windowed_reliable_seqnum,
            nack_windowed_seqnums=self.cfg.nack_windowed_seqnums,
            besteffort_seqnum=self._next_besteffort_seqnum,
            tx_window_name=self.cfg.tx_window_name,
            nack_list_window_name=self.cfg.nack_list_window_name,
        )

        transport = encode_frame_injection_transport(
            session_id=self.cfg.session_id,
            destination_address=dest_bytes,
            injection_counter=injection_counter,
            injection_antenna_index=self.cfg.injection_antenna_index,
            windowing_transport=windowing_transport,
        )

        tunnel_data = pack_rtmp_frame(
            transport=transport,
            payload=self.cfg.payload,
            version=self.cfg.rtmp_version,
            frame_count=frame_count,
        )
        if len(tunnel_data) > MAX_FRAME_SIZE:
            raise ValueError(
                f"RTMP frame too large ({len(tunnel_data)} bytes > {MAX_FRAME_SIZE})"
            )

        tunnel_elements = build_tunnel_vendor_elements(tunnel_data)
        vendor_messages = b"".join(bytes(e) for e in tunnel_elements)
        signature = sign_v2v(vendor_messages, self.cfg.v2v_key)

        signature_element = Dot11Elt(
            ID=VENDOR_IE_ID,
            info=TARGET_OUI + bytes([VENDOR_TYPE_SIGNATURE]) + signature,
        )

        rate_units = int(self.cfg.rate_kbps / 500)
        radiotap = RadioTap(Rate=rate_units, Antenna=self.cfg.injection_antenna_index)
        dot11 = Dot11(
            type=0,
            subtype=8,
            addr1=BROADCAST_MAC,
            addr2=self.cfg.src_mac,
            addr3=self.cfg.src_mac,
        )
        beacon = Dot11Beacon(timestamp=0, beacon_interval=0, cap=0)
        country = Dot11Elt(ID=7, info=USA_COUNTRY_INFO)

        frame = radiotap / dot11 / beacon / country / signature_element
        for elem in tunnel_elements:
            frame = frame / elem

        self._next_injection_counter += 1
        if self._next_rtmp_frame_count is not None:
            self._next_rtmp_frame_count = (self._next_rtmp_frame_count + 1) & 0xFF
        self._next_besteffort_seqnum = (self._next_besteffort_seqnum + 1) & 0xFFFFFFFF

        return frame, tunnel_data, signature, vendor_messages


def _parse_payload(args: argparse.Namespace) -> bytes:
    if args.payload_hex:
        return bytes.fromhex(args.payload_hex)
    if args.payload_text is not None:
        return args.payload_text.encode("utf-8")
    if args.payload_file:
        with open(args.payload_file, "rb") as f:
            return f.read()
    return b"Hello, world!"


def _build_zmd_payload(args: argparse.Namespace) -> bytes:
    codec = ZmdCodec(zmd_file=args.zmd_file)
    wrap = not args.no_vertical_comms_wrap
    if wrap and args.zmd_wrap_vendor_ie:
        raise ValueError("Cannot use --zmd-wrap-vendor-ie with vertical-comms wrapping")

    if args.zmd_command:
        transport = encode_udp_zrtmp_transport_data(
            mailbox_id=None,
            bridge_identifier_fnv32a=_fnv32a(
                DROID_TO_ZIP_BRIDGE_IDENTIFIER.encode("utf-8")
            ),
            admin_wrapped=True,
        )
        command_type = (
            CMD_DESCEND_TO_DROID_CLEARANCE
            if args.zmd_command == "DESCEND"
            else CMD_HANDOFF_PACKAGE
        )
        cmd = build_command(
            codec,
            command_type,
            mission_id=args.mission_id,
            step_id=args.step_id,
            task_id=args.task_id,
            sequence_id=args.sequence_id,
            droid_subsystem_id=args.droid_subsystem_id,
            droid_step_id=args.droid_step_id,
        )
        if args.zmd_wrap_vendor_ie:
            payload = codec.encode_command(cmd)
        else:
            payload = codec.encode_command_payload(cmd)
        if args.udp_rtmp_wrap:
            payload = pack_udp_bridge_rtmp_frame(
                transport=transport,
                payload=payload,
                version=args.udp_rtmp_transport_version,
                frame_count=args.udp_rtmp_frame_count,
            )
        if wrap:
            src_ip = args.vc_src_ip or DROID_IP_DEFAULT
            dst_ip = args.vc_dst_ip or ZIP_IP_DEFAULT
            src_port = args.vc_src_port or DROID_PORT_DEFAULT
            dst_port = args.vc_dst_port or ZIP_PORT_DEFAULT
            return build_vertical_comms_ipv4_udp_packet(payload, src_ip, dst_ip, src_port, dst_port)
        return payload

    if args.zmd_response:
        transport = encode_udp_zrtmp_transport_data(
            mailbox_id=None,
            bridge_identifier_fnv32a=_fnv32a(
                ZIP_TO_DROID_BRIDGE_IDENTIFIER.encode("utf-8")
            ),
            admin_wrapped=True,
        )
        command_type = (
            CMD_DESCEND_TO_DROID_CLEARANCE
            if args.response_command == "DESCEND"
            else CMD_HANDOFF_PACKAGE
        )
        cmd = build_command(
            codec,
            command_type,
            mission_id=args.mission_id,
            step_id=args.step_id,
            task_id=args.task_id,
            sequence_id=args.sequence_id,
            droid_subsystem_id=args.droid_subsystem_id,
            droid_step_id=args.droid_step_id,
        )
        status = {
            "IN_PROGRESS": STATUS_IN_PROGRESS,
            "COMPLETED": STATUS_COMPLETED,
            "FAILED": STATUS_FAILED,
        }[args.zmd_response]
        resp = build_response(
            codec,
            cmd,
            status,
            package_mass_kg=args.package_mass_kg,
        )
        if args.zmd_wrap_vendor_ie:
            payload = codec.encode_response(resp)
        else:
            payload = codec.encode_response_payload(resp)
        if args.udp_rtmp_wrap:
            payload = pack_udp_bridge_rtmp_frame(
                transport=transport,
                payload=payload,
                version=args.udp_rtmp_transport_version,
                frame_count=args.udp_rtmp_frame_count,
            )
        if wrap:
            src_ip = args.vc_src_ip or ZIP_IP_DEFAULT
            dst_ip = args.vc_dst_ip or DROID_IP_DEFAULT
            src_port = args.vc_src_port or ZIP_PORT_DEFAULT
            dst_port = args.vc_dst_port or DROID_PORT_DEFAULT
            return build_vertical_comms_ipv4_udp_packet(payload, src_ip, dst_ip, src_port, dst_port)
        return payload

    raise ValueError("ZMD payload requested but no command/response specified")


def _parse_nack_list(value: str | None) -> list[int] | None:
    if not value:
        return None
    return [int(part.strip(), 0) for part in value.split(",") if part.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate V2V tunnel beacons compatible with framer_80211"
    )
    parser.add_argument("--src-mac", default=DEFAULT_SRC_MAC)
    parser.add_argument("--dest-mac", default=None)
    parser.add_argument("--session-id", type=int, default=0)
    parser.add_argument("--injection-counter", type=int, default=0)
    parser.add_argument("--antenna-index", type=int, default=0)
    parser.add_argument("--rtmp-version", type=int, default=DEFAULT_RTMP_VERSION)
    parser.add_argument("--rtmp-frame-count", type=int, default=None)
    parser.add_argument("--rate-kbps", type=int, default=DEFAULT_RATE_KBPS)
    parser.add_argument("--v2v-key-hex", default=DEFAULT_V2V_KEY_HEX)

    parser.add_argument("--payload-hex", default=None)
    parser.add_argument("--payload-text", default=None)
    parser.add_argument("--payload-file", default=None)

    parser.add_argument("--zmd-file", default="zmd/droid_zipping_point.zmd")
    parser.add_argument(
        "--zmd-command",
        choices=["DESCEND", "HANDOFF"],
        default=None,
        help="Build a DroidZippingPointCommand payload",
    )
    parser.add_argument(
        "--zmd-response",
        choices=["IN_PROGRESS", "COMPLETED", "FAILED"],
        default=None,
        help="Build a DroidZippingPointResponse payload",
    )
    parser.add_argument(
        "--response-command",
        choices=["DESCEND", "HANDOFF"],
        default="DESCEND",
        help="Command type to echo in a response payload",
    )
    parser.add_argument("--mission-id", default="test-mission-01")
    parser.add_argument("--step-id", type=int, default=1)
    parser.add_argument("--task-id", type=int, default=100)
    parser.add_argument("--sequence-id", type=int, default=1)
    parser.add_argument("--droid-subsystem-id", default="DELIVERY_ASSIST")
    parser.add_argument("--droid-step-id", type=int, default=42)
    parser.add_argument("--package-mass-kg", type=float, default=0.0)
    parser.add_argument(
        "--zmd-wrap-vendor-ie",
        action="store_true",
        help="Prefix OUI+type before ZMD payload (matches legacy vendor IE encoding)",
    )
    parser.add_argument(
        "--no-vertical-comms-wrap",
        action="store_true",
        help="Do not wrap ZMD bytes in IPv4/UDP vertical-comms envelope",
    )
    parser.add_argument("--vc-src-ip", default=None)
    parser.add_argument("--vc-dst-ip", default=None)
    parser.add_argument("--vc-src-port", type=int, default=None)
    parser.add_argument("--vc-dst-port", type=int, default=None)
    parser.add_argument(
        "--no-udp-rtmp-wrap",
        action="store_true",
        help="Do not wrap ZMD payload in UDP-bridge RTMP header before IPv4/UDP wrapping",
    )
    parser.add_argument(
        "--udp-rtmp-transport-version",
        type=int,
        default=0,
        help="Inner UDP-bridge RTMP transport_version",
    )
    parser.add_argument(
        "--udp-rtmp-frame-count",
        type=int,
        default=0,
        help="Inner UDP-bridge RTMP frame_count",
    )
    parser.add_argument(
        "--udp-transport-mailbox-id",
        type=lambda v: int(v, 0),
        default=None,
        help="UdpZrtmpTransportData.mailbox_id (u32)",
    )
    parser.add_argument(
        "--udp-transport-bridge-identifier",
        default=None,
        help="String bridge identifier; FNV32a hash will be computed for transport",
    )
    parser.add_argument(
        "--udp-transport-bridge-identifier-fnv32a",
        type=lambda v: int(v, 0),
        default=None,
        help="Explicit UdpZrtmpTransportData.bridge_identifier_fnv32a (u32)",
    )
    parser.add_argument(
        "--udp-transport-admin-wrapped",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="UdpZrtmpTransportData.admin_wrapped",
    )

    parser.add_argument("--windowed-reliable-seqnum", type=int, default=None)
    parser.add_argument("--besteffort-seqnum", type=int, default=None)
    parser.add_argument("--tx-window-name", type=int, default=None)
    parser.add_argument("--nack-list-window-name", type=int, default=None)
    parser.add_argument("--nack-list", default=None)

    parser.add_argument("--output-hex", action="store_true")
    parser.add_argument("--output-pcap", default=None)
    parser.add_argument("--print-rtmp-header", action="store_true")
    parser.add_argument("--print-serialized-payload-hex", action="store_true")

    parser.add_argument("--send", action="store_true")
    parser.add_argument("--interface", default=DEFAULT_INTERFACE)
    parser.add_argument("--rate-hz", type=float, default=DEFAULT_TX_RATE_HZ)
    parser.add_argument("--count", type=int, default=1)

    args = parser.parse_args()
    if args.zmd_command is None and args.zmd_response is None:
        # Default to ZIP->DROID vertical comms path for droid-side bridge testing.
        args.zmd_response = "IN_PROGRESS"

    args.udp_rtmp_wrap = not args.no_udp_rtmp_wrap
    if not (0 <= args.udp_rtmp_transport_version <= 255):
        raise ValueError("--udp-rtmp-transport-version must be in [0, 255]")
    if not (0 <= args.udp_rtmp_frame_count <= 255):
        raise ValueError("--udp-rtmp-frame-count must be in [0, 255]")

    dest_mac = args.dest_mac or args.src_mac
    if args.zmd_command and args.zmd_response:
        raise ValueError("Choose only one: --zmd-command or --zmd-response")

    if args.zmd_command or args.zmd_response:
        payload = _build_zmd_payload(args)
    else:
        payload = _parse_payload(args)

    nack_windowed_seqnums = _parse_nack_list(args.nack_list)

    v2v_key = bytes.fromhex(args.v2v_key_hex)
    if len(v2v_key) != 32:
        raise ValueError(f"v2v key must be 32 bytes, got {len(v2v_key)}")

    cfg = V2VFrameConfig(
        src_mac=args.src_mac,
        dest_mac=dest_mac,
        session_id=args.session_id,
        injection_counter=args.injection_counter,
        injection_antenna_index=args.antenna_index,
        rtmp_version=args.rtmp_version,
        rtmp_frame_count=args.rtmp_frame_count,
        payload=payload,
        windowed_reliable_seqnum=args.windowed_reliable_seqnum,
        nack_windowed_seqnums=nack_windowed_seqnums,
        besteffort_seqnum=args.besteffort_seqnum,
        tx_window_name=args.tx_window_name,
        nack_list_window_name=args.nack_list_window_name,
        v2v_key=v2v_key,
        rate_kbps=args.rate_kbps,
    )

    generator = V2VBeaconGenerator(cfg)
    frame, tunnel_data, signature, vendor_messages = generator.build_frame()

    print("Generated V2V beacon")
    print(f"  src_mac: {cfg.src_mac}")
    print(f"  dest_mac (transport): {cfg.dest_mac}")
    print(f"  session_id: {cfg.session_id}")
    print(f"  injection_counter: {cfg.injection_counter}")
    print(f"  rtmp_version: {cfg.rtmp_version}")
    print(f"  payload_len: {len(cfg.payload)}")
    print(f"  tunnel_data_len: {len(tunnel_data)}")
    print(f"  vendor_messages_len: {len(vendor_messages)}")
    print(f"  signature_len: {len(signature)}")
    if not args.no_vertical_comms_wrap and (args.zmd_command or args.zmd_response):
        vc = parse_vertical_comms_ipv4_udp_packet(cfg.payload)
        print(
            "  vertical_comms:"
            f" {vc['src_ip']}:{vc['src_port']} -> {vc['dst_ip']}:{vc['dst_port']}"
        )
        print(
            "  udp_transport_bridge_identifier:"
            f" {DROID_TO_ZIP_BRIDGE_IDENTIFIER if args.zmd_command else ZIP_TO_DROID_BRIDGE_IDENTIFIER}"
        )
        if args.udp_rtmp_wrap:
            inner = parse_rtmp_header(vc["payload"])
            print(
                "  inner_udp_rtmp:"
                f" version={inner['transport_version']}"
                f" transport_len={inner['transport_len']}"
                f" message_len={inner['message_len']}"
                f" frame_count={inner['frame_count']}"
            )
    if args.print_rtmp_header:
        header = parse_rtmp_header(tunnel_data)
        print(
            "RTMP header:"
            f" version={header['transport_version']}"
            f" transport_len={header['transport_len']}"
            f" message_len={header['message_len']}"
            f" frame_count={header['frame_count']}"
        )
        print(f"RTMP header bytes: {header['header_bytes'].hex()}")
    if args.print_serialized_payload_hex:
        print(f"Serialized payload hex: {cfg.payload.hex()}")

    if args.output_hex:
        print(bytes(frame).hex())

    if args.output_pcap:
        wrpcap(args.output_pcap, [frame])
        print(f"Wrote PCAP: {args.output_pcap}")

    if args.send:
        if os.geteuid() != 0:
            print("Error: --send requires root (sudo).")
            sys.exit(1)
        interface = args.interface
        if not interface:
            interfaces = get_if_list()
            if not interfaces:
                print("No interfaces found.")
                sys.exit(1)
            interface = interfaces[0]

        interval = 1.0 / args.rate_hz
        count = args.count
        print(f"Sending on {interface} at {args.rate_hz} Hz (count={count})")
        sent = 0
        try:
            while count == 0 or sent < count:
                frame, _, _, _ = generator.build_frame()
                sendp(frame, iface=interface, verbose=False)
                sent += 1
                time.sleep(interval)
        except KeyboardInterrupt:
            print("Stopped by user.")


if __name__ == "__main__":
    main()
