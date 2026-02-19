"""
Helpers for vertical-comms IPv4/UDP wrapping.
"""

from __future__ import annotations

import binascii
import ipaddress
import struct
from typing import Mapping


ZIP_IP_DEFAULT = "192.168.77.1"
DROID_IP_DEFAULT = "192.168.77.2"
ZIP_PORT_DEFAULT = 50056
DROID_PORT_DEFAULT = 50055


def _checksum16(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_vertical_comms_ipv4_udp_packet(
    zmd_payload: bytes,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
) -> bytes:
    if not isinstance(zmd_payload, (bytes, bytearray)) or len(zmd_payload) == 0:
        raise ValueError("zmd_payload must be non-empty bytes")
    try:
        src_ip_obj = ipaddress.ip_address(src_ip)
        dst_ip_obj = ipaddress.ip_address(dst_ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {exc}") from exc
    if src_ip_obj.version != 4 or dst_ip_obj.version != 4:
        raise ValueError("Only IPv4 is supported")
    if not (0 < src_port < 65536 and 0 < dst_port < 65536):
        raise ValueError("UDP ports must be in 1..65535")

    payload = bytes(zmd_payload)
    total_length = 20 + 8 + len(payload)

    version_ihl = 0x45
    tos = 0
    identification = 0
    flags_fragment = 0
    ttl = 64
    protocol = 17
    header_checksum = 0
    src_bytes = src_ip_obj.packed
    dst_bytes = dst_ip_obj.packed

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        header_checksum,
        src_bytes,
        dst_bytes,
    )
    header_checksum = _checksum16(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        header_checksum,
        src_bytes,
        dst_bytes,
    )

    udp_length = 8 + len(payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)
    pseudo = src_bytes + dst_bytes + struct.pack("!BBH", 0, protocol, udp_length)
    udp_checksum = _checksum16(pseudo + udp_header + payload)
    if udp_checksum == 0:
        udp_checksum = 0xFFFF
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, udp_checksum)

    return ip_header + udp_header + payload


def parse_vertical_comms_ipv4_udp_packet(packet: bytes, *, validate: bool = True) -> Mapping[str, object]:
    if len(packet) < 28:
        raise ValueError("Packet too short for IPv4+UDP")
    first = packet[0]
    version = first >> 4
    ihl = (first & 0x0F) * 4
    if version != 4 or ihl < 20:
        raise ValueError("Not an IPv4 packet")
    if len(packet) < ihl + 8:
        raise ValueError("Packet too short for UDP header")

    ip_hdr = packet[:ihl]
    (
        _ver_ihl,
        _tos,
        total_length,
        _identification,
        _flags_fragment,
        _ttl,
        protocol,
        hdr_checksum,
        src_bytes,
        dst_bytes,
    ) = struct.unpack("!BBHHHBBH4s4s", ip_hdr)

    if protocol != 17:
        raise ValueError("Not a UDP packet")
    if total_length != len(packet):
        raise ValueError(f"IPv4 total length mismatch: {total_length} != {len(packet)}")

    if validate:
        hdr = bytearray(ip_hdr)
        hdr[10:12] = b"\x00\x00"
        calc = _checksum16(bytes(hdr))
        if calc != hdr_checksum:
            raise ValueError("IPv4 header checksum mismatch")

    udp_offset = ihl
    src_port, dst_port, udp_length, udp_checksum = struct.unpack(
        "!HHHH", packet[udp_offset : udp_offset + 8]
    )
    payload = packet[udp_offset + 8 : total_length]
    if udp_length != 8 + len(payload):
        raise ValueError("UDP length mismatch")
    if validate:
        if udp_checksum == 0:
            raise ValueError("UDP checksum is zero")
        pseudo = src_bytes + dst_bytes + struct.pack("!BBH", 0, protocol, udp_length)
        hdr = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)
        calc = _checksum16(pseudo + hdr + payload)
        if calc == 0:
            calc = 0xFFFF
        if calc != udp_checksum:
            raise ValueError("UDP checksum mismatch")

    return {
        "src_ip": str(ipaddress.ip_address(src_bytes)),
        "dst_ip": str(ipaddress.ip_address(dst_bytes)),
        "src_port": src_port,
        "dst_port": dst_port,
        "payload": payload,
    }


def hexdump_prefix(data: bytes, length: int = 64) -> str:
    return binascii.hexlify(data[:length]).decode()
