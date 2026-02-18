#!/usr/bin/env python3
"""
Sniff and decode V2V tunnel beacons compatible with framer_80211.

Pipeline:
  - Extract Zipline OUI vendor IEs
  - Verify signature over vendor IE bytes (optional)
  - Reassemble tunnel data (vendor type 0x06)
  - Parse RTMP frame
  - Decode FrameInjectionTransport (proto2)
  - Decode ZMD payload (command/response) if requested
"""

from __future__ import annotations

import argparse
import binascii
import os
import struct
import zlib
from dataclasses import dataclass
from typing import Optional

from scapy.all import Dot11, Dot11Elt, sniff

from config import DEFAULT_INTERFACE, TARGET_OUI, TARGET_OUI_STR, VENDOR_IE_ID
from protocol import ZmdCodec, parse_vendor_ie

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except Exception:  # pragma: no cover
    Ed25519PrivateKey = None


VENDOR_TYPE_SIGNATURE = 0x03
VENDOR_TYPE_TUNNEL_DATA = 0x06
DEFAULT_V2V_KEY_HEX = (
    "c060a11c349a3b83d0fd0391d5310eae"
    "ab1dc648e5d7ed1a74edc636f04ad0bb"
)


def _checksum16(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def parse_vertical_comms_ipv4_udp_packet(packet: bytes) -> dict:
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
    if udp_checksum == 0:
        raise ValueError("UDP checksum is zero")
    pseudo = src_bytes + dst_bytes + struct.pack("!BBH", 0, protocol, udp_length)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)
    calc_udp = _checksum16(pseudo + udp_hdr + payload)
    if calc_udp == 0:
        calc_udp = 0xFFFF
    if calc_udp != udp_checksum:
        raise ValueError("UDP checksum mismatch")

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "payload": payload,
    }


def parse_mac(mac: str) -> bytes:
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC: {mac}")
    return bytes(int(p, 16) for p in parts)


def read_varint(buf: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if offset >= len(buf):
            raise ValueError("Truncated varint")
        b = buf[offset]
        offset += 1
        value |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return value, offset
        shift += 7
        if shift > 63:
            raise ValueError("Varint too long")


def parse_protobuf_fields(buf: bytes) -> list[tuple[int, int, bytes | int]]:
    fields: list[tuple[int, int, bytes | int]] = []
    offset = 0
    while offset < len(buf):
        key, offset = read_varint(buf, offset)
        field_num = key >> 3
        wire_type = key & 0x07
        if wire_type == 0:  # varint
            val, offset = read_varint(buf, offset)
            fields.append((field_num, wire_type, val))
        elif wire_type == 2:  # length-delimited
            length, offset = read_varint(buf, offset)
            end = offset + length
            if end > len(buf):
                raise ValueError("Truncated length-delimited field")
            fields.append((field_num, wire_type, buf[offset:end]))
            offset = end
        else:
            raise ValueError(f"Unsupported wire type {wire_type}")
    return fields


def parse_windowing_transport(buf: bytes) -> dict:
    result: dict = {
        "windowed_reliable_seqnum": None,
        "nack_windowed_seqnums": [],
        "besteffort_seqnum": None,
        "tx_window_name": None,
        "nack_list_window_name": None,
    }
    for field_num, wire_type, val in parse_protobuf_fields(buf):
        if wire_type != 0:
            continue
        if field_num == 1:
            result["windowed_reliable_seqnum"] = int(val)
        elif field_num == 2:
            result["nack_windowed_seqnums"].append(int(val))
        elif field_num == 3:
            result["besteffort_seqnum"] = int(val)
        elif field_num == 4:
            result["tx_window_name"] = int(val)
        elif field_num == 5:
            result["nack_list_window_name"] = int(val)
    return result


def parse_frame_injection_transport(buf: bytes) -> dict:
    result: dict = {
        "session_id": None,
        "destination_address": None,
        "injection_counter": None,
        "injection_antenna_index": None,
        "windowing_transport": None,
    }
    for field_num, wire_type, val in parse_protobuf_fields(buf):
        if field_num == 1 and wire_type == 0:
            result["session_id"] = int(val)
        elif field_num == 2 and wire_type == 2:
            result["destination_address"] = bytes(val)
        elif field_num == 3 and wire_type == 0:
            result["injection_counter"] = int(val)
        elif field_num == 4 and wire_type == 0:
            result["injection_antenna_index"] = int(val)
        elif field_num == 5 and wire_type == 2:
            result["windowing_transport"] = parse_windowing_transport(bytes(val))
    return result


def parse_rtmp_frame(buf: bytes) -> dict:
    if len(buf) < 6:
        raise ValueError("RTMP frame too short")
    transport_version = buf[0]
    transport_len = buf[1]
    message_len = int.from_bytes(buf[2:5], "big")
    frame_count = buf[5]
    offset = 6
    transport = buf[offset : offset + transport_len]
    offset += transport_len
    payload = buf[offset : offset + message_len]
    offset += message_len
    if offset + 4 > len(buf):
        raise ValueError("RTMP frame missing CRC")
    crc_expected = struct.unpack("<I", buf[offset : offset + 4])[0]
    crc_actual = zlib.crc32(buf[:offset]) & 0xFFFFFFFF
    if crc_expected != crc_actual:
        raise ValueError(f"RTMP CRC mismatch expected=0x{crc_expected:x} got=0x{crc_actual:x}")
    return {
        "transport_version": transport_version,
        "transport_len": transport_len,
        "message_len": message_len,
        "frame_count": frame_count,
        "transport": transport,
        "payload": payload,
    }


@dataclass
class VendorElement:
    raw: bytes
    vendor_type: int
    content: bytes


def extract_vendor_elements(pkt) -> list[VendorElement]:
    elements: list[VendorElement] = []
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == VENDOR_IE_ID and elt.info and len(elt.info) >= 4:
            info = bytes(elt.info)
            if info[:3] == TARGET_OUI:
                vendor_type = info[3]
                content = info[4:]
                raw = bytes([elt.ID, len(info)]) + info
                elements.append(VendorElement(raw=raw, vendor_type=vendor_type, content=content))
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return elements


def verify_signature(signature: bytes, signable: bytes, key_hex: str) -> bool:
    if Ed25519PrivateKey is None:
        raise RuntimeError(
            "cryptography is required for signature verification. "
            "Install with: pip install cryptography"
        )
    key_bytes = bytes.fromhex(key_hex)
    if len(key_bytes) != 32:
        raise ValueError(f"v2v key must be 32 bytes, got {len(key_bytes)}")
    if len(signature) != 64:
        raise ValueError(f"signature must be 64 bytes, got {len(signature)}")
    priv = Ed25519PrivateKey.from_private_bytes(key_bytes)
    pub = priv.public_key()
    pub.verify(signature, signable)
    return True


def decode_payload(
    payload: bytes,
    codec: Optional[ZmdCodec],
    zmd_type: str,
) -> Optional[dict]:
    if codec is None:
        return None
    if len(payload) >= 20 and (payload[0] >> 4) == 4:
        parsed = parse_vertical_comms_ipv4_udp_packet(payload)
        payload = parsed["payload"]
    if len(payload) >= 4 and payload[:3] == TARGET_OUI:
        _, type_byte, _ = parse_vendor_ie(payload)
        if type_byte == 0x10:
            return codec.decode_command(payload)
        if type_byte == 0x11:
            return codec.decode_response(payload)
    if zmd_type == "command":
        return codec.decode_command_payload(payload)
    if zmd_type == "response":
        return codec.decode_response_payload(payload)
    # auto: try command then response
    try:
        return codec.decode_command_payload(payload)
    except Exception:
        return codec.decode_response_payload(payload)


def main() -> None:
    parser = argparse.ArgumentParser(description="V2V tunnel beacon sniffer/decoder")
    parser.add_argument("interface", nargs="?", default=DEFAULT_INTERFACE)
    parser.add_argument("--self-mac", default=None, help="Drop frames not addressed to this MAC")
    parser.add_argument("--peer-mac", default=None, help="Drop frames not sourced from this MAC")
    parser.add_argument("--session-id", type=int, default=None)
    parser.add_argument("--no-verify-signature", action="store_true")
    parser.add_argument("--v2v-key-hex", default=DEFAULT_V2V_KEY_HEX)
    parser.add_argument("--decode-zmd", action="store_true")
    parser.add_argument("--zmd-file", default="zmd/droid_zipping_point.zmd")
    parser.add_argument("--zmd-type", choices=["auto", "command", "response"], default="auto")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: This script must be run as root (sudo)")
        raise SystemExit(1)

    codec = ZmdCodec(args.zmd_file) if args.decode_zmd else None
    self_mac = parse_mac(args.self_mac) if args.self_mac else None
    peer_mac = args.peer_mac.lower() if args.peer_mac else None

    print(f"[RX] Listening on {args.interface} for OUI {TARGET_OUI_STR}")

    def _handle(pkt) -> None:
        if not pkt.haslayer(Dot11):
            return
        if peer_mac and (pkt.addr2 or "").lower() != peer_mac:
            return

        elements = extract_vendor_elements(pkt)
        if not elements:
            return

        if elements[0].vendor_type != VENDOR_TYPE_SIGNATURE:
            return
        signature = elements[0].content
        signable = b"".join(e.raw for e in elements[1:])

        if not args.no_verify_signature:
            try:
                verify_signature(signature, signable, args.v2v_key_hex)
            except Exception as exc:
                print(f"[RX] Signature verify failed: {exc}")
                return

        tunnel_chunks = [e.content for e in elements if e.vendor_type == VENDOR_TYPE_TUNNEL_DATA]
        if not tunnel_chunks:
            return
        tunnel_data = b"".join(tunnel_chunks)

        try:
            rtmp = parse_rtmp_frame(tunnel_data)
        except Exception as exc:
            print(f"[RX] RTMP parse failed: {exc}")
            return

        try:
            transport = parse_frame_injection_transport(rtmp["transport"])
        except Exception as exc:
            print(f"[RX] Transport decode failed: {exc}")
            return

        if args.session_id is not None and transport["session_id"] != args.session_id:
            return
        if self_mac is not None:
            if transport["destination_address"] != self_mac:
                return

        src_mac = pkt.addr2 or "unknown"
        dest_mac = transport["destination_address"]
        dest_str = (
            ":".join(f"{b:02x}" for b in dest_mac) if dest_mac is not None else "None"
        )

        print(f"[RX] From {src_mac} → dest={dest_str} session={transport['session_id']}")
        print(
            "     inj_counter="
            f"{transport['injection_counter']} antenna={transport['injection_antenna_index']}"
        )

        if codec is not None:
            try:
                decoded = decode_payload(rtmp["payload"], codec, args.zmd_type)
                print(f"     ZMD: {decoded}")
            except Exception as exc:
                print(f"[RX] ZMD decode failed: {exc}")
                print(f"     payload hex: {binascii.hexlify(rtmp['payload']).decode()}")
        else:
            print(f"     payload hex: {binascii.hexlify(rtmp['payload']).decode()}")

    sniff(iface=args.interface, prn=_handle, store=0)


if __name__ == "__main__":
    main()
