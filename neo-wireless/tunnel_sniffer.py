#!/usr/bin/env python3
"""
Tunnel sniffer helpers + optional CLI sniffer.

This module provides the decode/verify helpers used by tunnel_transceiver.py.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import importlib
import struct
import time
import zlib
from dataclasses import dataclass
from typing import Any, Mapping

from scapy.all import Dot11, Dot11Elt, sniff

from config import DEFAULT_INTERFACE, TARGET_OUI
from protocol import ZmdCodec

_v2v_mod = importlib.import_module("gen-v2v-beaconv2")
DEFAULT_V2V_SIGNING_KEY_HEX = _v2v_mod.DEFAULT_V2V_KEY_HEX
# Public key paired to the default signing key above.
DEFAULT_V2V_KEY_HEX = "666bea73bd24392e9c0895e74cc2e62e530c7c66ad3bd06766a2774d797fd616"
parse_vertical_comms_ipv4_udp_packet = _v2v_mod.parse_vertical_comms_ipv4_udp_packet
parse_udp_bridge_rtmp_header = _v2v_mod.parse_udp_bridge_rtmp_header
_fnv32a = _v2v_mod._fnv32a
DROID_TO_ZIP_BRIDGE_IDENTIFIER = _v2v_mod.DROID_TO_ZIP_BRIDGE_IDENTIFIER
ZIP_TO_DROID_BRIDGE_IDENTIFIER = _v2v_mod.ZIP_TO_DROID_BRIDGE_IDENTIFIER
DROID_IP_DEFAULT = _v2v_mod.DROID_IP_DEFAULT
DROID_PORT_DEFAULT = _v2v_mod.DROID_PORT_DEFAULT
ZIP_IP_DEFAULT = _v2v_mod.ZIP_IP_DEFAULT
ZIP_PORT_DEFAULT = _v2v_mod.ZIP_PORT_DEFAULT

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:  # pragma: no cover
    Ed25519PublicKey = None


VENDOR_TYPE_SIGNATURE = 0x03
VENDOR_TYPE_TUNNEL_DATA = 0x06
VENDOR_TYPE_REMOTE_ID = 0x0D
VENDOR_TYPE_ZIPLINE_V2V_EXTENSION = 0x01
VENDOR_TYPE_AUTH_CERT = 0x02
VENDOR_TYPE_DOWNGOING = 0x04
VENDOR_TYPE_UPGOING = 0x05
VENDOR_TYPE_WIRELESS_TEST = 0x99
REMOTE_ID_OUI = bytes([0xFA, 0x0B, 0xBC])


@dataclass
class VendorElement:
    vendor_type: int
    content: bytes
    raw: bytes


@dataclass
class TunnelParseResult:
    signature: bytes
    signable: bytes
    tunnel_data: bytes


def parse_mac(mac: str) -> bytes:
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC: {mac}")
    return bytes(int(p, 16) for p in parts)


def _read_varint(buf: bytes, off: int) -> tuple[int, int]:
    shift = 0
    val = 0
    while True:
        if off >= len(buf):
            raise ValueError("truncated varint")
        b = buf[off]
        off += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, off
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def _unwrap_admin_wrapper_payload(data: bytes) -> bytes:
    """
    Best-effort unwrap for admin-wrapped payloads:
    protobuf field #1 length-delimited bytes: 0x0a <len> <payload>.
    """
    tag, off = _read_varint(data, 0)
    if tag != ((1 << 3) | 2):
        raise ValueError("not admin-wrapper field#1 bytes")
    ln, off = _read_varint(data, off)
    end = off + ln
    if end > len(data):
        raise ValueError("admin-wrapper payload truncated")
    return data[off:end]


def parse_frame_injection_transport(data: bytes) -> dict:
    out: dict[str, Any] = {
        "session_id": 0,
        "destination_address": b"\x00" * 6,
        "injection_counter": 0,
        "injection_antenna_index": 0,
        "windowing_transport": b"",
    }
    off = 0
    while off < len(data):
        tag, off = _read_varint(data, off)
        field_num = tag >> 3
        wire = tag & 0x7
        if wire == 0:
            val, off = _read_varint(data, off)
            if field_num == 1:
                out["session_id"] = val
            elif field_num == 3:
                out["injection_counter"] = val
            elif field_num == 4:
                out["injection_antenna_index"] = val
        elif wire == 2:
            ln, off = _read_varint(data, off)
            if off + ln > len(data):
                raise ValueError("truncated length-delimited field")
            val = data[off : off + ln]
            off += ln
            if field_num == 2:
                out["destination_address"] = val
            elif field_num == 5:
                out["windowing_transport"] = val
        else:
            raise ValueError(f"unsupported wire type {wire}")
    return out


def parse_rtmp_frame(data: bytes) -> dict:
    if len(data) < 10:
        raise ValueError("RTMP frame too short")
    version = data[0]
    transport_len = data[1]
    payload_len = int.from_bytes(data[2:5], "big")
    frame_count = data[5]
    body_len = 6 + transport_len + payload_len
    if len(data) < body_len + 4:
        raise ValueError("RTMP frame truncated")
    body = data[:body_len]
    crc_expected = struct.unpack("<I", data[body_len : body_len + 4])[0]
    crc_actual = zlib.crc32(body) & 0xFFFFFFFF
    if crc_actual != crc_expected:
        raise ValueError("RTMP CRC mismatch")
    transport = data[6 : 6 + transport_len]
    payload = data[6 + transport_len : body_len]
    return {
        "version": version,
        "transport_len": transport_len,
        "payload_len": payload_len,
        "frame_count": frame_count,
        "transport": transport,
        "payload": payload,
    }


def extract_vendor_elements(pkt) -> list[VendorElement]:
    out: list[VendorElement] = []
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 221:
            info = bytes(elt.info or b"")
            if len(info) >= 4 and info[:3] == TARGET_OUI:
                out.append(
                    VendorElement(
                        vendor_type=info[3],
                        content=info[4:],
                        raw=bytes(elt),
                    )
                )
        elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
    return out


def extract_tunnel_parse_result(pkt) -> TunnelParseResult:
    """
    Approximate ieee80211::beacon::unpack signable/tunnel parsing rules used by
    wireless_tunnel framer RX path.
    """
    tags = []
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        tags.append(elt)
        elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None

    raw_tags = [bytes(t) for t in tags]
    ends: list[int] = []
    off = 0
    for raw in raw_tags:
        off += len(raw)
        ends.append(off)

    tunnel_parts: list[bytes] = []
    signature: bytes | None = None
    signable_start: int | None = None
    last_non_sig_end: int | None = None
    signable_error: str | None = None

    for i, t in enumerate(tags):
        result = "err"
        if t.ID == 221:
            info = bytes(t.info or b"")
            if len(info) >= 4:
                oui = info[:3]
                vtype = info[3]
                content = info[4:]
                if oui == REMOTE_ID_OUI and vtype == VENDOR_TYPE_REMOTE_ID:
                    result = "non_sig"
                elif oui == TARGET_OUI and vtype in {
                    VENDOR_TYPE_ZIPLINE_V2V_EXTENSION,
                    VENDOR_TYPE_AUTH_CERT,
                    VENDOR_TYPE_SIGNATURE,
                    VENDOR_TYPE_DOWNGOING,
                    VENDOR_TYPE_UPGOING,
                    VENDOR_TYPE_TUNNEL_DATA,
                    VENDOR_TYPE_WIRELESS_TEST,
                }:
                    if vtype == VENDOR_TYPE_SIGNATURE:
                        signature = content
                        result = "sig"
                    else:
                        if vtype == VENDOR_TYPE_TUNNEL_DATA:
                            tunnel_parts.append(content)
                        result = "non_sig"

        if signable_error is not None:
            continue
        if signable_start is None:
            if result == "sig":
                signable_start = ends[i]
            elif result == "non_sig":
                signable_error = "SignatureNotFirst"
        else:
            if result == "sig":
                signable_error = "DuplicateSignatureMessage"
            elif result == "non_sig":
                last_non_sig_end = ends[i]

    if not tunnel_parts:
        raise ValueError("No tunnel data")
    if signature is None:
        raise ValueError("No signature")

    if signable_error is not None:
        raise ValueError(signable_error)
    if signable_start is None:
        raise ValueError("NoSignature")
    if last_non_sig_end is None or last_non_sig_end <= signable_start:
        raise ValueError("NothingValidToSign")

    blob = b"".join(raw_tags)
    signable = blob[signable_start:last_non_sig_end]
    return TunnelParseResult(
        signature=signature,
        signable=signable,
        tunnel_data=b"".join(tunnel_parts),
    )


def verify_signature(signature: bytes, signable: bytes, v2v_key_hex: str) -> None:
    if Ed25519PublicKey is None:
        raise RuntimeError("cryptography is required for signature verification")
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(v2v_key_hex))
    key.verify(signature, signable)


def _decode_raw(codec: ZmdCodec, payload: bytes, mode: str) -> Mapping[str, Any] | None:
    if mode == "command":
        return codec.decode_command_payload(payload)
    if mode == "response":
        return codec.decode_response_payload(payload)
    if mode == "auto":
        try:
            return codec.decode_command_payload(payload)
        except Exception:
            return codec.decode_response_payload(payload)
    raise ValueError(f"Unknown mode: {mode}")


def _unwrap_udp_bridge_payload(payload: bytes) -> bytes:
    vc = parse_vertical_comms_ipv4_udp_packet(payload)
    udp_payload = vc["payload"]
    hdr = parse_udp_bridge_rtmp_header(udp_payload)
    transport_len = hdr["transport_len"]
    message_len = hdr["message_len"]
    off = 6 + transport_len
    end = off + message_len
    if len(udp_payload) < end + 4:
        raise ValueError("udp-bridge RTMP truncated")
    body = udp_payload[:end]
    crc_expected = struct.unpack("<I", udp_payload[end : end + 4])[0]
    crc_actual = zlib.crc32(body) & 0xFFFFFFFF
    if crc_actual != crc_expected:
        raise ValueError("udp-bridge RTMP CRC mismatch")
    return udp_payload[off:end]


def _parse_udp_zrtmp_transport_data(buf: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    off = 0
    while off + 3 <= len(buf):
        t = buf[off]
        field_hash = int.from_bytes(buf[off + 1 : off + 3], "little")
        off += 3
        if t == 4:  # u32
            if off + 4 > len(buf):
                raise ValueError("udp-bridge transport truncated u32")
            out[field_hash] = int.from_bytes(buf[off : off + 4], "little")
            off += 4
        elif t == 1:  # bool
            if off + 1 > len(buf):
                raise ValueError("udp-bridge transport truncated bool")
            out[field_hash] = bool(buf[off])
            off += 1
        elif t == 0 and off == len(buf):
            break
        else:
            raise ValueError(f"udp-bridge transport unknown field type {t}")
    return out


def _extract_udp_bridge_identifier_hash(payload: bytes) -> int:
    vc = parse_vertical_comms_ipv4_udp_packet(payload)
    udp_payload = vc["payload"]
    hdr = parse_udp_bridge_rtmp_header(udp_payload)
    transport_len = hdr["transport_len"]
    if len(udp_payload) < 6 + transport_len:
        raise ValueError("udp-bridge transport truncated")
    transport = udp_payload[6 : 6 + transport_len]
    fields = _parse_udp_zrtmp_transport_data(transport)
    if 53931 not in fields:
        raise ValueError("udp-bridge transport has no bridge_identifier_fnv32a")
    return int(fields[53931])


def _unwrap_zipping_point_vertical_payload(
    payload: bytes,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    bridge_identifier: str,
) -> bytes:
    vc = parse_vertical_comms_ipv4_udp_packet(payload)
    if vc["src_ip"] != src_ip or vc["dst_ip"] != dst_ip:
        raise ValueError(
            f"Vertical IP tuple mismatch {vc['src_ip']}->{vc['dst_ip']}"
        )
    if vc["src_port"] != src_port or vc["dst_port"] != dst_port:
        raise ValueError(
            f"Vertical UDP tuple mismatch {vc['src_port']}->{vc['dst_port']}"
        )
    udp_payload = vc["payload"]
    hdr = parse_udp_bridge_rtmp_header(udp_payload)
    transport_len = hdr["transport_len"]
    message_len = hdr["message_len"]
    off = 6 + transport_len
    end = off + message_len
    if len(udp_payload) < end + 4:
        raise ValueError("udp-bridge RTMP truncated")
    body = udp_payload[:end]
    crc_expected = struct.unpack("<I", udp_payload[end : end + 4])[0]
    crc_actual = zlib.crc32(body) & 0xFFFFFFFF
    if crc_actual != crc_expected:
        raise ValueError("udp-bridge RTMP CRC mismatch")
    transport = udp_payload[6 : 6 + transport_len]
    fields = _parse_udp_zrtmp_transport_data(transport)
    bridge_hash = fields.get(53931)
    expected_hash = _fnv32a(bridge_identifier.encode("utf-8"))
    if bridge_hash != expected_hash:
        raise ValueError(
            f"udp-bridge identifier mismatch got={bridge_hash} expected={expected_hash}"
        )
    return udp_payload[off:end]


def decode_payload(
    payload: bytes,
    codec: ZmdCodec,
    mode: str = "auto",
    *,
    require_zipping_point_vertical: bool = False,
    vc_src_ip: str = DROID_IP_DEFAULT,
    vc_dst_ip: str = ZIP_IP_DEFAULT,
    vc_src_port: int = DROID_PORT_DEFAULT,
    vc_dst_port: int = ZIP_PORT_DEFAULT,
    bridge_identifier: str = DROID_TO_ZIP_BRIDGE_IDENTIFIER,
) -> Mapping[str, Any] | None:
    if require_zipping_point_vertical:
        inner = _unwrap_zipping_point_vertical_payload(
            payload,
            vc_src_ip,
            vc_dst_ip,
            vc_src_port,
            vc_dst_port,
            bridge_identifier,
        )
        try:
            return _decode_raw(codec, inner, mode)
        except Exception:
            wrapped = _unwrap_admin_wrapper_payload(inner)
            return _decode_raw(codec, wrapped, mode)
    try:
        return _decode_raw(codec, payload, mode)
    except Exception:
        pass
    try:
        _name, msg = codec.decode(payload)
        return msg
    except Exception:
        pass
    inner = _unwrap_udp_bridge_payload(payload)
    return _decode_raw(codec, inner, mode)


def _main() -> None:
    parser = argparse.ArgumentParser(description="Sniff and decode tunnel frames")
    parser.add_argument("interface", nargs="?", default=DEFAULT_INTERFACE)
    parser.add_argument("--zmd-file", default="zmd/droid_zipping_point.zmd")
    parser.add_argument("--v2v-key-hex", default=DEFAULT_V2V_KEY_HEX)
    parser.add_argument("--no-verify-signature", action="store_true")
    parser.add_argument("--decode-zmd", action="store_true")
    parser.add_argument("--no-zipping-point-filter", action="store_true")
    parser.add_argument(
        "--only-zipping-point-command",
        action="store_true",
        help="Only print frames that decode to a zipping-point command payload",
    )
    parser.add_argument("--peer-mac", default=None, help="Only process frames from this source MAC")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--bridge-summary-interval-s",
        type=float,
        default=5.0,
        help="Print top observed udp-bridge identifier hashes every N seconds (0 to disable)",
    )
    args = parser.parse_args()

    codec = ZmdCodec(args.zmd_file)
    print(f"[RX] Listening on {args.interface} for OUI {TARGET_OUI.hex(':')}")
    expected_cmd_hash = _fnv32a(DROID_TO_ZIP_BRIDGE_IDENTIFIER.encode("utf-8"))
    expected_resp_hash = _fnv32a(ZIP_TO_DROID_BRIDGE_IDENTIFIER.encode("utf-8"))
    bridge_counts: dict[int, int] = defaultdict(int)
    last_bridge_report = time.monotonic()

    def maybe_report_bridge_summary(now: float) -> None:
        nonlocal last_bridge_report
        if args.bridge_summary_interval_s <= 0:
            return
        if now - last_bridge_report < args.bridge_summary_interval_s:
            return
        last_bridge_report = now
        if not bridge_counts:
            print("[RX][BRIDGE] no udp-bridge identifiers observed yet")
            return
        top = sorted(bridge_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
        parts = []
        for h, c in top:
            label = ""
            if h == expected_cmd_hash:
                label = " (droid->zip zipping-point command)"
            elif h == expected_resp_hash:
                label = " (zip->droid zipping-point response)"
            parts.append(f"{h}:{c}{label}")
        print(f"[RX][BRIDGE] top hashes: {' | '.join(parts)}")

    def on_pkt(pkt):
        now = time.monotonic()
        maybe_report_bridge_summary(now)
        if not pkt.haslayer(Dot11):
            return
        if args.peer_mac and (pkt.addr2 or "").lower() != args.peer_mac.lower():
            return
        try:
            parsed = extract_tunnel_parse_result(pkt)
        except Exception as exc:
            print(f"[RX] parse failed: {exc}")
            if args.verbose:
                src = (pkt.addr2 or "").lower()
                dest = (pkt.addr1 or "").lower()
                elements = extract_vendor_elements(pkt)
                vtypes = ",".join(f"0x{e.vendor_type:02x}" for e in elements) if elements else "none"
                print(
                    f"[RX][DBG] src={src} dest={dest} zipline_vendor_types=[{vtypes}] count={len(elements)}"
                )
            return
        if not args.no_verify_signature:
            try:
                verify_signature(parsed.signature, parsed.signable, args.v2v_key_hex)
            except Exception as exc:
                print(f"[RX] signature verify failed: {exc}")
                if args.verbose:
                    print(
                        f"[RX][DBG] signable_len={len(parsed.signable)} signature_len={len(parsed.signature)}"
                    )
                return
        try:
            rtmp = parse_rtmp_frame(parsed.tunnel_data)
            transport = parse_frame_injection_transport(rtmp["transport"])
        except Exception as exc:
            print(f"[RX] RTMP parse failed: {exc}")
            if args.verbose:
                print(f"[RX][DBG] tunnel_data_len={len(parsed.tunnel_data)}")
            return
        try:
            bridge_hash = _extract_udp_bridge_identifier_hash(rtmp["payload"])
            bridge_counts[bridge_hash] += 1
        except Exception:
            pass
        decoded_msg = None
        if args.decode_zmd:
            try:
                decoded_msg = decode_payload(
                    rtmp["payload"],
                    codec,
                    "auto",
                    require_zipping_point_vertical=not args.no_zipping_point_filter,
                    vc_src_ip=DROID_IP_DEFAULT,
                    vc_dst_ip=ZIP_IP_DEFAULT,
                    vc_src_port=DROID_PORT_DEFAULT,
                    vc_dst_port=ZIP_PORT_DEFAULT,
                    bridge_identifier=DROID_TO_ZIP_BRIDGE_IDENTIFIER,
                )
                if args.only_zipping_point_command and (
                    not isinstance(decoded_msg, Mapping) or "command" not in decoded_msg
                ):
                    return
            except Exception as exc:
                if args.only_zipping_point_command:
                    return
                print(f"     ZMD decode failed: {exc}")
                # Helpful when traffic is valid vertical-comms UDP but from a different
                # bridge identifier than zipping-point.
                if "udp-bridge identifier mismatch" in str(exc):
                    try:
                        inner = _unwrap_udp_bridge_payload(rtmp["payload"])
                        try:
                            name, msg = codec.decode(inner)
                            print(f"     ZMD(other bridge): {name} {msg}")
                        except Exception:
                            print(
                                f"     ZMD(other bridge) undecodable, inner_len={len(inner)}"
                            )
                    except Exception as inner_exc:
                        if args.verbose:
                            print(f"     [DBG] inner unwrap failed: {inner_exc}")
                return

        print(
            f"[RX] From {(pkt.addr2 or '').lower()} -> dest={transport['destination_address'].hex(':')}"
            f" session={transport['session_id']}"
        )
        if args.verbose:
            print(
                f"[RX][DBG] inj_counter={transport['injection_counter']} antenna={transport['injection_antenna_index']}"
                f" rtmp_payload_len={len(rtmp['payload'])}"
            )
        if args.decode_zmd:
            print(f"     ZMD: {decoded_msg}")

    sniff(iface=args.interface, prn=on_pkt, store=0)


if __name__ == "__main__":
    _main()
