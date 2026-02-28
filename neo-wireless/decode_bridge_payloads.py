#!/usr/bin/env python3
"""
Quick bridge payload decoder for tunnel traffic.

Use this to inspect payload bytes for non-zipping-point bridge hashes.
"""

from __future__ import annotations

import argparse
import binascii
from pathlib import Path
import struct
import zlib
from typing import Any

from scapy.all import Dot11, sniff

from tunnel_sniffer import (
    extract_tunnel_parse_result,
    parse_frame_injection_transport,
    parse_rtmp_frame,
    parse_vertical_comms_ipv4_udp_packet,
    parse_udp_bridge_rtmp_header,
)


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
            out[str(field_hash)] = int.from_bytes(buf[off : off + 4], "little")
            off += 4
        elif t == 1:  # bool
            if off + 1 > len(buf):
                raise ValueError("udp-bridge transport truncated bool")
            out[str(field_hash)] = bool(buf[off])
            off += 1
        elif t == 0 and off == len(buf):
            break
        else:
            raise ValueError(f"udp-bridge transport unknown field type {t}")
    return out


def _extract_bridge_info(payload: bytes) -> dict[str, Any]:
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
    transport = udp_payload[6 : 6 + transport_len]
    fields = _parse_udp_zrtmp_transport_data(transport)
    bridge_hash = fields.get("53931")
    return {
        "src_ip": vc["src_ip"],
        "dst_ip": vc["dst_ip"],
        "src_port": vc["src_port"],
        "dst_port": vc["dst_port"],
        "bridge_hash": bridge_hash,
        "transport_fields": fields,
        "inner_payload": udp_payload[off:end],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Decode udp-bridge payload bytes from tunnel frames")
    parser.add_argument("interface", help="Monitor-mode interface, e.g. wlan0")
    parser.add_argument("--peer-mac", default=None, help="Only process frames from this source MAC")
    parser.add_argument(
        "--bridge-hash",
        action="append",
        type=int,
        default=None,
        help="Only print frames for this bridge hash (repeatable)",
    )
    parser.add_argument("--max-frames", type=int, default=0, help="Stop after N printed frames (0 = infinite)")
    parser.add_argument("--hex-bytes", type=int, default=128, help="Hex preview length for payload bytes")
    parser.add_argument(
        "--save-dir",
        default=None,
        help="Optional directory to save inner payload bytes as .bin files",
    )
    parser.add_argument(
        "--save-limit",
        type=int,
        default=0,
        help="Maximum saved payload files (0 = unlimited while running)",
    )
    args = parser.parse_args()

    wanted = set(args.bridge_hash or [])
    printed = 0
    saved = 0
    save_dir: Path | None = None
    if args.save_dir:
        save_dir = Path(args.save_dir)
        save_dir.mkdir(parents=True, exist_ok=True)
        print(f"[BRIDGE] saving payloads to: {save_dir}")

    print(f"[BRIDGE] Listening on {args.interface}")
    if args.peer_mac:
        print(f"[BRIDGE] peer-mac filter: {args.peer_mac.lower()}")
    if wanted:
        print(f"[BRIDGE] bridge-hash filter: {sorted(wanted)}")

    def on_pkt(pkt) -> None:
        nonlocal printed, saved
        if not pkt.haslayer(Dot11):
            return
        if args.peer_mac and (pkt.addr2 or "").lower() != args.peer_mac.lower():
            return
        try:
            parsed = extract_tunnel_parse_result(pkt)
            outer = parse_rtmp_frame(parsed.tunnel_data)
            inj = parse_frame_injection_transport(outer["transport"])
            info = _extract_bridge_info(outer["payload"])
        except Exception:
            return

        h = info["bridge_hash"]
        if h is None:
            return
        if wanted and h not in wanted:
            return

        payload = info["inner_payload"]
        preview = binascii.hexlify(payload[: args.hex_bytes]).decode("ascii")
        print(
            "[BRIDGE] "
            f"src={(pkt.addr2 or '').lower()} session={inj['session_id']} "
            f"inj={inj['injection_counter']} hash={h} "
            f"udp={info['src_ip']}:{info['src_port']}->{info['dst_ip']}:{info['dst_port']} "
            f"inner_len={len(payload)}"
        )
        print(f"         transport={info['transport_fields']}")
        print(f"         payload_hex={preview}")

        if save_dir is not None and (args.save_limit == 0 or saved < args.save_limit):
            fname = (
                f"bridge_{h}_inj_{inj['injection_counter']}_"
                f"src_{(pkt.addr2 or '').lower().replace(':', '')}.bin"
            )
            out = save_dir / fname
            out.write_bytes(payload)
            saved += 1
            print(f"         saved={out}")

        printed += 1
        if args.max_frames > 0 and printed >= args.max_frames:
            raise KeyboardInterrupt

    try:
        sniff(iface=args.interface, prn=on_pkt, store=0)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
