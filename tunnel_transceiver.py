#!/usr/bin/env python3
"""
Bidirectional tunnel transceiver.

Sniffs V2V tunnel beacons, decodes ZMD commands, and responds with ZMD
responses through the same tunnel framing.
"""

from __future__ import annotations

import argparse
import os
import struct
import threading
import time
from typing import Any, Mapping, Optional, Set, Tuple

from scapy.all import Dot11, sniff, sendp

from config import DEFAULT_INTERFACE, DEFAULT_SRC_MAC, DEFAULT_TX_RATE_HZ
from handoff_protocol import (
    CMD_HANDOFF_PACKAGE,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_IN_PROGRESS,
    build_response,
    build_response_in_progress,
    get_command_id_key,
)
from protocol import ZmdCodec
import importlib

_v2v_mod = importlib.import_module("gen-v2v-beaconv2")
V2VBeaconGenerator = _v2v_mod.V2VBeaconGenerator
V2VFrameConfig = _v2v_mod.V2VFrameConfig
from tunnel_sniffer import (
    DEFAULT_V2V_KEY_HEX,
    VENDOR_TYPE_SIGNATURE,
    extract_vendor_elements,
    parse_frame_injection_transport,
    parse_mac,
    parse_rtmp_frame,
    verify_signature,
    decode_payload,
)

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
    ipv4_checksum = _checksum16(ipv4_wo_checksum)
    ipv4_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0,
        0,
        64,
        17,
        ipv4_checksum,
        src_ip_b,
        dst_ip_b,
    )
    return ipv4_header + udp_header + payload


class HandoffState:
    """Tracks seen command IDs for duplicate detection."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: Set[Tuple] = set()

    def has_seen(self, key: Tuple) -> bool:
        with self._lock:
            return key in self._seen

    def mark_seen(self, key: Tuple) -> None:
        with self._lock:
            self._seen.add(key)


class TunnelTransceiver:
    def __init__(
        self,
        interface: str,
        src_mac: str,
        dest_mac: str,
        session_id: Optional[int],
        v2v_key_hex: str,
        antenna_index: int,
        rate_hz: float,
        zmd_file: str,
        self_mac_filter: Optional[str] = None,
        peer_mac_filter: Optional[str] = None,
        verify_signature: bool = True,
        complete_delay_s: float = 2.0,
        package_mass_kg: float = 2.35,
        wrap_vendor_ie: bool = False,
        wrap_vertical_comms: bool = True,
        vc_src_ip: str = ZIP_IP_DEFAULT,
        vc_dst_ip: str = DROID_IP_DEFAULT,
        vc_src_port: int = ZIP_PORT_DEFAULT,
        vc_dst_port: int = DROID_PORT_DEFAULT,
        verbose: bool = False,
    ) -> None:
        self.interface = interface
        self.session_id = session_id
        self.verify_signature_enabled = verify_signature
        self.complete_delay_s = complete_delay_s
        self.package_mass_kg = package_mass_kg
        self.wrap_vendor_ie = wrap_vendor_ie
        self.wrap_vertical_comms = wrap_vertical_comms
        self.vc_src_ip = vc_src_ip
        self.vc_dst_ip = vc_dst_ip
        self.vc_src_port = vc_src_port
        self.vc_dst_port = vc_dst_port
        self._v2v_key_hex = v2v_key_hex
        self.verbose = verbose

        self._codec = ZmdCodec(zmd_file)
        self._state = HandoffState()

        self._self_mac = parse_mac(self_mac_filter) if self_mac_filter else None
        self._peer_mac = peer_mac_filter.lower() if peer_mac_filter else None
        self._learned_session_id: Optional[int] = None
        self._tx_lock = threading.Lock()

        self._tx_gen = V2VBeaconGenerator(
            V2VFrameConfig(
                src_mac=src_mac,
                dest_mac=dest_mac,
                session_id=session_id if session_id is not None else 0,
                injection_counter=0,
                injection_antenna_index=antenna_index,
                rtmp_version=1,
                rtmp_frame_count=None,
                payload=b"",
                windowed_reliable_seqnum=None,
                nack_windowed_seqnums=None,
                besteffort_seqnum=None,
                tx_window_name=None,
                nack_list_window_name=None,
                v2v_key=bytes.fromhex(v2v_key_hex),
                rate_kbps=6000,
            )
        )
        self._tx_payload: Optional[bytes] = None
        self._tx_rate_hz = rate_hz
        self._tx_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._tx_counter = 0

    # -- TX -----------------------------------------------------------------

    def set_tx_payload(self, payload: bytes) -> None:
        self._tx_payload = payload
        if self.verbose:
            print(f"[TRX] TX payload set: {len(payload)} bytes")

    def _tx_loop(self) -> None:
        interval = 1.0 / self._tx_rate_hz
        while not self._stop.is_set():
            if not self._tx_payload:
                time.sleep(interval)
                continue
            with self._tx_lock:
                self._tx_gen.cfg.payload = self._tx_payload
                frame, _, _, _ = self._tx_gen.build_frame()
            sendp(frame, iface=self.interface, verbose=False)
            self._tx_counter += 1
            time.sleep(interval)

    # -- RX -----------------------------------------------------------------

    def _handle_packet(self, pkt) -> None:
        if not pkt.haslayer(Dot11):
            return
        if self._peer_mac and (pkt.addr2 or "").lower() != self._peer_mac:
            return

        elements = extract_vendor_elements(pkt)
        if not elements:
            return
        if elements[0].vendor_type != VENDOR_TYPE_SIGNATURE:
            if self.verbose:
                print(f"[TRX] Drop: first vendor type=0x{elements[0].vendor_type:02x}")
            return

        signature = elements[0].content
        signable = b"".join(e.raw for e in elements[1:])
        if self.verify_signature_enabled:
            try:
                verify_signature(signature, signable, self._v2v_key_hex)
            except Exception as exc:
                if self.verbose:
                    print(f"[TRX] Drop: signature verify failed ({exc})")
                return

        tunnel_chunks = [e.content for e in elements if e.vendor_type == 0x06]
        if not tunnel_chunks:
            if self.verbose:
                print("[TRX] Drop: no tunnel data vendor IEs")
            return
        tunnel_data = b"".join(tunnel_chunks)

        try:
            rtmp = parse_rtmp_frame(tunnel_data)
            transport = parse_frame_injection_transport(rtmp["transport"])
        except Exception as exc:
            if self.verbose:
                print(f"[TRX] Drop: RTMP/transport parse failed ({exc})")
            return

        rx_session_id = transport["session_id"]
        if self.session_id is not None:
            if rx_session_id != self.session_id:
                if self.verbose:
                    print(
                        f"[TRX] Drop: session mismatch rx={rx_session_id}"
                        f" expected={self.session_id}"
                    )
                return
        else:
            if self._learned_session_id is None:
                self._learned_session_id = rx_session_id
                if self.verbose:
                    print(f"[TRX] Learned session_id={self._learned_session_id} from RX")
            elif rx_session_id != self._learned_session_id:
                if self.verbose:
                    print(
                        f"[TRX] Drop: session mismatch rx={rx_session_id}"
                        f" learned={self._learned_session_id}"
                    )
                return
        if self._self_mac is not None:
            if transport["destination_address"] != self._self_mac:
                if self.verbose:
                    print(
                        "[TRX] Drop: dest MAC mismatch "
                        f"rx={transport['destination_address'].hex(':')}"
                    )
                return

        decoded = decode_payload(rtmp["payload"], self._codec, "auto")
        if not decoded or "command" not in decoded:
            if self.verbose:
                print("[TRX] Drop: payload did not decode to a command")
            return

        key = get_command_id_key(decoded)
        if self._state.has_seen(key):
            if self.verbose:
                print("[TRX] Drop: duplicate command")
            return
        self._state.mark_seen(key)

        if self.verbose:
            src = (pkt.addr2 or "").lower()
            dest = (pkt.addr1 or "").lower()
            print(
                "[TRX] RX "
                f"src={src} dest={dest} "
                f"session={transport['session_id']} "
                f"inj_counter={transport['injection_counter']} "
                f"antenna={transport['injection_antenna_index']}"
            )
            print(f"[TRX] ZMD command: {decoded}")

        # Send IN_PROGRESS immediately
        in_prog = build_response_in_progress(self._codec, decoded)
        self._set_response_payload(in_prog, rx_session_id)
        if self.verbose:
            print(f"[TRX] TX response: IN_PROGRESS {in_prog}")

        # Complete in background
        threading.Thread(
            target=self._complete_command, args=(decoded, rx_session_id), daemon=True
        ).start()

    def _set_response_payload(self, resp: Mapping[str, Any], session_id: int) -> None:
        if self.wrap_vendor_ie:
            payload = self._codec.encode_response(resp)
        else:
            payload = self._codec.encode_response_payload(resp)
        if self.wrap_vertical_comms:
            payload = build_vertical_comms_ipv4_udp_packet(
                payload,
                self.vc_src_ip,
                self.vc_dst_ip,
                self.vc_src_port,
                self.vc_dst_port,
            )
        with self._tx_lock:
            self._tx_gen.cfg.session_id = session_id
        self.set_tx_payload(payload)

    def _complete_command(self, cmd: Mapping[str, Any], session_id: int) -> None:
        time.sleep(self.complete_delay_s)
        status = STATUS_COMPLETED
        mass = 0.0
        if cmd["command"] == CMD_HANDOFF_PACKAGE:
            mass = self.package_mass_kg
        resp = build_response(self._codec, cmd, status, package_mass_kg=mass)
        self._set_response_payload(resp, session_id)
        if self.verbose:
            print(f"[TRX] TX response: COMPLETED {resp}")

    # -- Lifecycle -----------------------------------------------------------

    def start(self) -> None:
        self._stop.clear()
        self._tx_thread = threading.Thread(target=self._tx_loop, daemon=True)
        self._tx_thread.start()
        sniff(iface=self.interface, prn=self._handle_packet, store=0, stop_filter=lambda _: self._stop.is_set())

    def stop(self) -> None:
        self._stop.set()
        if self._tx_thread is not None:
            self._tx_thread.join(timeout=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Tunnel transceiver (sniff + respond)")
    parser.add_argument("interface", nargs="?", default=DEFAULT_INTERFACE)
    parser.add_argument("--src-mac", default=DEFAULT_SRC_MAC)
    parser.add_argument("--dest-mac", required=True, help="Peer MAC to send to (transport dest)")
    parser.add_argument("--self-mac", default=None, help="Only accept frames addressed to this MAC")
    parser.add_argument("--peer-mac", default=None, help="Only accept frames from this MAC")
    parser.add_argument(
        "--session-id",
        type=int,
        default=None,
        help="If omitted, learn from first valid droid frame and echo that session",
    )
    parser.add_argument("--v2v-key-hex", default=DEFAULT_V2V_KEY_HEX)
    parser.add_argument("--antenna-index", type=int, default=0)
    parser.add_argument("--rate-hz", type=float, default=DEFAULT_TX_RATE_HZ)
    parser.add_argument("--zmd-file", default="zmd/droid_zipping_point.zmd")
    parser.add_argument("--no-verify-signature", action="store_true")
    parser.add_argument("--complete-delay", type=float, default=2.0)
    parser.add_argument("--package-mass-kg", type=float, default=2.35)
    parser.add_argument("--wrap-vendor-ie", action="store_true")
    parser.add_argument("--no-vertical-comms-wrap", action="store_true")
    parser.add_argument("--vc-src-ip", default=ZIP_IP_DEFAULT)
    parser.add_argument("--vc-dst-ip", default=DROID_IP_DEFAULT)
    parser.add_argument("--vc-src-port", type=int, default=ZIP_PORT_DEFAULT)
    parser.add_argument("--vc-dst-port", type=int, default=DROID_PORT_DEFAULT)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: This script must be run as root (sudo)")
        raise SystemExit(1)

    trx = TunnelTransceiver(
        interface=args.interface,
        src_mac=args.src_mac,
        dest_mac=args.dest_mac,
        session_id=args.session_id,
        v2v_key_hex=args.v2v_key_hex,
        antenna_index=args.antenna_index,
        rate_hz=args.rate_hz,
        zmd_file=args.zmd_file,
        self_mac_filter=args.self_mac,
        peer_mac_filter=args.peer_mac,
        verify_signature=not args.no_verify_signature,
        complete_delay_s=args.complete_delay,
        package_mass_kg=args.package_mass_kg,
        wrap_vendor_ie=args.wrap_vendor_ie,
        wrap_vertical_comms=not args.no_vertical_comms_wrap,
        vc_src_ip=args.vc_src_ip,
        vc_dst_ip=args.vc_dst_ip,
        vc_src_port=args.vc_src_port,
        vc_dst_port=args.vc_dst_port,
        verbose=args.verbose,
    )

    if args.verbose:
        if args.session_id is None:
            print(f"[TRX] Listening on {args.interface} session=auto(first RX frame)")
        else:
            print(f"[TRX] Listening on {args.interface} session={args.session_id}")
        if not args.no_vertical_comms_wrap:
            print(
                "[TRX] vertical_comms:"
                f" {args.vc_src_ip}:{args.vc_src_port} -> {args.vc_dst_ip}:{args.vc_dst_port}"
            )

    try:
        trx.start()
    except KeyboardInterrupt:
        pass
    finally:
        trx.stop()


if __name__ == "__main__":
    main()
