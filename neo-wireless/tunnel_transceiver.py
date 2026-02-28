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
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Set, Tuple

from scapy.all import Dot11, sniff, sendp

from config import DEFAULT_INTERFACE, DEFAULT_SRC_MAC, DEFAULT_TX_RATE_HZ
from handoff_protocol import (
    CMD_DESCEND_TO_DROID_CLEARANCE,
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
DEFAULT_V2V_SIGNING_KEY_HEX = _v2v_mod.DEFAULT_V2V_KEY_HEX
DROID_TO_ZIP_BRIDGE_IDENTIFIER = _v2v_mod.DROID_TO_ZIP_BRIDGE_IDENTIFIER
ZIP_TO_DROID_BRIDGE_IDENTIFIER = _v2v_mod.ZIP_TO_DROID_BRIDGE_IDENTIFIER
encode_udp_zrtmp_transport_data = _v2v_mod.encode_udp_zrtmp_transport_data
pack_udp_bridge_rtmp_frame = _v2v_mod.pack_udp_bridge_rtmp_frame
wrap_admin_wrapper_payload = _v2v_mod.wrap_admin_wrapper_payload
_fnv32a = _v2v_mod._fnv32a
from tunnel_sniffer import (
    DEFAULT_V2V_KEY_HEX,
    extract_tunnel_parse_result,
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

try:
    import serial  # type: ignore
except Exception:
    serial = None


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


@dataclass
class PendingCompletion:
    key: Tuple
    cmd: Mapping[str, Any]
    session_id: int
    stage: str
    started_at: float


class TunnelTransceiver:
    def __init__(
        self,
        interface: str,
        src_mac: str,
        dest_mac: str,
        session_id: Optional[int],
        v2v_verify_pubkey_hex: str,
        v2v_sign_privkey_hex: str,
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
        wrap_udp_rtmp: bool = True,
        udp_rtmp_transport_version: int = 0,
        udp_rtmp_frame_count: int = 0,
        vc_src_ip: str = ZIP_IP_DEFAULT,
        vc_dst_ip: str = DROID_IP_DEFAULT,
        vc_src_port: int = ZIP_PORT_DEFAULT,
        vc_dst_port: int = DROID_PORT_DEFAULT,
        serial_port: Optional[str] = None,
        serial_baud: int = 115200,
        serial_timeout: float = 0.2,
        serial_debug_mode: str = "off",
        actuator_timeout_s: float = 8.0,
        verbose: bool = False,
    ) -> None:
        self.interface = interface
        self.session_id = session_id
        self.verify_signature_enabled = verify_signature
        self.complete_delay_s = complete_delay_s
        self.package_mass_kg = package_mass_kg
        self.wrap_vendor_ie = wrap_vendor_ie
        self.wrap_vertical_comms = wrap_vertical_comms
        self.wrap_udp_rtmp = wrap_udp_rtmp
        self.udp_rtmp_transport_version = udp_rtmp_transport_version
        self.udp_rtmp_frame_count = udp_rtmp_frame_count
        self.vc_src_ip = vc_src_ip
        self.vc_dst_ip = vc_dst_ip
        self.vc_src_port = vc_src_port
        self.vc_dst_port = vc_dst_port
        self._v2v_verify_pubkey_hex = v2v_verify_pubkey_hex
        self._v2v_sign_privkey_hex = v2v_sign_privkey_hex
        self.verbose = verbose
        self.serial_port = serial_port
        self.serial_baud = serial_baud
        self.serial_timeout = serial_timeout
        self.serial_debug_mode = serial_debug_mode
        self.actuator_timeout_s = actuator_timeout_s

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
                v2v_key=bytes.fromhex(v2v_sign_privkey_hex),
                rate_kbps=6000,
            )
        )
        self._tx_payload: Optional[bytes] = None
        self._tx_rate_hz = rate_hz
        self._tx_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._tx_counter = 0
        self._serial = None
        self._serial_lock = threading.Lock()
        self._serial_rx_thread: Optional[threading.Thread] = None
        self._descend_count = 0
        self._pending_lock = threading.Lock()
        self._pending: dict[Tuple, PendingCompletion] = {}
        self._pending_stage_queues: dict[str, list[Tuple]] = {
            "DESCEND_TO_DROID_CLEARANCE_HEIGHT": [],
            "HANDOFF_PACKAGE_TO_DROID": [],
        }
        self._expected_command = CMD_DESCEND_TO_DROID_CLEARANCE

    def _open_serial(self) -> None:
        if self.serial_debug_mode == "mock":
            if self.verbose:
                print("[TRX] Serial debug mode: mock (no hardware required)")
            return
        if not self.serial_port:
            return
        if serial is None:
            raise RuntimeError(
                "pyserial is required for --serial-port. Install with: python3 -m pip install pyserial"
            )
        self._serial = serial.Serial(
            self.serial_port,
            self.serial_baud,
            timeout=self.serial_timeout,
        )
        if self.verbose:
            print(
                f"[TRX] Serial bridge connected: port={self.serial_port} baud={self.serial_baud}"
            )

    def _serial_rx_loop(self) -> None:
        if self.serial_debug_mode == "mock":
            return
        while not self._stop.is_set() and self._serial is not None:
            try:
                raw = self._serial.readline()
            except Exception as exc:
                if self.verbose:
                    print(f"[TRX] Serial read error: {exc}")
                break
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").strip()
            if line:
                print(f"[TRX][SER] {line}")
                self._on_serial_line(line)

    def _send_serial_command(self, cmd: str, why: str) -> None:
        if self.serial_debug_mode == "mock":
            print(f"[TRX][SER-MOCK] TX ({why}): {cmd}")
            print(f"[TRX][SER-MOCK] RX MOCK_ACK:{cmd}")
            return
        if self._serial is None:
            return
        with self._serial_lock:
            self._serial.write((cmd + "\n").encode("ascii"))
            self._serial.flush()
        print(f"[TRX] Serial TX ({why}): {cmd}")

    def _dispatch_command_to_cycle_tester(self, cmd: Mapping[str, Any]) -> None:
        if self._serial is None and self.serial_debug_mode != "mock":
            return "NONE"
        command_type = cmd.get("command")
        serial_cmd = None
        reason = ""
        stage = "NONE"
        if command_type == "DESCEND_TO_DROID_CLEARANCE_HEIGHT":
            self._descend_count += 1
            serial_cmd = "trx_descend_to_droid_clearance_height"
            reason = (
                "DESCEND_TO_DROID_CLEARANCE_HEIGHT #1"
                if self._descend_count == 1
                else "DESCEND_TO_DROID_CLEARANCE_HEIGHT (subsequent)"
            )
            stage = "DESCEND_TO_DROID_CLEARANCE_HEIGHT"
        elif command_type == "HANDOFF_PACKAGE_TO_DROID":
            serial_cmd = "trx_handoff_package_to_droid"
            reason = "HANDOFF_PACKAGE_TO_DROID"
            stage = "HANDOFF_PACKAGE_TO_DROID"

        if serial_cmd:
            self._send_serial_command(serial_cmd, reason)
        elif self.verbose:
            print(f"[TRX] No serial mapping for command: {command_type}")
        return stage

    def _on_serial_line(self, line: str) -> None:
        if line == "AUTO_READY" or line == "AUTO2_READY":
            self._expected_command = CMD_DESCEND_TO_DROID_CLEARANCE
            if self.verbose:
                print("[TRX] Command gate reset: expect DESCEND_TO_DROID_CLEARANCE_HEIGHT")
        if line.startswith("AUTO_WAIT_CMD:") or line.startswith("AUTO2_WAIT_CMD:"):
            wait_cmd = line.split(":", 1)[1].strip().upper()
            if wait_cmd == "DESCEND_TO_DROID_CLEARANCE_HEIGHT":
                self._expected_command = CMD_DESCEND_TO_DROID_CLEARANCE
            elif wait_cmd == "HANDOFF_PACKAGE_TO_DROID":
                self._expected_command = CMD_HANDOFF_PACKAGE
            if self.verbose:
                print(f"[TRX] Command gate update from cycle_tester: expect {self._expected_command}")
        if line.startswith("TRX_COMPLETE:") or line.startswith("TRX2_COMPLETE:"):
            stage = line.split(":", 1)[1].strip().upper()
            if stage in self._pending_stage_queues:
                self._complete_next_for_stage(stage, reason="actuator complete")

    def _register_pending_completion(
        self, key: Tuple, cmd: Mapping[str, Any], session_id: int, stage: str
    ) -> None:
        pending = PendingCompletion(
            key=key,
            cmd=cmd,
            session_id=session_id,
            stage=stage,
            started_at=time.time(),
        )
        with self._pending_lock:
            self._pending[key] = pending
            self._pending_stage_queues[stage].append(key)
        threading.Thread(
            target=self._pending_timeout_worker, args=(key,), daemon=True
        ).start()

    def _pending_timeout_worker(self, key: Tuple) -> None:
        time.sleep(self.actuator_timeout_s)
        with self._pending_lock:
            pending = self._pending.get(key)
            if pending is None:
                return
        self._complete_pending_key(
            key,
            reason=f"actuator timeout {self.actuator_timeout_s:.1f}s",
        )

    def _complete_next_for_stage(self, stage: str, reason: str) -> None:
        key: Optional[Tuple] = None
        with self._pending_lock:
            q = self._pending_stage_queues.get(stage, [])
            while q:
                candidate = q.pop(0)
                if candidate in self._pending:
                    key = candidate
                    break
        if key is not None:
            self._complete_pending_key(key, reason=reason)

    def _complete_pending_key(self, key: Tuple, reason: str) -> None:
        with self._pending_lock:
            pending = self._pending.pop(key, None)
            if pending is None:
                return
            q = self._pending_stage_queues.get(pending.stage, [])
            self._pending_stage_queues[pending.stage] = [k for k in q if k != key]
        status = STATUS_COMPLETED
        mass = 0.0
        if pending.cmd["command"] == CMD_HANDOFF_PACKAGE:
            mass = self.package_mass_kg
        resp = build_response(self._codec, pending.cmd, status, package_mass_kg=mass)
        self._set_response_payload(resp, pending.session_id)
        print(f"[TRX] TX response: COMPLETED ({reason}) {resp}")

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

        try:
            parsed = extract_tunnel_parse_result(pkt)
        except Exception as exc:
            if self.verbose:
                print(f"[TRX] Drop: tunnel/signable parse failed ({exc})")
            return

        if self.verify_signature_enabled:
            try:
                verify_signature(
                    parsed.signature,
                    parsed.signable,
                    self._v2v_verify_pubkey_hex,
                )
            except Exception as exc:
                if self.verbose:
                    print(f"[TRX] Drop: signature verify failed ({exc})")
                return

        tunnel_data = parsed.tunnel_data

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

        try:
            decoded = decode_payload(
                rtmp["payload"],
                self._codec,
                "auto",
                require_zipping_point_vertical=True,
                vc_src_ip=self.vc_dst_ip,
                vc_dst_ip=self.vc_src_ip,
                vc_src_port=self.vc_dst_port,
                vc_dst_port=self.vc_src_port,
                bridge_identifier=DROID_TO_ZIP_BRIDGE_IDENTIFIER,
            )
        except Exception as exc:
            if self.verbose:
                print(f"[TRX] Drop: payload decode failed ({exc})")
            return
        if not decoded or "command" not in decoded:
            if self.verbose:
                print("[TRX] Drop: payload did not decode to a command")
            return
        command_type = decoded.get("command")
        if command_type != self._expected_command:
            if self.verbose:
                print(
                    "[TRX] Drop: command out of sequence "
                    f"got={command_type} expected={self._expected_command}"
                )
            return

        key = get_command_id_key(decoded)
        if self._state.has_seen(key):
            if self.verbose:
                print("[TRX] Drop: duplicate command")
            return
        self._state.mark_seen(key)
        if command_type == CMD_DESCEND_TO_DROID_CLEARANCE:
            self._expected_command = CMD_HANDOFF_PACKAGE
        elif command_type == CMD_HANDOFF_PACKAGE:
            self._expected_command = CMD_DESCEND_TO_DROID_CLEARANCE

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
        stage = self._dispatch_command_to_cycle_tester(decoded)

        # Send IN_PROGRESS immediately
        in_prog = build_response_in_progress(self._codec, decoded)
        self._set_response_payload(in_prog, rx_session_id)
        if self.verbose:
            print(f"[TRX] TX response: IN_PROGRESS {in_prog}")

        serial_gated = stage in self._pending_stage_queues and self.serial_debug_mode != "mock" and self._serial is not None
        if serial_gated:
            self._register_pending_completion(key, decoded, rx_session_id, stage)
        else:
            threading.Thread(
                target=self._complete_command, args=(decoded, rx_session_id), daemon=True
            ).start()

    def _set_response_payload(self, resp: Mapping[str, Any], session_id: int) -> None:
        if self.wrap_vendor_ie:
            payload = self._codec.encode_response(resp)
        else:
            payload = self._codec.encode_response_payload(resp)
        payload = wrap_admin_wrapper_payload(payload)
        if self.wrap_udp_rtmp:
            transport = encode_udp_zrtmp_transport_data(
                mailbox_id=None,
                bridge_identifier_fnv32a=_fnv32a(
                    ZIP_TO_DROID_BRIDGE_IDENTIFIER.encode("utf-8")
                ),
                admin_wrapped=True,
            )
            payload = pack_udp_bridge_rtmp_frame(
                transport=transport,
                payload=payload,
                version=self.udp_rtmp_transport_version,
                frame_count=self.udp_rtmp_frame_count,
            )
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
        self._open_serial()
        if self._serial is not None:
            self._serial_rx_thread = threading.Thread(target=self._serial_rx_loop, daemon=True)
            self._serial_rx_thread.start()
        self._tx_thread = threading.Thread(target=self._tx_loop, daemon=True)
        self._tx_thread.start()
        # Some monitor-mode drivers intermittently emit truncated frames that close
        # the Scapy listen socket. Keep sniffing instead of exiting the process.
        while not self._stop.is_set():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._handle_packet,
                    store=0,
                    stop_filter=lambda _: self._stop.is_set(),
                )
            except Exception as exc:
                if self.verbose:
                    print(f"[TRX] Sniff socket error, restarting: {exc}")
                time.sleep(0.2)

    def stop(self) -> None:
        self._stop.set()
        if self._tx_thread is not None:
            self._tx_thread.join(timeout=2)
        if self._serial_rx_thread is not None:
            self._serial_rx_thread.join(timeout=1)
        if self._serial is not None:
            try:
                self._serial.close()
            except Exception:
                pass
            self._serial = None


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
    parser.add_argument(
        "--v2v-verify-pubkey-hex",
        default=DEFAULT_V2V_KEY_HEX,
        help="Ed25519 public key hex used to verify incoming signatures",
    )
    parser.add_argument(
        "--v2v-sign-privkey-hex",
        default=DEFAULT_V2V_SIGNING_KEY_HEX,
        help="Ed25519 private key hex used to sign outgoing responses",
    )
    parser.add_argument("--antenna-index", type=int, default=0)
    parser.add_argument("--rate-hz", type=float, default=DEFAULT_TX_RATE_HZ)
    parser.add_argument("--zmd-file", default="zmd/droid_zipping_point.zmd")
    parser.add_argument("--no-verify-signature", action="store_true")
    parser.add_argument("--complete-delay", type=float, default=2.0)
    parser.add_argument("--package-mass-kg", type=float, default=2.35)
    parser.add_argument("--wrap-vendor-ie", action="store_true")
    parser.add_argument("--no-vertical-comms-wrap", action="store_true")
    parser.add_argument("--no-udp-rtmp-wrap", action="store_true")
    parser.add_argument("--udp-rtmp-transport-version", type=int, default=0)
    parser.add_argument("--udp-rtmp-frame-count", type=int, default=0)
    parser.add_argument("--vc-src-ip", default=ZIP_IP_DEFAULT)
    parser.add_argument("--vc-dst-ip", default=DROID_IP_DEFAULT)
    parser.add_argument("--vc-src-port", type=int, default=ZIP_PORT_DEFAULT)
    parser.add_argument("--vc-dst-port", type=int, default=DROID_PORT_DEFAULT)
    parser.add_argument("--serial-port", default=None, help="Optional cycle_tester serial port, e.g. /dev/ttyACM0")
    parser.add_argument("--serial-baud", type=int, default=115200)
    parser.add_argument("--serial-timeout", type=float, default=0.2)
    parser.add_argument(
        "--serial-debug-mode",
        choices=["off", "mock"],
        default="off",
        help="Use 'mock' to test serial command mapping without Arduino hardware",
    )
    parser.add_argument(
        "--actuator-timeout",
        type=float,
        default=8.0,
        help="When serial bridge is enabled, send COMPLETED if TRX_COMPLETE is not seen before this timeout",
    )
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
        v2v_verify_pubkey_hex=args.v2v_verify_pubkey_hex,
        v2v_sign_privkey_hex=args.v2v_sign_privkey_hex,
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
        wrap_udp_rtmp=not args.no_udp_rtmp_wrap,
        udp_rtmp_transport_version=args.udp_rtmp_transport_version,
        udp_rtmp_frame_count=args.udp_rtmp_frame_count,
        vc_src_ip=args.vc_src_ip,
        vc_dst_ip=args.vc_dst_ip,
        vc_src_port=args.vc_src_port,
        vc_dst_port=args.vc_dst_port,
        serial_port=args.serial_port,
        serial_baud=args.serial_baud,
        serial_timeout=args.serial_timeout,
        serial_debug_mode=args.serial_debug_mode,
        actuator_timeout_s=args.actuator_timeout,
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
        if args.serial_debug_mode == "mock":
            print("[TRX] serial bridge debug mode: mock")
        elif args.serial_port:
            print(f"[TRX] serial bridge enabled: {args.serial_port} @ {args.serial_baud}")
            print(f"[TRX] actuator timeout: {args.actuator_timeout:.1f}s")

    try:
        trx.start()
    except KeyboardInterrupt:
        pass
    finally:
        trx.stop()


if __name__ == "__main__":
    main()
