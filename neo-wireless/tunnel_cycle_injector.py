#!/usr/bin/env python3
"""
Inject a full command cycle repeatedly for transceiver testing.

Cycle order:
  1) DESCEND
  2) HANDOFF
  3) DESCEND
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from typing import Any, Mapping

from scapy.all import Dot11, sniff

from protocol import ZmdCodec
from tunnel_sniffer import (
    DEFAULT_V2V_KEY_HEX,
    decode_payload,
    extract_tunnel_parse_result,
    parse_frame_injection_transport,
    parse_rtmp_frame,
    verify_signature,
)

ZIP_IP_DEFAULT = "192.168.77.1"
DROID_IP_DEFAULT = "192.168.77.2"
ZIP_PORT_DEFAULT = 50056
DROID_PORT_DEFAULT = 50055
ZIP_TO_DROID_BRIDGE_IDENTIFIER = "zipping_point.executive.response"

COMMAND_ENUM_MAP = {
    "DESCEND": "DESCEND_TO_DROID_CLEARANCE_HEIGHT",
    "HANDOFF": "HANDOFF_PACKAGE_TO_DROID",
}


def _run_injection(
    script_path: str,
    src_mac: str,
    dest_mac: str,
    session_id: int,
    command: str,
    mission_id: str,
    sequence_id: int,
    interface: str,
    count: int,
    rate_hz: float,
) -> None:
    cmd = [
        sys.executable,
        script_path,
        "--src-mac",
        src_mac,
        "--dest-mac",
        dest_mac,
        "--session-id",
        str(session_id),
        "--zmd-command",
        command,
        "--mission-id",
        mission_id,
        "--step-id",
        "1",
        "--task-id",
        "1",
        "--droid-step-id",
        "1",
        "--sequence-id",
        str(sequence_id),
        "--send",
        "--interface",
        interface,
        "--count",
        str(count),
        "--rate-hz",
        str(rate_hz),
    ]
    subprocess.run(cmd, check=True)


def _mission_id_bytes(decoded: Mapping[str, Any]) -> bytes:
    eid = decoded.get("command_id", {}).get("zip_executive_id", {})
    mid = eid.get("mission_id", b"")
    if isinstance(mid, str):
        return mid.encode("utf-8", errors="replace")
    return bytes(mid)


def _sequence_id(decoded: Mapping[str, Any]) -> int:
    eid = decoded.get("command_id", {}).get("zip_executive_id", {})
    return int(eid.get("sequence_id", -1))


def _wait_for_completed_response(
    *,
    interface: str,
    codec: ZmdCodec,
    zp_mac: str,
    session_id: int,
    mission_id: str,
    sequence_id: int,
    expected_command: str,
    timeout_s: float,
    verify_signature_enabled: bool,
    v2v_verify_pubkey_hex: str,
    verbose: bool,
) -> bool:
    deadline = time.time() + timeout_s
    expected_mission = mission_id.encode("utf-8", errors="replace")
    zp_mac = zp_mac.lower()

    while time.time() < deadline:
        packets = sniff(iface=interface, timeout=0.8, store=1)
        for pkt in packets:
            if not pkt.haslayer(Dot11):
                continue
            if (pkt.addr2 or "").lower() != zp_mac:
                continue
            try:
                parsed = extract_tunnel_parse_result(pkt)
                if verify_signature_enabled:
                    verify_signature(parsed.signature, parsed.signable, v2v_verify_pubkey_hex)
                rtmp = parse_rtmp_frame(parsed.tunnel_data)
                transport = parse_frame_injection_transport(rtmp["transport"])
                if int(transport["session_id"]) != session_id:
                    continue
                decoded = decode_payload(
                    rtmp["payload"],
                    codec,
                    "auto",
                    require_zipping_point_vertical=True,
                    vc_src_ip=ZIP_IP_DEFAULT,
                    vc_dst_ip=DROID_IP_DEFAULT,
                    vc_src_port=ZIP_PORT_DEFAULT,
                    vc_dst_port=DROID_PORT_DEFAULT,
                    bridge_identifier=ZIP_TO_DROID_BRIDGE_IDENTIFIER,
                )
            except Exception:
                continue
            if not decoded:
                continue
            if decoded.get("command") != expected_command:
                continue
            if decoded.get("command_response") == "IN_PROGRESS":
                if verbose:
                    print(f"[CYCLE] observed IN_PROGRESS for {expected_command} seq={sequence_id}")
                continue
            if decoded.get("command_response") != "COMPLETED":
                continue
            if _sequence_id(decoded) != sequence_id:
                continue
            if _mission_id_bytes(decoded) != expected_mission:
                continue
            if verbose:
                print(f"[CYCLE] observed COMPLETED for {expected_command} seq={sequence_id}")
            return True
    return False


def _learn_session_id_from_peer(
    *,
    interface: str,
    peer_mac: str,
    timeout_s: float,
    verify_signature_enabled: bool,
    v2v_verify_pubkey_hex: str,
    verbose: bool,
) -> int:
    deadline = time.time() + timeout_s
    peer_mac = peer_mac.lower()
    while time.time() < deadline:
        packets = sniff(iface=interface, timeout=0.8, store=1)
        for pkt in packets:
            if not pkt.haslayer(Dot11):
                continue
            if (pkt.addr2 or "").lower() != peer_mac:
                continue
            try:
                parsed = extract_tunnel_parse_result(pkt)
                if verify_signature_enabled:
                    verify_signature(parsed.signature, parsed.signable, v2v_verify_pubkey_hex)
                rtmp = parse_rtmp_frame(parsed.tunnel_data)
                transport = parse_frame_injection_transport(rtmp["transport"])
                learned = int(transport["session_id"])
                if verbose:
                    print(
                        f"[CYCLE] learned session_id={learned} "
                        f"from src={peer_mac} inj_counter={transport.get('injection_counter')}"
                    )
                return learned
            except Exception:
                continue
    raise TimeoutError(
        f"Timed out after {timeout_s}s waiting to learn session_id from {peer_mac}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Inject repeated DESCEND/HANDOFF/DESCEND cycles")
    parser.add_argument("--interface", default="wlan0")
    parser.add_argument("--src-mac", required=True, help="Injected source MAC (typically droid MAC)")
    parser.add_argument("--dest-mac", required=True, help="Injected destination MAC (typically ZP MAC)")
    parser.add_argument(
        "--session-id",
        default="1",
        help="Tunnel session id (integer) or 'auto' to learn from peer traffic first",
    )
    parser.add_argument("--loops", type=int, default=1, help="Number of full cycles to inject (0 = infinite)")
    parser.add_argument("--start-sequence-id", type=int, default=1000)
    parser.add_argument("--count-per-command", type=int, default=1)
    parser.add_argument("--rate-hz", type=float, default=10.0)
    parser.add_argument("--delay-between-commands", type=float, default=0.35)
    parser.add_argument("--delay-between-loops", type=float, default=1.0)
    parser.add_argument("--mission-prefix", default="TEST_CYCLE")
    parser.add_argument(
        "--confirm-each-loop",
        action="store_true",
        help="Prompt before starting each loop (press Enter to continue, q to quit)",
    )
    parser.add_argument("--wait-for-completed", action="store_true")
    parser.add_argument("--response-timeout", type=float, default=20.0)
    parser.add_argument("--learn-session-timeout", type=float, default=20.0)
    parser.add_argument("--no-verify-signature", action="store_true")
    parser.add_argument("--v2v-verify-pubkey-hex", default=DEFAULT_V2V_KEY_HEX)
    parser.add_argument("--zmd-file", default="/root/neo-wireless/zmd/droid_zipping_point.zmd")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--beacon-script",
        default="/root/neo-wireless/gen-v2v-beaconv2.py",
        help="Path to gen-v2v-beaconv2.py",
    )
    args = parser.parse_args()
    codec = ZmdCodec(args.zmd_file) if args.wait_for_completed else None

    if str(args.session_id).lower() == "auto":
        try:
            session_id = _learn_session_id_from_peer(
                interface=args.interface,
                peer_mac=args.src_mac,
                timeout_s=args.learn_session_timeout,
                verify_signature_enabled=not args.no_verify_signature,
                v2v_verify_pubkey_hex=args.v2v_verify_pubkey_hex,
                verbose=args.verbose,
            )
        except TimeoutError as exc:
            print(f"[CYCLE] {exc}", file=sys.stderr)
            return 3
    else:
        session_id = int(args.session_id)

    sequence_id = args.start_sequence_id
    loop_idx = 0
    commands = ("DESCEND", "HANDOFF", "DESCEND")

    try:
        while args.loops == 0 or loop_idx < args.loops:
            if args.confirm_each_loop:
                prompt = "[CYCLE] Press Enter to run next loop (or 'q' then Enter to quit): "
                answer = input(prompt).strip().lower()
                if answer in {"q", "quit", "x", "exit"}:
                    print("[CYCLE] stopped by user request")
                    break
            loop_idx += 1
            mission_id = f"{args.mission_prefix}_{loop_idx:06d}"
            print(f"[CYCLE] loop={loop_idx} mission_id={mission_id} start_seq={sequence_id}")

            for command in commands:
                print(f"[CYCLE] inject command={command} sequence_id={sequence_id}")
                _run_injection(
                    script_path=args.beacon_script,
                    src_mac=args.src_mac,
                    dest_mac=args.dest_mac,
                    session_id=session_id,
                    command=command,
                    mission_id=mission_id,
                    sequence_id=sequence_id,
                    interface=args.interface,
                    count=args.count_per_command,
                    rate_hz=args.rate_hz,
                )
                if args.wait_for_completed:
                    expected_command = COMMAND_ENUM_MAP[command]
                    ok = _wait_for_completed_response(
                        interface=args.interface,
                        codec=codec,
                        zp_mac=args.dest_mac,
                        session_id=session_id,
                        mission_id=mission_id,
                        sequence_id=sequence_id,
                        expected_command=expected_command,
                        timeout_s=args.response_timeout,
                        verify_signature_enabled=not args.no_verify_signature,
                        v2v_verify_pubkey_hex=args.v2v_verify_pubkey_hex,
                        verbose=args.verbose,
                    )
                    if not ok:
                        print(
                            f"[CYCLE] timeout waiting for COMPLETED {expected_command} seq={sequence_id}",
                            file=sys.stderr,
                        )
                        return 2
                sequence_id += 1
                time.sleep(args.delay_between_commands)

            print(f"[CYCLE] loop={loop_idx} done")
            if args.loops == 0 or loop_idx < args.loops:
                time.sleep(args.delay_between_loops)
    except KeyboardInterrupt:
        print("\n[CYCLE] stopped by user")
        return 130
    except subprocess.CalledProcessError as exc:
        print(f"[CYCLE] injection command failed (exit={exc.returncode})", file=sys.stderr)
        return exc.returncode

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
