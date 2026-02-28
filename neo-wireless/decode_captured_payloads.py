#!/usr/bin/env python3
"""
Decode captured inner payload .bin files using a ZMD schema.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from protocol import ZmdCodec


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
    tag, off = _read_varint(data, 0)
    if tag != ((1 << 3) | 2):
        raise ValueError("not admin-wrapper field#1 bytes")
    ln, off = _read_varint(data, off)
    end = off + ln
    if end > len(data):
        raise ValueError("admin-wrapper payload truncated")
    return data[off:end]


def try_decode(codec: ZmdCodec, data: bytes):
    attempts = [
        ("cmd_payload", codec.decode_command_payload),
        ("resp_payload", codec.decode_response_payload),
    ]
    for label, fn in attempts:
        try:
            return label, fn(data)
        except Exception:
            pass
    try:
        name, msg = codec.decode(data)
        return f"wrapped:{name}", msg
    except Exception as exc:
        # Try admin-wrapper bytes field extraction as a final fallback.
        try:
            inner = _unwrap_admin_wrapper_payload(data)
            for label, fn in attempts:
                try:
                    return f"{label}:admin_unwrapped", fn(inner)
                except Exception:
                    pass
            name, msg = codec.decode(inner)
            return f"wrapped:{name}:admin_unwrapped", msg
        except Exception:
            return "fail", str(exc)


def main() -> None:
    parser = argparse.ArgumentParser(description="Decode captured bridge payload .bin files")
    parser.add_argument(
        "--capture-dir",
        default="/root/neo-wireless/captures_856753827",
        help="Directory containing .bin payload files",
    )
    parser.add_argument(
        "--zmd-file",
        default="/root/neo-wireless/zmd/droid_zipping_point.zmd",
        help="Path to .zmd file",
    )
    parser.add_argument("--limit", type=int, default=0, help="Max files to decode (0 = all)")
    args = parser.parse_args()

    cap_dir = Path(args.capture_dir)
    if not cap_dir.exists():
        raise SystemExit(f"capture dir not found: {cap_dir}")

    codec = ZmdCodec(args.zmd_file)
    files = sorted(cap_dir.glob("*.bin"))
    if args.limit > 0:
        files = files[: args.limit]

    print(f"[DECODE] zmd={args.zmd_file}")
    print(f"[DECODE] dir={cap_dir} files={len(files)}")

    ok = 0
    fail = 0
    for f in files:
        data = f.read_bytes()
        kind, out = try_decode(codec, data)
        if kind == "fail":
            fail += 1
            print(f"{f.name}: FAIL: {out}")
        else:
            ok += 1
            print(f"{f.name}: {kind}: {out}")

    print(f"[DECODE] done ok={ok} fail={fail}")


if __name__ == "__main__":
    main()
