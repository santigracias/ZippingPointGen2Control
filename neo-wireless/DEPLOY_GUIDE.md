# Neo Wireless Tunnel Deploy Guide

This guide is for deploying and running the Neo tunnel transceiver, plus optional sniffer/response-injector tools for debug.

## Access

- Neo SSH: `root@192.168.1.1`
- Password: `ZippingPoint`

From laptop:

```powershell
ssh root@192.168.1.1
```

## What to copy to Neo

Required runtime files/folders:

- `tunnel_transceiver.py`
- `tunnel_sniffer.py`
- `gen-v2v-beaconv2.py`
- `gen_v2v_autolearn_injector.py` (optional helper)
- `tunnel_cycle_injector.py` (optional helper)
- `handoff_protocol.py`
- `protocol.py`
- `config.py`
- `zmd/droid_zipping_point.zmd`
- `zmd_runtime/` (entire folder)

Copy from laptop (repo root):

```powershell
scp -O `
  neo-wireless/tunnel_transceiver.py `
  neo-wireless/tunnel_sniffer.py `
  neo-wireless/gen-v2v-beaconv2.py `
  neo-wireless/gen_v2v_autolearn_injector.py `
  neo-wireless/tunnel_cycle_injector.py `
  neo-wireless/handoff_protocol.py `
  neo-wireless/protocol.py `
  neo-wireless/config.py `
  root@192.168.1.1:/root/neo-wireless/

scp -O -r `
  neo-wireless/zmd `
  neo-wireless/zmd_runtime `
  root@192.168.1.1:/root/neo-wireless/
```

## Dependencies on Neo

Install once:

```sh
python3 -m pip install scapy cryptography pyserial
```

If using offline wheelhouse, install from local paths instead.

## Prepare monitor interface (channel 6)

On Neo:

```sh
wifi down
iw dev wlan0 del 2>/dev/null
iw dev phy2-sta0 del 2>/dev/null
iw phy phy2 interface add wlan0 type monitor
iw dev wlan0 set channel 6
ip link set wlan0 up
iw dev
```

Expected output includes:
- `Interface wlan0`
- `type monitor`
- `channel 6 (2437 MHz)`

## Run transceiver (main runtime)

This mode auto-learns session ID from the first valid droid frame and echoes it in responses.

```sh
cd /root/neo-wireless
python3 tunnel_transceiver.py wlan0 \
  --src-mac 11:22:33:44:55:66 \
  --dest-mac 00:91:9e:7e:b2:b5 \
  --self-mac 11:22:33:44:55:66 \
  --peer-mac 00:91:9e:7e:b2:b5 \
  --serial-port /dev/ttyACM1 \
  --verbose
```

Notes:
- `--src-mac` is Neo/ZP source MAC in transmitted beacons.
- `--dest-mac` is droid transport destination MAC.
- Omit `--session-id` to auto-learn from first RX frame.
- Add `--session-id <n>` if you need fixed session filtering.
- Check serial port first (ACM index can change): `ls /dev/ttyACM* /dev/ttyUSB*`
- With `--serial-port`, transceiver forwards received command stages to cycle tester:
  - `DESCEND_TO_DROID_CLEARANCE_HEIGHT` -> `trx_descend_to_droid_clearance_height`
  - `HANDOFF_PACKAGE_TO_DROID` -> `trx_handoff_package_to_droid`
  - second descend in the flow is still `trx_descend_to_droid_clearance_height`
- Terminal output includes serial bridge TX/RX lines prefixed with `[TRX] Serial TX` and `[TRX][SER]`.
- For comms-only testing without Arduino, use mock serial mode:
  - add `--serial-debug-mode mock`
  - transceiver prints mocked serial TX/RX events as `[TRX][SER-MOCK] ...`

## Optional: run sniffer (debug decode only)

In another terminal:

```sh
cd /root/neo-wireless
python3 tunnel_sniffer.py wlan0 --decode-zmd
```

Useful filters:

```sh
# only one source MAC
python3 tunnel_sniffer.py wlan0 --decode-zmd --peer-mac 00:91:9e:7e:b2:b5
```

## Optional: standalone response injector (debug TX)

Send one `COMPLETED` response frame:

```sh
cd /root/neo-wireless
python3 gen-v2v-beaconv2.py \
  --src-mac 11:22:33:44:55:66 \
  --dest-mac 00:91:9e:7e:b2:b5 \
  --session-id 1 \
  --zmd-response COMPLETED \
  --response-command DESCEND \
  --print-serialized-payload-hex \
  --send --interface wlan0 --count 1
```

Change `--zmd-response` to `IN_PROGRESS` if needed.

If you need a null/omitted tunnel session field for debug filtering, set:

```sh
--session-id none
```

Example:

```sh
python3 gen-v2v-beaconv2.py \
  --src-mac 11:22:33:44:55:66 \
  --dest-mac 00:91:9e:7e:b2:b5 \
  --session-id none \
  --zmd-response COMPLETED \
  --response-command DESCEND \
  --send --interface wlan0 --count 1
```

If you also want no tunnel sequence numbers, omit both sequence fields (or set to `none`):

```sh
--windowed-reliable-seqnum none
--besteffort-seqnum none
```

Example with null session and no sequence numbers:

```sh
python3 gen-v2v-beaconv2.py \
  --src-mac 11:22:33:44:55:66 \
  --dest-mac 00:91:9e:7e:b2:b5 \
  --session-id none \
  --windowed-reliable-seqnum none \
  --besteffort-seqnum none \
  --zmd-response COMPLETED \
  --response-command DESCEND \
  --send --interface wlan0 --count 1
```

## Optional: auto-learn + continuous injector

Learn session id from droid traffic, then start continuous injection:

```sh
cd /root/neo-wireless
python3 gen_v2v_autolearn_injector.py \
  --interface wlan0 \
  --learn-peer-mac 00:91:9e:7e:b2:b5 \
  --src-mac 11:22:33:44:55:66 \
  --dest-mac 00:91:9e:7e:b2:b5 \
  --zmd-response COMPLETED \
  --response-command DESCEND \
  --count 0
```

Notes:
- Default session-learn timeout is indefinite (`--timeout 0`).
- Add `--no-verify-signature` only for debugging noisy RF environments.

## Recommended test flow

1. Start `tunnel_transceiver.py` with `--verbose`.
2. Start `tunnel_sniffer.py --decode-zmd`.
3. Trigger droid command traffic.
4. Verify transceiver logs:
   - RX command decode
   - TX `IN_PROGRESS`
   - TX `COMPLETED`

## Troubleshooting

- `Interface 'wlan0' not found`:
  - Re-run monitor setup commands.
- `signature verify failed`:
  - Ensure sender and receiver use same V2V key.
- No RX logs:
  - Confirm channel is 6 and peer MAC is correct.
- ZMD file error:
  - Ensure `/root/neo-wireless/zmd/droid_zipping_point.zmd` exists.

## Known-good commands (current lab MACs)

Current MACs:
- Zipping Point (Neo): `78:b8:0f:fa:03:0f`
- Droid: `f0:d4:15:38:2f:f7`

Transceiver:

```sh
cd /root/neo-wireless
python3 tunnel_transceiver.py wlan0 \
  --src-mac 78:b8:0f:fa:03:0f \
  --dest-mac f0:d4:15:38:2f:f7 \
  --self-mac 78:b8:0f:fa:03:0f \
  --peer-mac f0:d4:15:38:2f:f7 \
  --serial-port /dev/ttyACM1 \
  --verbose
```

Sniffer:

```sh
cd /root/neo-wireless
python3 tunnel_sniffer.py wlan0 --decode-zmd --peer-mac f0:d4:15:38:2f:f7 --verbose
```

Auto-learn continuous injector (waits indefinitely for session id, then injects):

```sh
cd /root/neo-wireless
python3 gen_v2v_autolearn_injector.py \
  --interface wlan0 \
  --learn-peer-mac f0:d4:15:38:2f:f7 \
  --src-mac 78:b8:0f:fa:03:0f \
  --dest-mac f0:d4:15:38:2f:f7 \
  --zmd-response COMPLETED \
  --response-command DESCEND \
  --count 0
```
