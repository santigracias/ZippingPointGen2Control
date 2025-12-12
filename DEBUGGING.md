# Debugging / Tuning Guide

This file is meant to help new users quickly diagnose common issues and find the right place in the codebase to make changes.

## Where to go (code map)

### Mega (`cycle_tester/`)
- **USB command parsing**: `cycle_tester/10_commands.ino`
- **M1 lift (state machine)**: `cycle_tester/20_m1.ino`
- **M1 encoder (AS5048 PWM)**: `cycle_tester/15_m1_encoder.ino`
- **M2 lid PID + encoder ISR**: `cycle_tester/30_m2.ino`
- **Nano link (Serial1 protocol)**: `cycle_tester/40_nano_link.ino`
- **Homing / stop / status / zero**: `cycle_tester/50_system.ino`

### Slave (`nano_slave_distributed/`)
- **Command parsing + top-level loop**: `nano_slave_distributed/nano_slave_distributed.ino`
- **PID + hold behavior**: `nano_slave_distributed/20_control.ino`
- **Motion profile**: `nano_slave_distributed/30_motion_profile.ino`
- **Encoder ISR + PWM setup**: `nano_slave_distributed/10_hw.ino`

### PC automation
- **Cycle steps**: `cycle_config.yaml`
- **Runner + serial wait logic**: `test_automation.py`

---

## Enabling / disabling debug output

### Mega: print Nano debug chatter
File: `cycle_tester/cycle_tester.ino`
- Set `ENABLE_NANO_DEBUG_PASSTHROUGH = true`
- You’ll see Nano lines (`DBG:`, `HOLD:`, `PROGRESS:`, `OK:`) prefixed by `Nano: ...`

### Slave: periodic telemetry (very spammy)
File: `nano_slave_distributed/20_control.ino`
- Set `ENABLE_DEBUG_TELEMETRY = true`
- Prints `DBG:` (during motion) / `HOLD:` (during hold) about every ~250ms
- Recommendation: enable only while tuning; disable for endurance tests

---

## Mega ↔ Slave (Nano/UNO) communication troubleshooting

The Mega talks to the slave over **UART** (`Serial1` at **115200**).

### 1) “Nothing moves / no NANO_DONE / Nano never READY”
Checklist:
- **Power**: slave board has power and is running firmware
- **Baud rate**: Mega uses `Serial1.begin(115200)`; slave uses `Serial.begin(115200)`
- **Common ground**: Mega GND and slave GND must be connected
- **TX/RX crossed**:
  - Mega **TX1** → slave **RX**
  - Mega **RX1** ← slave **TX**
- **Correct port**: ensure you are wiring to the Mega’s `Serial1` pins (not `Serial`/USB)
- **Only one “host” on the slave serial**:
  - If the slave is plugged into a PC via USB serial *and* connected to the Mega at the same time, you can get confusing behavior (two devices driving the same UART or consuming output).
  - Recommendation: during normal operation, **do not also have the slave USB serial connected to a PC** unless you intentionally know what you’re doing.

### 2) “It works sometimes” / flaky comms
Checklist:
- **Loose jumpers** on TX/RX/GND are the #1 cause
- Ensure no long unshielded wiring near motor leads (EMI)
- Add a small delay between high-rate debug prints (or disable telemetry) to avoid serial congestion

### 3) Verifying comms quickly
On Mega (USB serial), send:
- `nano_move:1`
Expected:
- Mega prints `NANO_DONE` when the slave reports completion (`TARGET_REACHED` or `OK:ALREADY`)

If you want to see slave details:
- enable `ENABLE_NANO_DEBUG_PASSTHROUGH` on Mega
- enable `ENABLE_DEBUG_TELEMETRY` on slave (temporarily)

---

## Common “jitter / whine” guidance (accuracy over cycles, low overshoot)

Some whine/jitter near setpoint is normal (static friction + backdrivable mechanics + discrete encoder counts).

If it becomes excessive:
- increase deadband (stop driving for very small errors)
- increase minimum effective PWM (don’t apply tiny PWM that can’t move the mechanism)
- use hold hysteresis (don’t correct until error is meaningfully large)
- reduce `KP`, add a bit more `KD`, keep `KI` small

### Nano axis note (belt + counterweight, backdrivable)
- Expect a bias to creep **upward** if unpowered (counterweight dominance).
- Quiet hold typically requires **hysteresis** (don’t chase tiny errors).

---

## M2 encoder “weirdness”
If the lid pulse encoder misses pulses or bounces:
- verify wiring and ground
- consider hardware filtering / Schmitt trigger if needed
- if you suspect bounce, consider adding a minimum pulse-interval filter in the ISR (advanced)


