# ZippingPointGen2Control

This repo contains:
- **Arduino Mega** firmware (`cycle_tester/`) acting as a **command server** for:
  - M1 (lift axis, AS5048 PWM encoder)
  - M2 (lid axis, encoder + PID)
  - Serial link to the Nano/UNO slave (“vertical”)
- **Arduino UNO/Nano slave** firmware (`nano_slave_distributed/`) acting as a **motor controller** for the vertical axis
- **PC-side automation** (`test_automation.py`) that sequences the test using a YAML config (`cycle_config.yaml`)

## Quick start

### 1) Python setup (Windows)

Create + activate a venv, then install deps:

```powershell
pip install -r requirements.txt
```

Run the automation:

```powershell
python .\test_automation.py
```

Cycle definition is in `cycle_config.yaml`.

### 2) Arduino uploads

- **Upload to Mega**: open `cycle_tester/cycle_tester.ino` and upload to the Mega.
- **Upload to UNO/Nano slave**: open `nano_slave_distributed/nano_slave_distributed.ino` and upload to the slave board.

## Arduino sketch structure )

### `cycle_tester/` (Mega) tabs
- `cycle_tester.ino`: globals + `setup()`/`loop()`
- `10_commands.ino`: USB serial parsing + command dispatch
- `15_m1_encoder.ino`: AS5048 PWM decode for M1
- `20_m1.ino`: M1 motor + non-blocking state machine
- `30_m2.ino`: M2 PID + encoder ISR
- `40_nano_link.ino`: Serial1 protocol to slave
- `50_system.ino`: homing/stop/status


### `nano_slave_distributed/` (UNO/Nano slave) tabs
- `nano_slave_distributed.ino`: constants/state + `setup()`/`loop()` + command parsing
- `10_hw.ino`: PWM setup + encoder ISR
- `20_control.ino`: PID control loop + motor helpers (debug telemetry off by default)
- `30_motion_profile.ino`: motion profiling helpers

## Command protocol (Mega over USB)

### Commands
- `stop` (or `s`): stop all motion immediately
- `home`: home Nano, M1, and lid
- `status`: print current state
- `zero`: issue `STOP` then `ZERO` to the slave
- `open_lid` / `close_lid`
- `nano_move:<rev>` / `nano_slow:<rev>`
- `m1_extend:<counts>` / `m1_retract`

### Common outputs (tokens)
- `LID_OPEN`, `LID_CLOSED`
- `NANO_DONE`
- `M1_DONE`
- `HOME_ABORTED`
- `ERR:*` (e.g. `ERR:M1_BUSY`, `ERR:HOME_BUSY`, `ERR:UNKNOWN_CMD:<cmd>`)

## Wiring: Nano-axis home limit switch (Mega input)

The Nano-axis home limit switch is **wired to the Mega** (not to the slave).

- **Mega pin**: **D27** (`PIN_NANO_HOME_SWITCH = 27`)
- **Switch type**: **NO (Normally Open)**
- **Wiring**:
  - One switch terminal -> **Mega D27**
  - Other switch terminal -> **Mega GND**
- **Electrical**:
  - Configured as `INPUT_PULLUP`, so the pin reads:
    - **HIGH** when not pressed (open circuit)
    - **LOW** when pressed (switch closes to GND)

### Nano homing speed
- The Mega homes the Nano axis using a **slow seek move** (`SLOW_MOVETO:<far>`) in the home direction and then sends `STOP` + `ZERO` as soon as the switch triggers.
- If it moves the wrong direction during homing, flip the sign of `NANO_HOME_SEEK_REV` in `cycle_tester/50_system.ino`.

## Driod commands

### Manually drive/home motors
- `ssh zipline@p2-smart-cart-18` connect to smart cart
- `sudo nmcli device wifi connect "p2_droid_746_ch1" password "icecream" ifname wlx9cefd5f61015`  conect to droid brain wifi
- `ping 192.168.66.1` verify connection
- `motor-client2 -p droid NAN --live-ipc-server-ip 192.168.66.1` start motor client
- `home_ev2_doors()` close/home doors
- `open_ev2_doors()` open doors

### Turn off droid
- From the smart cart `ssh 192.168.66.1`
- `droid-battery-cli -i fe80::62%enP8p1s0 power-off` turn off battery

