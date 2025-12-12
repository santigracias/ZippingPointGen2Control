# Test Automation Script
# Coordinates SSH commands, WiFi, motor-client2, EV2 doors, and Arduino cycle tester

import serial
import time
import subprocess
from pathlib import Path

try:
    import yaml
except Exception:
    yaml = None

# ============ CONFIGURATION ============
SSH_HOST = "p2-smart-cart-18"
SSH_USER = "zipline"

WIFI_SSID = "p2_droid_746_ch1"
WIFI_PASSWORD = "icecream"
WIFI_INTERFACE = "wlx9cefd5f61015"
DROID_IP = "192.168.66.1"

ARDUINO_PORT = "COM9"  # Adjust to your COM port
ARDUINO_BAUD = 115200

TMUX_SESSION = "motor_client"

# Manual mode - wait for user input between steps
MANUAL_MODE = False

# ============ GLOBAL STATE ============
arduino = None
motor_client_started = False

CONFIG_PATH = Path(__file__).with_name("cycle_config.yaml")
CONFIG = None

DEFAULT_CYCLE_STEPS = [
    {"type": "ev2", "name": "Cycle Init: Home EV2 doors", "action": "home_ev2_doors", "sleep_after": 2.5},
    {"type": "arduino", "name": "Step 1: Open lid", "cmd": "open_lid", "expect": "LID_OPEN", "timeout": 3},
    {"type": "sleep", "name": "Step 2: Pause 2 seconds", "seconds": 2},
    {"type": "arduino", "name": "Step 2b: Close lid", "cmd": "close_lid", "expect": "LID_CLOSED", "timeout": 3},
    {"type": "arduino", "name": "Step 3: Nano to 5 rev", "cmd": "nano_move:5", "expect": "NANO_DONE", "timeout": 30},
    {"type": "arduino", "name": "Step 4: Open lid (ensure)", "cmd": "open_lid", "expect": "LID_OPEN", "timeout": 3},
    {"type": "arduino", "name": "Step 6: Nano to 33 rev", "cmd": "nano_move:33", "expect": "NANO_DONE", "timeout": 30},
    {"type": "sleep", "name": "Step 7: Pause 2 seconds", "seconds": 2},
    {"type": "arduino", "name": "Step 8: Nano to 28 rev", "cmd": "nano_move:28", "expect": "NANO_DONE", "timeout": 30},
    {"type": "ev2", "name": "Step 9: Open EV2 doors (SSH)", "action": "open_ev2_doors"},
    {"type": "sleep", "name": "Step 10: Pause 2 seconds", "seconds": 2},
    {"type": "arduino", "name": "Step 11: Nano SLOW to 35.75 rev", "cmd": "nano_slow:36.00", "expect": "NANO_DONE", "timeout": 45},
    {"type": "arduino", "name": "Step 12: M1 extend to 4000", "cmd": "m1_extend:4000", "expect": "M1_DONE", "timeout": 60},
    {"type": "arduino", "name": "Step 13: Nano to 35 rev", "cmd": "nano_move:35.25", "expect": "NANO_DONE", "timeout": 30},
    {"type": "arduino", "name": "Step 14: M1 extend to 4400", "cmd": "m1_extend:4500", "expect": "M1_DONE", "timeout": 60},
    {"type": "ev2", "name": "Step 15: Home EV2 doors (SSH)", "action": "home_ev2_doors"},
    {"type": "sleep", "name": "Step 16: Wait 3s then retract M1", "seconds": 3},
    {"type": "arduino", "name": "Step 16b: M1 retract", "cmd": "m1_retract", "expect": "M1_DONE", "timeout": 60},
    {"type": "arduino", "name": "Step 17a: Nano to 4 rev", "cmd": "nano_move:4", "expect": "NANO_DONE", "timeout": 30},
    {"type": "arduino", "name": "Step 17b: Nano SLOW to 2 rev", "cmd": "nano_slow:2", "expect": "NANO_DONE", "timeout": 30},
    {"type": "arduino", "name": "Final: Close lid", "cmd": "close_lid", "expect": "LID_CLOSED", "timeout": 5},
]


def load_config():
    global CONFIG
    if CONFIG is not None:
        return CONFIG
    if yaml is None:
        print("[CONFIG] PyYAML not available; using built-in defaults")
        CONFIG = {"cycle": {"steps": DEFAULT_CYCLE_STEPS}}
        return CONFIG
    if not CONFIG_PATH.exists():
        print(f"[CONFIG] Missing {CONFIG_PATH.name}; using built-in defaults")
        CONFIG = {"cycle": {"steps": DEFAULT_CYCLE_STEPS}}
        return CONFIG
    try:
        data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
        steps = (data.get("cycle") or {}).get("steps")
        if not isinstance(steps, list) or not steps:
            raise ValueError("cycle.steps must be a non-empty list")
        CONFIG = data
        print(f"[CONFIG] Loaded {CONFIG_PATH.name} ({len(steps)} steps)")
        return CONFIG
    except Exception as e:
        print(f"[CONFIG] Failed to load {CONFIG_PATH.name}: {e}. Using built-in defaults")
        CONFIG = {"cycle": {"steps": DEFAULT_CYCLE_STEPS}}
        return CONFIG

# ============ MANUAL MODE HELPER ============
def wait_for_user(step_name):
    """In manual mode, wait for user to press Enter before proceeding"""
    if MANUAL_MODE:
        print(f"\n{'='*50}")
        print(f"  NEXT: {step_name}")
        print(f"{'='*50}")
        input("Press ENTER to execute (or Ctrl+C to abort)...")
        print()

# ============ SSH FUNCTIONS (Native SSH for Tailscale) ============
def native_ssh_run_full(cmd):
    """Run a command via native SSH and return CompletedProcess."""
    print(f"[SSH] Running: {cmd}")
    result = subprocess.run(
        ["ssh", f"{SSH_USER}@{SSH_HOST}", cmd],
        capture_output=True, text=True, encoding='utf-8', errors='replace'
    )
    if result.stdout:
        print(f"[SSH] Output: {result.stdout.strip()}")
    if result.stderr and "warning" not in result.stderr.lower():
        print(f"[SSH] Stderr: {result.stderr.strip()}")
    return result

def native_ssh_run(cmd):
    """Run a command via native SSH (compat wrapper)."""
    result = native_ssh_run_full(cmd)
    return result.stdout, result.stderr

def native_ssh_test():
    """Test if native SSH works"""
    print(f"\n[SSH] Testing connection to {SSH_USER}@{SSH_HOST}...")
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", f"{SSH_USER}@{SSH_HOST}", "echo OK"],
        capture_output=True, text=True, encoding='utf-8', errors='replace'
    )
    if "OK" in result.stdout:
        print("[SSH] Native SSH connection works!")
        return True
    print(f"[SSH] Native SSH failed: {result.stderr}")
    return False

def connect_wifi():
    """Connect to WiFi on remote device"""
    print(f"\n[WIFI] Connecting to {WIFI_SSID}...")
    cmd = f'sudo nmcli device wifi connect "{WIFI_SSID}" password "{WIFI_PASSWORD}" ifname {WIFI_INTERFACE}'
    output, errors = native_ssh_run(cmd)
    if "successfully" in output.lower() or "already" in output.lower():
        print("[WIFI] Connected!")
        return True
    return False

def ping_droid(count=3):
    """Ping the droid to verify connection"""
    print(f"\n[PING] Pinging {DROID_IP}...")
    output, _ = native_ssh_run(f"ping -c {count} -W 2 {DROID_IP}")
    success = f"{count} received" in output or f"{count} packets transmitted, {count} received" in output
    if success:
        print("[PING] Success!")
    else:
        print("[PING] Failed!")
    return success

# ============ MOTOR CLIENT FUNCTIONS (tmux) ============
def start_motor_client():
    """Start motor-client2 in a persistent tmux session"""
    global motor_client_started
    print("\n[MOTOR] Starting motor-client2 in persistent tmux session...")
    
    # Kill any existing session first
    native_ssh_run_full(f"tmux kill-session -t {TMUX_SESSION} 2>/dev/null || true")
    time.sleep(1)
    
    # Start motor-client2 in a detached tmux session
    start_cmd = f'tmux new-session -d -s {TMUX_SESSION} "source ~/firmware2-tools-venv/bin/activate && motor-client2 -p droid NAN --live-ipc-server-ip 192.168.66.1"'
    
    result = native_ssh_run_full(start_cmd)
    
    if result.returncode != 0:
        print(f"[MOTOR] Failed to start tmux session: {result.stderr}")
        return False
    
    # Wait for motor-client2 to initialize
    print("[MOTOR] Waiting for motor-client2 to initialize (5s)...")
    time.sleep(5)
    
    # Verify session is running
    check_result = native_ssh_run_full(f"tmux list-sessions 2>/dev/null | grep {TMUX_SESSION}")
    
    if TMUX_SESSION in check_result.stdout:
        motor_client_started = True
        print("[MOTOR] motor-client2 started!")
        return True
    else:
        print("[MOTOR] Failed to verify tmux session")
        return False

def motor_cmd(cmd):
    """Send command to motor-client2 running in tmux session"""
    if not motor_client_started:
        print("[ERROR] Motor client not started!")
        return ""
    
    print(f"[MOTOR] Sending: {cmd}")
    
    # Send command to tmux session using send-keys
    send_cmd = f"tmux send-keys -t {TMUX_SESSION} '{cmd}' Enter"
    
    result = native_ssh_run_full(send_cmd)
    
    if result.returncode != 0:
        print(f"[MOTOR] Failed to send command: {result.stderr}")
        return ""
    
    print("[MOTOR] Command sent!")
    return "OK"

def close_motor_client():
    """Close the motor-client2 tmux session"""
    global motor_client_started
    
    if motor_client_started:
        print("\n[MOTOR] Closing motor-client2 tmux session...")
        
        # Send exit() command first
        native_ssh_run_full(f"tmux send-keys -t {TMUX_SESSION} 'exit()' Enter")
        time.sleep(2)
        
        # Kill the tmux session
        native_ssh_run_full(f"tmux kill-session -t {TMUX_SESSION}")
        
    motor_client_started = False
    print("[MOTOR] Motor client closed")

def home_ev2_doors():
    """Home EV2 doors via motor-client2"""
    print("\n[EV2] Homing doors...")
    result = motor_cmd("home_ev2_doors()")
    print(f"[EV2] home_ev2_doors() sent, result: {result}")
    return result

def open_ev2_doors():
    """Open EV2 doors via motor-client2"""
    print("\n[EV2] Opening doors...")
    result = motor_cmd("open_ev2_doors()")
    print(f"[EV2] open_ev2_doors() sent, result: {result}")
    return result

# ============ ARDUINO FUNCTIONS ============
def arduino_connect():
    global arduino
    print(f"\n[ARDUINO] Connecting on {ARDUINO_PORT}...")
    arduino = serial.Serial(ARDUINO_PORT, ARDUINO_BAUD, timeout=1)
    time.sleep(2)
    
    # Flush startup messages
    while arduino.in_waiting:
        line = arduino.readline().decode().strip()
        if line:
            print(f"[ARDUINO] {line}")
    
    print("[ARDUINO] Connected!")
    return arduino

def arduino_send(cmd):
    """Send command to Arduino"""
    print(f"[ARDUINO] << Sending: '{cmd}'")
    arduino.write((cmd + '\n').encode())
    time.sleep(0.2)  # Give more time for immediate response
    
    # Read immediate responses
    responses = []
    while arduino.in_waiting:
        line = arduino.readline().decode().strip()
        if line:
            print(f"[ARDUINO] >> (immediate) {line}")
            responses.append(line)
    if not responses:
        print(f"[ARDUINO] >> (no immediate response)")
    return responses

def arduino_wait(keyword, timeout=60):
    """Wait for specific response from Arduino"""
    print(f"[ARDUINO] Waiting for '{keyword}' (timeout={timeout}s)...")
    start = time.time()
    all_received = []
    while time.time() - start < timeout:
        if arduino.in_waiting:
            line = arduino.readline().decode().strip()
            if line:
                elapsed = time.time() - start
                print(f"[ARDUINO] >> [{elapsed:.1f}s] {line}")
                all_received.append(line)
                if keyword in line:
                    print(f"[ARDUINO] Found '{keyword}'!")
                    return True
        time.sleep(0.05)
    print(f"[ARDUINO] Timeout! All received lines:")
    for i, line in enumerate(all_received):
        print(f"  {i+1}: {line}")
    print(f"[ARDUINO] Looking for: '{keyword}'")
    return False

def arduino_drain():
    """Read all pending Arduino output"""
    while arduino.in_waiting:
        line = arduino.readline().decode().strip()
        if line:
            print(f"[ARDUINO] >> {line}")

# ============ STEP HELPERS ============
def arduino_step(step_name, cmd, expect=None, timeout=60):
    wait_for_user(step_name)
    print(f"--- {step_name} ---")
    immediate = arduino_send(cmd)
    if expect:
        # arduino_send() drains any immediate output; handle the common case where
        # the completion token arrives immediately (e.g. M1 already at target).
        if any(expect in line for line in immediate):
            print(f"[ARDUINO] Found '{expect}' in immediate responses!")
            return True
        return arduino_wait(expect, timeout=timeout)
    return True

def ev2_step(step_name, fn, sleep_after=0.0):
    wait_for_user(step_name)
    print(f"--- {step_name} ---")
    fn()
    if sleep_after and sleep_after > 0:
        time.sleep(sleep_after)
    return True

def sleep_step(step_name, seconds):
    wait_for_user(step_name)
    print(f"--- {step_name} ---")
    time.sleep(seconds)
    return True

# ============ CYCLE SEQUENCE ============
def run_cycle(cycle_num=1):
    """Run one complete test cycle"""
    print(f"\n{'='*50}")
    print(f"           CYCLE {cycle_num} START")
    print(f"{'='*50}\n")

    cfg = load_config()
    steps = (cfg.get("cycle") or {}).get("steps", [])

    ev2_actions = {
        "home_ev2_doors": home_ev2_doors,
        "open_ev2_doors": open_ev2_doors,
    }

    for step in steps:
        step_type = (step.get("type") or "").strip().lower()
        name = step.get("name") or step_type or "step"

        if step_type == "sleep":
            seconds = float(step.get("seconds", 0))
            ok = sleep_step(name, seconds)
        elif step_type == "arduino":
            cmd = step.get("cmd")
            if not cmd:
                raise RuntimeError(f"Invalid arduino step (missing cmd): {step}")
            expect = step.get("expect")
            timeout = float(step.get("timeout", 60))
            ok = arduino_step(name, cmd, expect=expect, timeout=timeout)
        elif step_type == "ev2":
            action = step.get("action")
            fn = ev2_actions.get(action)
            if fn is None:
                raise RuntimeError(f"Unknown EV2 action '{action}' in step: {step}")
            sleep_after = float(step.get("sleep_after", 0.0))
            ok = ev2_step(name, fn, sleep_after=sleep_after)
        else:
            raise RuntimeError(f"Unknown step type '{step_type}' in step: {step}")

        if not ok:
            raise RuntimeError(f"Cycle step failed: {name}")
    
    print(f"\n{'='*50}")
    print(f"         CYCLE {cycle_num} COMPLETE")
    print(f"{'='*50}\n")

# ============ STARTUP SEQUENCE ============
def startup_sequence(sudo_password=None):
    """Initialize everything before cycling"""
    print("\n" + "="*50)
    print("         STARTUP SEQUENCE")
    print("="*50 + "\n")
    
    # 1. Test SSH connection
    if not native_ssh_test():
        print("[ERROR] SSH connection failed!")
        return False
    
    # 2. Connect to Arduino
    arduino_connect()
    
    # 3. Check/home Arduino
    print("\n[STARTUP] Checking Arduino positions...")
    arduino_send("status")
    time.sleep(0.5)
    arduino_drain()
    
    # Home if needed
    print("\n[STARTUP] Homing Arduino axes...")
    arduino_send("home")
    arduino_wait("All homed!", timeout=60)
    
    # 4. WiFi
    connect_wifi()
    time.sleep(2)
    
    # 5. Ping droid
    if not ping_droid():
        print("[ERROR] Cannot reach droid! Check WiFi connection.")
        return False
    
    # 6. Start motor-client2 (tmux session)
    if not start_motor_client():
        print("[ERROR] Failed to start motor-client2!")
        return False
    
    # 7. Home EV2 doors
    home_ev2_doors()
    time.sleep(2.5)
    
    print("\n[STARTUP] All systems ready!")
    return True

# ============ MAIN ============
def main():
    global arduino, motor_client_started, MANUAL_MODE
    
    print("\n" + "="*60)
    print("        AUTOMATED TEST SYSTEM")
    print("="*60)
    
    # Get sudo password if needed
    sudo_pass = input("\nEnter sudo password for remote device (Enter for none): ")
    sudo_pass = sudo_pass if sudo_pass else None
    
    # Manual mode?
    manual_input = input("Manual mode? (y/N - press Enter between steps): ").lower()
    MANUAL_MODE = manual_input in ['y', 'yes']
    if MANUAL_MODE:
        print("[MODE] Manual mode ENABLED - press Enter to advance each step")
    else:
        print("[MODE] Automatic mode - cycle will run continuously")
    
    try:
        # Initialize everything
        if not startup_sequence(sudo_pass):
            print("[ERROR] Startup failed!")
            return
        
        # Wait for user before starting first cycle
        print("\n" + "="*60)
        print("         STARTUP COMPLETE - READY TO RUN")
        print("="*60)
        input("\nPress ENTER to start cycle test (or Ctrl+C to quit)...")
        
        # Run cycles with option to continue
        cycle_num = 0
        while True:
            cycle_num += 1
            run_cycle(cycle_num)
            
            print("\n" + "="*60)
            print(f"         CYCLE {cycle_num} COMPLETE!")
            print("="*60)
            
            # Ask user what to do next
            print("\nOptions:")
            print("  [Enter] - Run another cycle")
            print("  [q]     - Quit")
            choice = input("\nChoice: ").strip().lower()
            
            if choice in ['q', 'quit', 'exit']:
                print("\n[INFO] Exiting...")
                break
            else:
                print("\n[INFO] Starting next cycle...")
        
    except KeyboardInterrupt:
        print("\n\n[INTERRUPT] Emergency stop!")
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup - always stop motors and disable PWM hold
        if arduino:
            try:
                print("[CLEANUP] Stopping motors and disabling PWM hold...")
                arduino_send("stop")
                time.sleep(0.2)
            except:
                pass
            arduino.close()
            print("[CLEANUP] Arduino disconnected")
        close_motor_client()

if __name__ == "__main__":
    main()
