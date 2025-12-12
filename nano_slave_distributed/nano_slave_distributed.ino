/*
  UNO_Slave_Distributed - DC Motor Controller (SIMPLIFIED PID)
  
  Simplified high-frequency PID only - no motion profile for testing.
  
  Hardware (Arduino UNO slave):
    Motor Driver (BTS7960):
      RPWM -> D9
      LPWM -> D10
      R_EN -> D7
      L_EN -> D8
    
    Encoder (CHANCS 16 PPR AB quadrature):
      A -> D2 (INT0 - interrupt pin)
      B -> D3 (INT1 - interrupt pin)
      VCC -> D5 (powered from digital pin)
      GND -> GND (shared with driver)
  
  Commands from Mega:
    "FORWARD"     - Run motor forward (manual)
    "REVERSE"     - Run motor reverse (manual)
    "STOP"        - Stop motor
    "MOVETO:x"    - Auto-move to position (revolutions)
    "GET_POS"     - Report current position
    "ZERO"        - Reset encoder to zero
  
  Responses to Mega:
    "POS:x"           - Current position
    "TARGET_REACHED"  - Auto-move complete
    "PROGRESS:x/y"    - Progress during auto-move
    "STOPPED"         - Motor stopped
    "OK"              - Command acknowledged
    "READY"           - Initialization complete
*/

#include <Arduino.h>

// -----------------------------------------------------------------------------
// MOTOR DRIVER PINS
// -----------------------------------------------------------------------------
constexpr uint8_t PIN_RPWM = 9;
constexpr uint8_t PIN_LPWM = 10;
constexpr uint8_t PIN_R_EN = 7;
constexpr uint8_t PIN_L_EN = 8;

// -----------------------------------------------------------------------------
// ENCODER PINS (MUST BE INTERRUPT PINS ON UNO!)
// -----------------------------------------------------------------------------
constexpr uint8_t PIN_ENC_A = 2;     // INT0
constexpr uint8_t PIN_ENC_B = 3;     // INT1
constexpr uint8_t PIN_ENC_PWR = 5;   // Power encoder from this pin

// -----------------------------------------------------------------------------
// ENCODER SETTINGS
// -----------------------------------------------------------------------------
constexpr int ENCODER_PPR = 16;                 // pulses per revolution
constexpr int ENCODER_CPR = ENCODER_PPR * 4;    // counts per revolution (quadrature)
constexpr bool ENCODER_REVERSED = false;
constexpr long ENCODER_TOLERANCE = 3;           // allowable error in counts

volatile long encoderTicks = 0;
volatile uint8_t lastEncoderState = 0;

// -----------------------------------------------------------------------------
// PID CONTROL PARAMETERS - SEPARATE UP/DOWN TUNING
// -----------------------------------------------------------------------------
// UP = moving to higher rev values (against gravity)
constexpr double  MOTOR_KP_UP = 2;          // Aggressive - need power to go up
constexpr double  MOTOR_KI_UP = 0.0;          // Small integral to push through
constexpr double  MOTOR_KD_UP = 0.0;          // Small damping

// DOWN = moving to lower rev values (with gravity)
constexpr double  MOTOR_KP_DOWN = 4.0;        // Increased - more force to reach target
constexpr double  MOTOR_KI_DOWN = 0.2;        // Pushes through to target
constexpr double  MOTOR_KD_DOWN = 0.05;

constexpr double  MOTOR_INTEGRAL_MAX = 100.0; // Limit integral windup
constexpr int     MOTOR_PWM_MAX = 255;
constexpr int     MOTOR_PWM_MIN = 150;        // Higher minimum PWM to overcome friction
constexpr int     MOTOR_PWM_HOLD = 90;        // Increased - more force near target
constexpr int     MOTOR_PWM_DEADBAND = 20;    // Stop whining at low output
constexpr long    HOLD_ZONE_COUNTS = 3;       // Smaller zone - keep driving longer
constexpr unsigned long PID_UPDATE_INTERVAL_US = 1000; // 1 kHz

// -----------------------------------------------------------------------------
// MOTION PROFILE PARAMETERS (SEPARATE UP/DOWN)
// -----------------------------------------------------------------------------
// Set to false to disable ramp and let PID control speed directly
constexpr bool USE_MOTION_PROFILE = true;

// UPWARD motion profile (against gravity)
constexpr float PROFILE_VEL_UP = 15.0f;         // Slower max speed so PID can track
constexpr float PROFILE_ACCEL_UP = 25.0f;       // Acceleration up
constexpr float PROFILE_DECEL_UP = 100.0f;      // Strong braking to prevent overshoot

// DOWNWARD motion profile (with gravity - needs different tuning)
constexpr float PROFILE_VEL_DOWN = 15.0f;       // Max speed down (rev/s)
constexpr float PROFILE_ACCEL_DOWN = 40.0f;     // Acceleration down
constexpr float PROFILE_DECEL_DOWN = 40.0f;    // Strong braking

// SLOW MOTION PROFILE (for soft moves - same for both directions)
constexpr float PROFILE_VEL_SLOW = 5.0f;        // Slow max speed (rev/s) - not too slow to avoid whine
constexpr float PROFILE_ACCEL_SLOW = 15.0f;     // Gentle acceleration
constexpr float PROFILE_DECEL_SLOW = 20.0f;     // Gentle braking

constexpr float PROFILE_TOLERANCE_REV = 0.1f;   // Position tolerance in revolutions
constexpr unsigned long PROFILE_UPDATE_INTERVAL_US = 10000; // Update every 10ms

// -----------------------------------------------------------------------------
// MOTOR CONTROL STATE
// -----------------------------------------------------------------------------
bool motorAutoMode = false;
bool motionProfileActive = false;
bool positionHoldActive = false;        // Keep PID running to hold position
bool holdCorrecting = false;            // Hysteresis state: true = actively correcting, false = holding still
bool slowMoveMode = false;              // Use slow velocity profile for soft moves
float profileTargetRev = 0.0f;          // Final target position
float profileSetpointRev = 0.0f;        // Current moving setpoint for PID to track
float profileVelocityRev = 0.0f;        // Current velocity (rev/s)
unsigned long lastProfileUpdateMicros = 0;
bool movingUp = true;                   // Direction flag for PID gain selection

long motorTargetCounts = 0;
double motorIntegral = 0.0;
double motorPrevError = 0.0;
unsigned long lastPidUpdateMicros = 0;
unsigned long lastAutoReportMicros = 0;
unsigned long moveStartTime = 0;  // Track when move started for completion check
constexpr float POSITION_TOLERANCE_REV = 0.02f; // Very tight tolerance

// Position hold mode constants
// Position hold mode with hysteresis to prevent twitching
constexpr int HOLD_PWM_MIN = 120;          // Minimum PWM to overcome friction (reduced to avoid overshoot)
constexpr int HOLD_PWM_MAX = 220;          // Maximum PWM for large errors (reduced)
constexpr double HOLD_KP = 6.0;            // Proportional gain (reduced for less aggressive)
constexpr long HOLD_ENTER_DEADBAND = 2;    // Stop correcting when error <= 2 counts
constexpr long HOLD_EXIT_DEADBAND = 6;     // Start correcting when error > 6 counts (wider band)

constexpr uint8_t MANUAL_DUTY = 255;

// -----------------------------------------------------------------------------
// FORWARD DECLARATIONS
// -----------------------------------------------------------------------------
void configureBridgePwm();
void configureEncoder();
void encoderISR();
void stopDcMotor();
void setMotorTargetRev(float revs);
void setMotorPWM(int pwm);
void serviceAutoControl();
void sendResponse(const String& msg);
float getCurrentRevolutions();
void updateMotionProfile();
void resetMotionProfile();

// -----------------------------------------------------------------------------
// SETUP
// -----------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  
  // Wait for serial to stabilize
  delay(1000);
  
  // Power encoder from pin 5 (5V pin used by motor driver)
  pinMode(PIN_ENC_PWR, OUTPUT);
  digitalWrite(PIN_ENC_PWR, HIGH);
  delay(100); // Give encoder time to power up
  
  configureBridgePwm();
  configureEncoder();
  
  // Tell master we're ready (send twice to be sure)
  sendResponse("READY");
  delay(100);
  sendResponse("READY");
}

// -----------------------------------------------------------------------------
// LOOP
// -----------------------------------------------------------------------------
void loop() {
  // Handle commands from Mega
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    cmd.toUpperCase();
    
    if (cmd == "FORWARD") {
      motorAutoMode = false;
      positionHoldActive = false;
      resetMotionProfile();
      setMotorPWM(MANUAL_DUTY);
      sendResponse("RUN_FORWARD");
      
    } else if (cmd == "REVERSE") {
      motorAutoMode = false;
      positionHoldActive = false;
      resetMotionProfile();
      setMotorPWM(-128);  // Limit manual reverse to 50% duty cycle
      sendResponse("RUN_REVERSE");
      
    } else if (cmd == "STOP") {
      motorAutoMode = false;
      positionHoldActive = false;
      resetMotionProfile();
      setMotorPWM(0);
      motorIntegral = 0.0;
      motorPrevError = 0.0;
      sendResponse("STOPPED");
      
    } else if (cmd.startsWith("MOVETO:")) {
      float revs = cmd.substring(7).toFloat();
      slowMoveMode = false;  // Normal speed
      setMotorTargetRev(revs);
      
    } else if (cmd.startsWith("SLOW_MOVETO:")) {
      float revs = cmd.substring(12).toFloat();
      slowMoveMode = true;   // Slow speed for soft moves
      setMotorTargetRev(revs);
      
    } else if (cmd == "GET_POS") {
      float revs = getCurrentRevolutions();
      sendResponse("POS:" + String(revs, 3));
      
    } else if (cmd == "ZERO") {
      noInterrupts();
      encoderTicks = 0;
      interrupts();
      motorAutoMode = false;
      positionHoldActive = false;
      resetMotionProfile();
      motorTargetCounts = 0;
      motorIntegral = 0.0;
      motorPrevError = 0.0;
      stopDcMotor();
      sendResponse("OK");
    }
  }
  
  // Service auto-control if moving OR holding position
  if (motorAutoMode || positionHoldActive) {
    serviceAutoControl();
  }
}

