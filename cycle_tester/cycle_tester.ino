// Cycle Tester - M1 (Lift), M2 (Lid), Nano (Vertical)
#include <Arduino.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

// PIN DEFINITIONS
constexpr uint8_t PIN_M1_RPWM = 9;
constexpr uint8_t PIN_M1_LPWM = 10;
constexpr uint8_t PIN_M1_R_EN = 7;
constexpr uint8_t PIN_M1_L_EN = 8;
constexpr uint8_t PIN_M1_LIMIT_RETRACT = 26;
constexpr uint8_t PIN_ENC_PWM = 3;
constexpr uint8_t PIN_M2_RPWM = 11;
constexpr uint8_t PIN_M2_LPWM = 12;
constexpr uint8_t PIN_M2_R_EN = 22;
constexpr uint8_t PIN_M2_L_EN = 23;
constexpr uint8_t PIN_M2_ENCODER = 2;
constexpr uint8_t PIN_LID_LIMIT_SWITCH = 24;
// Nano-axis home limit switch (wired to Mega, NO switch to GND)
constexpr uint8_t PIN_NANO_HOME_SWITCH = 27;

// M1 SETTINGS
constexpr int M1_EXTEND_SPEED = 200;
constexpr int M1_RETRACT_SPEED = 128;
constexpr long M1_POSITION_TOLERANCE = 50;
constexpr bool M1_INVERT_ENCODER = true;
constexpr bool M1_LIMIT_ACTIVE_LOW = false;
constexpr long AS5048_COUNTS_PER_REV = 16384;

volatile unsigned long encRiseTime = 0;
volatile unsigned long encFallTime = 0;
volatile unsigned long encPeriod = 0;
volatile unsigned long encHighTime = 0;
long encZero = 0;
long encRawCount = 0;
long encPosition = 0;
bool m1Moving = false;

// M1 COMMAND-SERVER STATE (non-blocking)
enum class M1CommandState : uint8_t { IDLE = 0, EXTENDING = 1, RETRACTING = 2 };
M1CommandState m1CmdState = M1CommandState::IDLE;
long m1CmdTarget = 0;
bool m1DonePending = false;

// M2 SETTINGS
constexpr double M2_KP = 4.0;
constexpr double M2_KI = 0.1;
constexpr double M2_KD = 0.0;
constexpr double M2_INTEGRAL_MAX = 80.0;
constexpr int M2_PWM_MAX = 255;
constexpr int M2_PWM_MIN = 100;
constexpr long M2_ENCODER_TOLERANCE = 0;
constexpr unsigned long M2_PID_INTERVAL_US = 2000;
constexpr float M2_VEL_OPEN_FAST = 55.0f;
constexpr float M2_VEL_OPEN_SLOW = 24.0f;
constexpr long M2_OPEN_SLOW_START = 30;
constexpr long M2_OPEN_TARGET = 65;
constexpr float M2_VEL_CLOSE_FAST = 80.0f;
constexpr float M2_VEL_CLOSE_SLOW = 25.0f;
constexpr long M2_CLOSE_SLOW_START = 8;
constexpr unsigned long M2_SETPOINT_INTERVAL_US = 10000;

volatile long m2EncoderPulses = 0;
volatile int8_t m2Direction = 0;
bool m2AutoMode = false;
long m2TargetPulses = 0;
long m2StartPulses = 0;
float m2Setpoint = 0.0f;
double m2Integral = 0.0;
double m2PrevError = 0.0;
unsigned long m2LastPidMicros = 0;
unsigned long m2LastSetpointMicros = 0;
unsigned long m2MoveStartMicros = 0;

// NANO STATE
bool nanoMoving = false;
bool nanoReady = false;
float nanoTargetRev = 0.0f;
unsigned long nanoMoveStartMillis = 0;
constexpr unsigned long NANO_MOVE_TIMEOUT_MS = 30000;

// Set to false to suppress printing Nano debug chatter (DBG/HOLD/PROGRESS/OK lines)
constexpr bool ENABLE_NANO_DEBUG_PASSTHROUGH = false;

// Homing state machine (non-blocking)
enum class HomeState : uint8_t {
  IDLE = 0,
  START,
  NANO_HOME_RUN,
  NANO_STOP_CMD,
  NANO_ZERO_CMD,
  NANO_ZERO_WAIT,
  M1_RETRACT,
  M1_RETRACT_WAIT,
  LID_CLOSE,
  LID_WAIT,
  DONE,
  ABORTED
};
HomeState homeState = HomeState::IDLE;
unsigned long homeStateStartMs = 0;

// Nano ZERO state machine (non-blocking)
enum class ZeroState : uint8_t { IDLE = 0, STOP_SENT, WAIT_100MS, ZERO_SENT };
ZeroState zeroState = ZeroState::IDLE;
unsigned long zeroStateStartMs = 0;

// CYCLE STATE
// This firmware operates as a command server (no internal cycle state machine).
// Higher-level sequencing is expected to be done by an external controller (e.g. Python).
bool lidOpening = false;  // Track lid movement for automation responses
bool lidClosing = false;

// FORWARD DECLARATIONS
// Implementations are split across multiple `.ino` modules in this folder:
// - `10_commands.ino` (USB parsing + dispatch)
// - `15_m1_encoder.ino` (AS5048 PWM decode)
// - `20_m1.ino` (lift axis state machine)
// - `30_m2.ino` (lid PID + encoder)
// - `40_nano_link.ino` (Serial1 protocol)
// - `50_system.ino` (home/stop/status)
void configureMotor1();
void configureMotor2();
void configureEncoder();
void encISR();
long pwmToCount(unsigned long highTime, unsigned long period);
void updateEncoderPosition();
inline void serviceBackground();
void pollUsbSerial();
void processUsbCommand(char* cmd);
void pollNanoSerial();
void processNanoLine(char* line);
bool m1StartExtend(long target);
bool m1StartRetract();
void m1Service();
bool m1LimitTriggered();
void m1Stop();
void m1HoldPWM(int pwm);
void m1DriveForward(int speed);
void m1DriveReverse(int speed);
void m2EncoderISR();
void m2ServicePID();
void m2UpdateSetpoint();
float m2GetVelocity();
void m2SetPWM(int pwm);
void m2Stop();
void m2ResetEncoder();
void m2OpenLid();
void m2CloseLid();
void m2MoveToPulse(long targetPulse);
bool m2AtTarget();
void sendCommandToNano(const char* cmd);
void handleNanoResponses();
bool nanoMoveToRev(float revs);
void nanoSlowMoveToRev(float revs);
bool waitForNano();
void homeAll();
void homeService();
bool homeIsActive();
bool nanoHomeSwitchTriggered();
void zeroStart();
void zeroService();
bool zeroIsActive();
void stopAll();
void printStatus();

// Common background servicing for blocking moves
inline void serviceBackground() {
  updateEncoderPosition();
  if (m2AutoMode) m2ServicePID();
  handleNanoResponses();
}

void setup() {
  Serial.begin(115200);
  Serial1.begin(115200);
  configureEncoder();
  configureMotor1();
  configureMotor2();
  pinMode(PIN_NANO_HOME_SWITCH, INPUT_PULLUP);
  
  Serial.println(F("=========================================="));
  Serial.println(F("       CYCLE TESTER - v2.0 (CMD SERVER)"));
  Serial.println(F("=========================================="));
  Serial.println(F("Commands: stop, home, status, zero"));
  Serial.println(F("          open_lid, close_lid"));
  Serial.println(F("          nano_move:X, nano_slow:X"));
  Serial.println(F("          m1_extend:X, m1_retract"));
  Serial.println(F("=========================================="));
  
  delay(100);
  updateEncoderPosition();
  
  Serial.println(F("Resetting Nano..."));
  sendCommandToNano("STOP");
  delay(200);
  
  Serial.println(F("Waiting for Nano..."));
  unsigned long waitStart = millis();
  while (!nanoReady && (millis() - waitStart) < 3000) {
    handleNanoResponses();
    delay(100);
  }
  nanoReady = true;
  Serial.println(F("Nano connected!"));
  
  Serial.println(F("Setting Nano home position..."));
  sendCommandToNano("ZERO");
  delay(200);
  Serial.println(F("Ready! Waiting for commands over USB serial."));
}

void loop() {
  updateEncoderPosition();
  if (m2AutoMode) m2ServicePID();
  handleNanoResponses();
  m1Service();
  homeService();
  zeroService();
  
  // Check for lid completion (for automation responses)
  if (lidOpening && m2AtTarget()) {
    lidOpening = false;
    Serial.println(F("LID_OPEN"));
  }
  if (lidClosing && (m2AtTarget() || digitalRead(PIN_LID_LIMIT_SWITCH) == LOW)) {
    lidClosing = false;
    m2Stop();
    m2AutoMode = false;
    if (digitalRead(PIN_LID_LIMIT_SWITCH) == LOW) m2ResetEncoder();
    Serial.println(F("LID_CLOSED"));
  }
  
  pollUsbSerial();
}
