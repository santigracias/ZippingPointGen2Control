// M1 lift axis (module)

void configureMotor1() {
  pinMode(PIN_M1_R_EN, OUTPUT);
  pinMode(PIN_M1_L_EN, OUTPUT);
  digitalWrite(PIN_M1_R_EN, HIGH);
  digitalWrite(PIN_M1_L_EN, HIGH);

  pinMode(PIN_M1_RPWM, OUTPUT);
  pinMode(PIN_M1_LPWM, OUTPUT);
  pinMode(PIN_M1_LIMIT_RETRACT, INPUT_PULLUP);

  // PWM frequency tweak on Timer2 (Mega pins 9/10)
  TCCR2B = (TCCR2B & 0b11111000) | 0x01;

  m1Stop();
}

bool m1LimitTriggered() {
  bool rawState = digitalRead(PIN_M1_LIMIT_RETRACT);
  return M1_LIMIT_ACTIVE_LOW ? (rawState == LOW) : (rawState == HIGH);
}

void m1DriveForward(int speed) {
  speed = constrain(speed, 0, 255);
  m1Moving = true;
  analogWrite(PIN_M1_RPWM, speed);
  analogWrite(PIN_M1_LPWM, 0);
}

void m1DriveReverse(int speed) {
  speed = constrain(speed, 0, 255);
  m1Moving = true;
  analogWrite(PIN_M1_RPWM, 0);
  analogWrite(PIN_M1_LPWM, speed);
}

void m1Stop() {
  m1Moving = false;
  analogWrite(PIN_M1_RPWM, 0);
  analogWrite(PIN_M1_LPWM, 0);
}

void m1HoldPWM(int pwm) {
  m1Moving = false;
  pwm = constrain(pwm, -255, 255);
  if (pwm > 0) {
    analogWrite(PIN_M1_RPWM, pwm);
    analogWrite(PIN_M1_LPWM, 0);
  } else if (pwm < 0) {
    analogWrite(PIN_M1_RPWM, 0);
    analogWrite(PIN_M1_LPWM, -pwm);
  } else {
    analogWrite(PIN_M1_RPWM, 0);
    analogWrite(PIN_M1_LPWM, 0);
  }
}

bool m1StartExtend(long target) {
  if (m1CmdState != M1CommandState::IDLE) return false;
  m1CmdTarget = target;
  m1DonePending = true;
  m1CmdState = M1CommandState::EXTENDING;
  m1DriveForward(M1_EXTEND_SPEED);
  return true;
}

bool m1StartRetract() {
  if (m1CmdState != M1CommandState::IDLE) return false;
  m1DonePending = true;
  m1CmdState = M1CommandState::RETRACTING;

  if (m1LimitTriggered()) {
    // Already at home
    updateEncoderPosition();
    encZero = encRawCount;
    encPosition = 0;
    m1Stop();
    m1CmdState = M1CommandState::IDLE;
    if (m1DonePending) { m1DonePending = false; Serial.println(F("M1_DONE")); }
    return true;
  }

  m1DriveReverse(M1_RETRACT_SPEED);
  return true;
}

void m1Service() {
  if (m1CmdState == M1CommandState::IDLE) return;

  if (m1CmdState == M1CommandState::EXTENDING) {
    if (encPosition >= (m1CmdTarget - M1_POSITION_TOLERANCE)) {
      m1Stop();
      m1CmdState = M1CommandState::IDLE;
      if (m1DonePending) { m1DonePending = false; Serial.println(F("M1_DONE")); }
    }
    return;
  }

  if (m1CmdState == M1CommandState::RETRACTING) {
    if (m1LimitTriggered()) {
      m1Stop();
      delay(50);
      updateEncoderPosition();
      encZero = encRawCount;
      encPosition = 0;
      m1CmdState = M1CommandState::IDLE;
      if (m1DonePending) { m1DonePending = false; Serial.println(F("M1_DONE")); }
    }
    return;
  }
}


