// M2 lid axis (module)

void configureMotor2() {
  pinMode(PIN_M2_R_EN, OUTPUT);
  pinMode(PIN_M2_L_EN, OUTPUT);
  digitalWrite(PIN_M2_R_EN, HIGH);
  digitalWrite(PIN_M2_L_EN, HIGH);

  pinMode(PIN_M2_RPWM, OUTPUT);
  pinMode(PIN_M2_LPWM, OUTPUT);
  pinMode(PIN_LID_LIMIT_SWITCH, INPUT_PULLUP);

  // PWM frequency tweak on Timer1
  TCCR1B = (TCCR1B & 0b11111000) | 0x01;

  pinMode(PIN_M2_ENCODER, INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(PIN_M2_ENCODER), m2EncoderISR, RISING);

  m2Stop();
}

void m2EncoderISR() {
  if (m2Direction > 0) m2EncoderPulses++;
  else if (m2Direction < 0) m2EncoderPulses--;
}

void m2Stop() {
  m2Direction = 0;
  analogWrite(PIN_M2_RPWM, 0);
  analogWrite(PIN_M2_LPWM, 0);
}

void m2ResetEncoder() {
  noInterrupts();
  m2EncoderPulses = 0;
  interrupts();
}

float m2GetVelocity() {
  long currentPos;
  noInterrupts(); currentPos = m2EncoderPulses; interrupts();
  bool opening = (m2TargetPulses > m2StartPulses);
  long pulsesMoved = abs(currentPos - m2StartPulses);
  if (opening) return (currentPos < M2_OPEN_SLOW_START) ? M2_VEL_OPEN_FAST : M2_VEL_OPEN_SLOW;
  else return (pulsesMoved < M2_CLOSE_SLOW_START) ? M2_VEL_CLOSE_FAST : M2_VEL_CLOSE_SLOW;
}

void m2UpdateSetpoint() {
  float dt = M2_SETPOINT_INTERVAL_US / 1e6f;
  float velocity = m2GetVelocity();
  float remaining = (float)m2TargetPulses - m2Setpoint;
  float direction = (remaining >= 0.0f) ? 1.0f : -1.0f;
  m2Setpoint += velocity * dt * direction;
  if ((direction > 0.0f && m2Setpoint > (float)m2TargetPulses) ||
      (direction < 0.0f && m2Setpoint < (float)m2TargetPulses)) {
    m2Setpoint = (float)m2TargetPulses;
  }
}

void m2ServicePID() {
  unsigned long nowMicros = micros();
  if ((nowMicros - m2LastSetpointMicros) >= M2_SETPOINT_INTERVAL_US) {
    m2LastSetpointMicros = nowMicros;
    m2UpdateSetpoint();
  }
  if ((nowMicros - m2LastPidMicros) < M2_PID_INTERVAL_US) return;
  double dt = (nowMicros - m2LastPidMicros) / 1e6;
  if (dt <= 0.0) dt = M2_PID_INTERVAL_US / 1e6;
  m2LastPidMicros = nowMicros;

  long currentPulses;
  noInterrupts(); currentPulses = m2EncoderPulses; interrupts();
  double error = (double)m2Setpoint - (double)currentPulses;
  long finalError = m2TargetPulses - currentPulses;

  if (abs(finalError) <= M2_ENCODER_TOLERANCE) {
    m2SetPWM(0);
  } else {
    m2Integral += error * dt;
    m2Integral = constrain(m2Integral, -M2_INTEGRAL_MAX, M2_INTEGRAL_MAX);
    double derivative = (error - m2PrevError) / dt;
    m2PrevError = error;
    double output = M2_KP * error + M2_KI * m2Integral + M2_KD * derivative;
    int pwm = constrain((int)output, -M2_PWM_MAX, M2_PWM_MAX);
    if (abs(error) > 1.0) {
      if (pwm > 0 && pwm < M2_PWM_MIN) pwm = M2_PWM_MIN;
      if (pwm < 0 && pwm > -M2_PWM_MIN) pwm = -M2_PWM_MIN;
    } else {
      pwm = 0;
    }
    m2SetPWM(pwm);
  }

  if ((nowMicros - m2MoveStartMicros) > 300000UL && abs(finalError) <= M2_ENCODER_TOLERANCE) {
    m2Stop();
    m2AutoMode = false;
    m2Integral = 0.0;
    m2PrevError = 0.0;
  }
}

void m2SetPWM(int pwm) {
  pwm = constrain(pwm, -255, 255);
  if (pwm > 0) {
    m2Direction = 1;
    analogWrite(PIN_M2_RPWM, 0);
    analogWrite(PIN_M2_LPWM, pwm);
  } else if (pwm < 0) {
    m2Direction = -1;
    analogWrite(PIN_M2_RPWM, -pwm);
    analogWrite(PIN_M2_LPWM, 0);
  } else {
    m2Direction = 0;
    analogWrite(PIN_M2_RPWM, 0);
    analogWrite(PIN_M2_LPWM, 0);
  }
}

void m2MoveToPulse(long targetPulse) {
  long currentPulse;
  noInterrupts(); currentPulse = m2EncoderPulses; interrupts();
  if (abs(targetPulse - currentPulse) <= M2_ENCODER_TOLERANCE) return;
  m2TargetPulses = targetPulse;
  m2StartPulses = currentPulse;
  m2Setpoint = (float)currentPulse;
  m2AutoMode = true;
  m2Integral = 0.0;
  m2PrevError = 0.0;
  m2LastPidMicros = micros();
  m2LastSetpointMicros = micros();
  m2MoveStartMicros = micros();
}

void m2OpenLid() {
  if (digitalRead(PIN_LID_LIMIT_SWITCH) == LOW) m2ResetEncoder();
  m2MoveToPulse(M2_OPEN_TARGET);
}

void m2CloseLid() {
  if (digitalRead(PIN_LID_LIMIT_SWITCH) == LOW) {
    m2ResetEncoder();
    return;
  }
  m2MoveToPulse(-200);
}

bool m2AtTarget() {
  if (!m2AutoMode) return true;
  long currentPulses;
  noInterrupts(); currentPulses = m2EncoderPulses; interrupts();
  return abs(m2TargetPulses - currentPulses) <= 3;
}


