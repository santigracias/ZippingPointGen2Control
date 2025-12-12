// Control loop + motor helpers (module)

// Set to false to suppress periodic debug telemetry (DBG/HOLD spam)
constexpr bool ENABLE_DEBUG_TELEMETRY = false;

void serviceAutoControl() {
  unsigned long nowMicros = micros();

  // Update motion profile setpoint (outer loop - 10ms cadence)
  if (motionProfileActive && (nowMicros - lastProfileUpdateMicros) >= PROFILE_UPDATE_INTERVAL_US) {
    lastProfileUpdateMicros = nowMicros;
    updateMotionProfile();
  }

  // Use profile setpoint if active, otherwise track final target directly
  float targetRev = motionProfileActive ? profileSetpointRev : profileTargetRev;
  long targetCounts = static_cast<long>(targetRev * ENCODER_CPR);

  // Enforce consistent timing for PID (inner loop - 1 kHz)
  if ((nowMicros - lastPidUpdateMicros) < PID_UPDATE_INTERVAL_US) {
    return;
  }
  double dt = (nowMicros - lastPidUpdateMicros) / 1e6;
  if (dt <= 0.0) dt = PID_UPDATE_INTERVAL_US / 1e6;
  lastPidUpdateMicros = nowMicros;

  long currentCounts;
  noInterrupts();
  currentCounts = encoderTicks;
  interrupts();

  long errorCounts = targetCounts - currentCounts;

  // Select PID gains based on mode
  double kp, ki, kd;
  if (positionHoldActive) {
    // Holding position - PID not used (direct proportional in hold logic below)
    kp = HOLD_KP;
    ki = 0.0;
    kd = 0.0;
  } else {
    // Moving - use direction-specific gains
    kp = movingUp ? MOTOR_KP_UP : MOTOR_KP_DOWN;
    ki = movingUp ? MOTOR_KI_UP : MOTOR_KI_DOWN;
    kd = movingUp ? MOTOR_KD_UP : MOTOR_KD_DOWN;
  }

  // PID calculations in counts domain
  motorIntegral += errorCounts * dt;
  motorIntegral = constrain(motorIntegral, -MOTOR_INTEGRAL_MAX, MOTOR_INTEGRAL_MAX);

  double derivative = (errorCounts - motorPrevError) / dt;
  motorPrevError = errorCounts;

  double output = kp * errorCounts + ki * motorIntegral + kd * derivative;

  // Clamp to motor limits
  int targetPWM = static_cast<int>(output);
  if (targetPWM > 0) {
    targetPWM = constrain(targetPWM, 0, MOTOR_PWM_MAX);
  } else {
    targetPWM = constrain(targetPWM, -255, 0);
  }

  // Apply PWM thresholds based on mode and error magnitude
  if (positionHoldActive) {
    // HOLD MODE with hysteresis to prevent twitching
    if (holdCorrecting) {
      if (abs(errorCounts) <= HOLD_ENTER_DEADBAND) {
        holdCorrecting = false;
        targetPWM = 0;
      } else {
        int holdPWM = static_cast<int>(HOLD_KP * abs(errorCounts));
        holdPWM = constrain(holdPWM, HOLD_PWM_MIN, HOLD_PWM_MAX);
        targetPWM = (errorCounts > 0) ? holdPWM : -holdPWM;
      }
    } else {
      if (abs(errorCounts) > HOLD_EXIT_DEADBAND) {
        holdCorrecting = true;
        int holdPWM = static_cast<int>(HOLD_KP * abs(errorCounts));
        holdPWM = constrain(holdPWM, HOLD_PWM_MIN, HOLD_PWM_MAX);
        targetPWM = (errorCounts > 0) ? holdPWM : -holdPWM;
      } else {
        targetPWM = 0;
      }
    }
  } else {
    // MOVING MODE
    if (abs(errorCounts) <= ENCODER_TOLERANCE) {
      targetPWM = 0;
    } else if (abs(errorCounts) <= HOLD_ZONE_COUNTS) {
      if (targetPWM > 0 && targetPWM < MOTOR_PWM_HOLD) targetPWM = MOTOR_PWM_HOLD;
      else if (targetPWM < 0 && targetPWM > -MOTOR_PWM_HOLD) targetPWM = -MOTOR_PWM_HOLD;
      if (abs(targetPWM) < MOTOR_PWM_DEADBAND) targetPWM = 0;
    } else {
      if (targetPWM > 0 && targetPWM < MOTOR_PWM_MIN) targetPWM = MOTOR_PWM_MIN;
      else if (targetPWM < 0 && targetPWM > -MOTOR_PWM_MIN) targetPWM = -MOTOR_PWM_MIN;
    }
  }

  setMotorPWM(targetPWM);

  // Completion check - switch to hold mode when target reached
  float currentRev = getCurrentRevolutions();

  // Check distance to FINAL target (not the moving setpoint!)
  long finalTargetCounts = static_cast<long>(profileTargetRev * ENCODER_CPR);
  long distToFinal = abs(finalTargetCounts - currentCounts);

  // Only check completion after 500ms and when very close to FINAL TARGET
  if ((nowMicros - moveStartTime) > 500000UL && distToFinal <= 3 && !positionHoldActive) {
    motionProfileActive = false;
    positionHoldActive = true;
    holdCorrecting = true;
    moveStartTime = 0;
    sendResponse("TARGET_REACHED:HOLDING");
  } else if (ENABLE_DEBUG_TELEMETRY && (nowMicros - lastAutoReportMicros) >= 250000UL) {
    // Optional telemetry every 250ms (DBG/HOLD spam)
    lastAutoReportMicros = nowMicros;
    if (positionHoldActive) {
      sendResponse("HOLD:" + String(currentRev, 2) + " err:" + String(errorCounts));
    } else {
      sendResponse("DBG:set=" + String(profileSetpointRev, 2) +
                   " pos=" + String(currentRev, 2) +
                   " vel=" + String(profileVelocityRev, 1) +
                   " pwm=" + String(targetPWM));
    }
  }
}

void setMotorTargetRev(float revs) {
  float currentRev = getCurrentRevolutions();
  if (abs(revs - currentRev) <= POSITION_TOLERANCE_REV) {
    sendResponse("OK:ALREADY_AT_TARGET");
    return;
  }

  // Exit hold mode if active
  positionHoldActive = false;

  // Set direction flag for PID gain selection
  movingUp = (revs > currentRev);

  // Initialize motion profile (if enabled)
  profileTargetRev = revs;
  profileSetpointRev = currentRev;
  profileVelocityRev = 0.0f;
  motionProfileActive = USE_MOTION_PROFILE;
  lastProfileUpdateMicros = micros();

  motorTargetCounts = static_cast<long>(revs * ENCODER_CPR);
  motorAutoMode = true;
  motorIntegral = 0.0;
  motorPrevError = 0.0;
  lastPidUpdateMicros = micros();
  lastAutoReportMicros = micros();
  moveStartTime = micros();

  // Keep OK:MOVING_* response (useful to know command parsed), but not periodic spam
  String dir = movingUp ? "UP" : "DOWN";
  String mode = USE_MOTION_PROFILE ? "RAMP" : "PID";
  sendResponse("OK:MOVING_" + dir + ":" + String(revs, 3) + ":" + mode);
}

void stopDcMotor() {
  analogWrite(PIN_RPWM, 0);
  analogWrite(PIN_LPWM, 0);
}

void setMotorPWM(int pwm) {
  pwm = constrain(pwm, -255, 255);

  if (pwm > 0) {
    analogWrite(PIN_RPWM, pwm);
    analogWrite(PIN_LPWM, 0);
  } else if (pwm < 0) {
    analogWrite(PIN_RPWM, 0);
    analogWrite(PIN_LPWM, -pwm);
  } else {
    analogWrite(PIN_RPWM, 0);
    analogWrite(PIN_LPWM, 0);
  }
}

float getCurrentRevolutions() {
  long ticks;
  noInterrupts();
  ticks = encoderTicks;
  interrupts();
  return static_cast<float>(ticks) / ENCODER_CPR;
}

void sendResponse(const String& msg) {
  Serial.println(msg);
}


