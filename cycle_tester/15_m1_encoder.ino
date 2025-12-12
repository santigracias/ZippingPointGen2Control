// M1 encoder (AS5048 PWM) (module)

void encISR() {
  unsigned long now = micros();
  if (digitalRead(PIN_ENC_PWM) == HIGH) {
    if (encFallTime > 0) encPeriod = now - encRiseTime;
    encRiseTime = now;
  } else {
    encHighTime = now - encRiseTime;
    encFallTime = now;
  }
}

long pwmToCount(unsigned long highTime, unsigned long period) {
  if (period == 0 || period < 500) return 0;
  unsigned long dutyPerMille = (highTime * 1000UL) / period;
  if (dutyPerMille < 125) dutyPerMille = 125;
  if (dutyPerMille > 875) dutyPerMille = 875;
  return ((long)(dutyPerMille - 125) * AS5048_COUNTS_PER_REV) / 750;
}

void updateEncoderPosition() {
  noInterrupts();
  unsigned long h = encHighTime;
  unsigned long p = encPeriod;
  interrupts();
  encRawCount = pwmToCount(h, p);
  encPosition = encRawCount - encZero;
  if (encPosition > 8192) encPosition -= 16384;
  if (encPosition < -8192) encPosition += 16384;
  if (M1_INVERT_ENCODER) encPosition = -encPosition;
}

void configureEncoder() {
  pinMode(PIN_ENC_PWM, INPUT);
  attachInterrupt(digitalPinToInterrupt(PIN_ENC_PWM), encISR, CHANGE);
}


