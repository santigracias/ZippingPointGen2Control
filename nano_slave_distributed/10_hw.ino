// Hardware configuration + encoder ISR (module)

void configureBridgePwm() {
  pinMode(PIN_R_EN, OUTPUT);
  pinMode(PIN_L_EN, OUTPUT);
  digitalWrite(PIN_R_EN, HIGH);
  digitalWrite(PIN_L_EN, HIGH);

  pinMode(PIN_RPWM, OUTPUT);
  pinMode(PIN_LPWM, OUTPUT);

  // Set PWM frequency (~31 kHz) on UNO Timer1 (pins 9 & 10)
  // Configure Timer1 for 8-bit phase-correct PWM, prescaler = 1
  TCCR1A = (TCCR1A & 0b11111100) | 0x01; // WGM10 = 1 (8-bit), preserve COM bits
  TCCR1B = (TCCR1B & 0b11110111) | 0x01; // WGM12 = 0, CS10 = 1 (no prescale)

  analogWrite(PIN_RPWM, 0);
  analogWrite(PIN_LPWM, 0);
}

void configureEncoder() {
  pinMode(PIN_ENC_A, INPUT_PULLUP);
  pinMode(PIN_ENC_B, INPUT_PULLUP);

  uint8_t msb = digitalRead(PIN_ENC_A);
  uint8_t lsb = digitalRead(PIN_ENC_B);
  lastEncoderState = (msb << 1) | lsb;

  // Attach interrupts to BOTH encoder pins (requires pins 2 & 3 on UNO)
  attachInterrupt(digitalPinToInterrupt(PIN_ENC_A), encoderISR, CHANGE);
  attachInterrupt(digitalPinToInterrupt(PIN_ENC_B), encoderISR, CHANGE);
}

void encoderISR() {
  uint8_t msb = digitalRead(PIN_ENC_A);
  uint8_t lsb = digitalRead(PIN_ENC_B);
  uint8_t encoded = (msb << 1) | lsb;
  uint8_t combined = (lastEncoderState << 2) | encoded;

  switch (combined) {
    case 0b0001:
    case 0b0111:
    case 0b1110:
    case 0b1000:
      encoderTicks += ENCODER_REVERSED ? -1 : 1;
      break;
    case 0b0010:
    case 0b0100:
    case 0b1101:
    case 0b1011:
      encoderTicks += ENCODER_REVERSED ? 1 : -1;
      break;
    default:
      break;
  }

  lastEncoderState = encoded;
}


