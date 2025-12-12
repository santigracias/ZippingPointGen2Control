// USB command parsing (module)
// - Reads newline-terminated commands from USB Serial
// - Dispatches to axis/link functions (M1/M2/Nano/system)

void pollUsbSerial() {
  static char buf[64];
  static uint8_t idx = 0;

  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      buf[idx] = '\0';
      if (idx > 0) processUsbCommand(buf);
      idx = 0;
      continue;
    }
    if (idx < (sizeof(buf) - 1)) {
      buf[idx++] = c;
    } else {
      // overflow: drop line
      idx = 0;
    }
  }
}

static inline void strToLowerInPlace(char* s) {
  for (; *s; ++s) *s = (char)tolower((unsigned char)*s);
}

void processUsbCommand(char* cmd) {
  // Trim leading spaces
  while (*cmd == ' ' || *cmd == '\t') ++cmd;
  // Trim trailing spaces
  for (int i = (int)strlen(cmd) - 1; i >= 0; --i) {
    if (cmd[i] == ' ' || cmd[i] == '\t') cmd[i] = '\0';
    else break;
  }
  if (*cmd == '\0') return;

  strToLowerInPlace(cmd);

  if (strcmp(cmd, "stop") == 0 || strcmp(cmd, "s") == 0) {
    stopAll();
    Serial.println(F("*** EMERGENCY STOP ***"));
    return;
  }
  if (strcmp(cmd, "home") == 0) {
    if (homeIsActive()) {
      Serial.println(F("ERR:HOME_BUSY"));
      return;
    }
    homeAll();
    return;
  }
  if (strcmp(cmd, "status") == 0) { printStatus(); return; }
  if (strcmp(cmd, "zero") == 0) {
    if (zeroIsActive()) {
      Serial.println(F("ERR:ZERO_BUSY"));
      return;
    }
    Serial.println(F("Zeroing Nano..."));
    zeroStart();
    return;
  }

  // Direct control commands for automation
  if (strcmp(cmd, "open_lid") == 0) {
    m2OpenLid();
    if (m2AtTarget()) Serial.println(F("LID_OPEN"));
    else {
      lidOpening = true;
      lidClosing = false;
      Serial.println(F("Opening lid..."));
    }
    return;
  }
  if (strcmp(cmd, "close_lid") == 0) {
    if (digitalRead(PIN_LID_LIMIT_SWITCH) == LOW) Serial.println(F("LID_CLOSED"));
    else {
      m2CloseLid();
      lidClosing = true;
      lidOpening = false;
      Serial.println(F("Closing lid..."));
    }
    return;
  }

  if (strncmp(cmd, "nano_move:", 10) == 0) {
    float rev = (float)atof(cmd + 10);
    nanoMoveToRev(rev);
    Serial.print(F("Nano moving to ")); Serial.print(rev); Serial.println(F(" rev"));
    return;
  }
  if (strncmp(cmd, "nano_slow:", 10) == 0) {
    float rev = (float)atof(cmd + 10);
    nanoSlowMoveToRev(rev);
    Serial.print(F("Nano slow moving to ")); Serial.print(rev); Serial.println(F(" rev"));
    return;
  }

  if (strncmp(cmd, "m1_extend:", 10) == 0) {
    long target = atol(cmd + 10);
    if (!m1StartExtend(target)) {
      Serial.println(F("ERR:M1_BUSY"));
      return;
    }
    Serial.print(F("M1 extending to ")); Serial.println(target);
    return;
  }
  if (strcmp(cmd, "m1_retract") == 0) {
    if (!m1StartRetract()) {
      Serial.println(F("ERR:M1_BUSY"));
      return;
    }
    Serial.println(F("M1 retracting..."));
    return;
  }

  Serial.print(F("ERR:UNKNOWN_CMD:"));
  Serial.println(cmd);
}


