// Nano link (Serial1) (module)

void sendCommandToNano(const char* cmd) { Serial1.println(cmd); }

static void formatFloat3(char* out, size_t outLen, float value) {
  // dtostrf pads with leading spaces; strip them.
  char tmp[16];
  dtostrf(value, 0, 3, tmp);
  const char* p = tmp;
  while (*p == ' ') ++p;
  strncpy(out, p, outLen);
  out[outLen - 1] = '\0';
}

bool nanoMoveToRev(float revs) {
  nanoTargetRev = revs;
  nanoMoving = true;
  nanoMoveStartMillis = millis();
  char num[16];
  formatFloat3(num, sizeof(num), revs);
  char cmd[32];
  strcpy(cmd, "MOVETO:");
  strncat(cmd, num, sizeof(cmd) - strlen(cmd) - 1);
  sendCommandToNano(cmd);
  return true;
}

void nanoSlowMoveToRev(float revs) {
  nanoTargetRev = revs;
  nanoMoving = true;
  nanoMoveStartMillis = millis();
  char num[16];
  formatFloat3(num, sizeof(num), revs);
  char cmd[40];
  strcpy(cmd, "SLOW_MOVETO:");
  strncat(cmd, num, sizeof(cmd) - strlen(cmd) - 1);
  sendCommandToNano(cmd);
  Serial.print(F("  Slow move to: "));
  Serial.println(revs, 2);
}

bool waitForNano() {
  if (!nanoMoving) return true;
  if ((millis() - nanoMoveStartMillis) > NANO_MOVE_TIMEOUT_MS) {
    Serial.println(F("WARNING: Nano timeout!"));
    nanoMoving = false;
    return true;
  }
  return false;
}

void processNanoLine(char* line) {
  // trim leading spaces
  while (*line == ' ' || *line == '\t') ++line;
  // trim trailing spaces
  for (int i = (int)strlen(line) - 1; i >= 0; --i) {
    if (line[i] == ' ' || line[i] == '\t') line[i] = '\0';
    else break;
  }
  if (*line == '\0') return;

  if (strncmp(line, "READY", 5) == 0) {
    nanoReady = true;
  } else if (strncmp(line, "TARGET_REACHED", 13) == 0 || strncmp(line, "OK:ALREADY", 9) == 0) {
    nanoMoving = false;
  } else if (strncmp(line, "STOPPED", 7) == 0) {
    nanoMoving = false;
  } else if (strncmp(line, "DBG:", 4) == 0 || strncmp(line, "HOLD:", 5) == 0 ||
             strncmp(line, "PROGRESS:", 9) == 0 || strncmp(line, "OK:", 3) == 0) {
    if (ENABLE_NANO_DEBUG_PASSTHROUGH) {
      Serial.print(F("Nano: "));
      Serial.println(line);
    }
  } else if (strncmp(line, "POS:", 4) == 0) {
    Serial.print(F("Nano Pos: "));
    Serial.print(line + 4);
    Serial.println(F(" rev"));
  }
}

void pollNanoSerial() {
  static char buf[96];
  static uint8_t idx = 0;

  while (Serial1.available()) {
    char c = (char)Serial1.read();
    if (c == '\r') continue;
    if (c == '\n') {
      buf[idx] = '\0';
      if (idx > 0) processNanoLine(buf);
      idx = 0;
      continue;
    }
    if (idx < (sizeof(buf) - 1)) {
      buf[idx++] = c;
    } else {
      idx = 0; // overflow: drop line
    }
  }
}

void handleNanoResponses() {
  static bool wasNanoMoving = false;
  pollNanoSerial();

  // Send NANO_DONE when movement completes
  if (wasNanoMoving && !nanoMoving) {
    Serial.println(F("NANO_DONE"));
  }
  wasNanoMoving = nanoMoving;
}


