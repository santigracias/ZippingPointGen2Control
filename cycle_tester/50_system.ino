// System / orchestration helpers (module)

void homeAll() {
  // Non-blocking: just kick off the state machine.
  homeState = HomeState::START;
  homeStateStartMs = millis();
  Serial.println(F("Homing all axes..."));
}

bool homeIsActive() {
  return homeState != HomeState::IDLE && homeState != HomeState::DONE && homeState != HomeState::ABORTED;
}

bool zeroIsActive() {
  return zeroState != ZeroState::IDLE;
}

void zeroStart() {
  zeroState = ZeroState::STOP_SENT;
  zeroStateStartMs = millis();
}

void zeroService() {
  switch (zeroState) {
    case ZeroState::IDLE:
      return;
    case ZeroState::STOP_SENT:
      sendCommandToNano("STOP");
      zeroState = ZeroState::WAIT_100MS;
      zeroStateStartMs = millis();
      return;
    case ZeroState::WAIT_100MS:
      if ((millis() - zeroStateStartMs) >= 100) {
        sendCommandToNano("ZERO");
        zeroState = ZeroState::ZERO_SENT;
        zeroStateStartMs = millis();
      }
      return;
    case ZeroState::ZERO_SENT:
      // Give the slave a moment to apply zero; then report completion.
      if ((millis() - zeroStateStartMs) >= 50) {
        Serial.println(F("Nano zeroed"));
        zeroState = ZeroState::IDLE;
      }
      return;
  }
}

static inline void homeTransition(HomeState next) {
  homeState = next;
  homeStateStartMs = millis();
}

void homeService() {
  switch (homeState) {
    case HomeState::IDLE:
    case HomeState::DONE:
    case HomeState::ABORTED:
      return;

    case HomeState::START: {
      Serial.println(F("  Nano homing to limit switch..."));
      // Use a slow, controlled seek so we don't slam into the switch.
      // We command an intentionally "far" slow move in the home direction and then
      // stop/zero as soon as the Mega-mounted limit switch triggers.
      //
      // NOTE: This assumes negative revolutions move toward the home switch.
      // If your wiring is opposite, change the sign of NANO_HOME_SEEK_REV below.
      constexpr float NANO_HOME_SEEK_REV = -999.0f;
      nanoMoveStartMillis = millis();
      if (!nanoHomeSwitchTriggered()) {
        char cmd[48];
        char num[16];
        // Use the same float formatting as Nano link (3 decimals, no leading spaces)
        dtostrf(NANO_HOME_SEEK_REV, 0, 3, num);
        const char* p = num;
        while (*p == ' ') ++p;
        strcpy(cmd, "SLOW_MOVETO:");
        strncat(cmd, p, sizeof(cmd) - strlen(cmd) - 1);
        sendCommandToNano(cmd);
      } else {
        // Already on the switch; ensure we're stopped before zeroing.
        sendCommandToNano("STOP");
      }
      homeTransition(HomeState::NANO_HOME_RUN);
      return;
    }

    case HomeState::NANO_HOME_RUN: {
      // Drive until the Mega-mounted limit switch triggers (NO switch to GND => LOW when pressed)
      if (nanoHomeSwitchTriggered()) {
        homeTransition(HomeState::NANO_STOP_CMD);
        return;
      }
      if ((millis() - nanoMoveStartMillis) > NANO_MOVE_TIMEOUT_MS) {
        Serial.println(F("WARNING: Nano homing timeout; continuing"));
        homeTransition(HomeState::NANO_STOP_CMD);
      }
      return;
    }

    case HomeState::NANO_STOP_CMD: {
      sendCommandToNano("STOP");
      // Give the motor a moment to settle before zeroing
      homeTransition(HomeState::NANO_ZERO_CMD);
      return;
    }

    case HomeState::NANO_ZERO_CMD: {
      sendCommandToNano("ZERO");
      homeTransition(HomeState::NANO_ZERO_WAIT);
      return;
    }

    case HomeState::NANO_ZERO_WAIT: {
      // Give the Nano a moment to apply zero (avoids immediate subsequent motion using stale origin)
      if ((millis() - homeStateStartMs) >= 200) {
        Serial.println(F("  Nano homed"));
        homeTransition(HomeState::M1_RETRACT);
      }
      return;
    }

    case HomeState::M1_RETRACT: {
      Serial.println(F("  M1 retracting..."));
      // Retract using the existing non-blocking M1 state machine; don't print M1_DONE as part of homing
      m1DonePending = false;
      if (!m1StartRetract()) {
        // If M1 is busy with an external command, abort homing instead of fighting it
        Serial.println(F("ERR:HOME_M1_BUSY"));
        homeTransition(HomeState::ABORTED);
        return;
      }
      homeTransition(HomeState::M1_RETRACT_WAIT);
      return;
    }

    case HomeState::M1_RETRACT_WAIT: {
      // Completion is "at limit"
      if (m1LimitTriggered()) {
        // Update encoder zero once we're settled at the limit
        if ((millis() - homeStateStartMs) >= 50) {
          updateEncoderPosition();
          encZero = encRawCount;
          encPosition = 0;
          Serial.println(F("  M1 homed"));
          homeTransition(HomeState::LID_CLOSE);
        }
      } else {
        // refresh timer until we hit the switch
        homeStateStartMs = millis();
      }
      return;
    }

    case HomeState::LID_CLOSE: {
      Serial.println(F("  Closing lid..."));
      m2CloseLid();
      homeTransition(HomeState::LID_WAIT);
      return;
    }

    case HomeState::LID_WAIT: {
      if (digitalRead(PIN_LID_LIMIT_SWITCH) == LOW || m2AtTarget()) {
        m2Stop();
        m2AutoMode = false;
        if (digitalRead(PIN_LID_LIMIT_SWITCH) == LOW) m2ResetEncoder();
        Serial.println(F("  Lid homed"));
        Serial.println(F("All homed!"));
        homeTransition(HomeState::DONE);
      }
      return;
    }
  }
}

void stopAll() {
  m1Stop();
  m1CmdState = M1CommandState::IDLE;
  m1DonePending = false;
  m2Stop();
  m2AutoMode = false;
  sendCommandToNano("STOP");
  nanoMoving = false;
  zeroState = ZeroState::IDLE;
  if (homeIsActive()) {
    Serial.println(F("HOME_ABORTED"));
    homeState = HomeState::ABORTED;
  }
}

void printStatus() {
  Serial.println(F("\n--- STATUS ---"));
  Serial.println(F("Mode: COMMAND SERVER"));
  Serial.print(F("Homing: ")); Serial.println(homeIsActive() ? "YES" : "NO");
  Serial.print(F("Nano home sw: ")); Serial.println(nanoHomeSwitchTriggered() ? "TRIGGERED" : "open");
  Serial.print(F("M1 pos: ")); Serial.println(encPosition);
  Serial.print(F("M1 limit: ")); Serial.println(m1LimitTriggered() ? "TRIGGERED" : "clear");
  Serial.print(F("M2 pos: ")); Serial.println(m2EncoderPulses);
  Serial.print(F("Lid limit: ")); Serial.println(digitalRead(PIN_LID_LIMIT_SWITCH) == LOW ? "CLOSED" : "open");
  Serial.print(F("Nano moving: ")); Serial.println(nanoMoving ? "YES" : "NO");
  Serial.println(F("--------------\n"));
}

bool nanoHomeSwitchTriggered() {
  // Wired NO to GND with INPUT_PULLUP => pressed closes to GND => LOW
  return digitalRead(PIN_NANO_HOME_SWITCH) == LOW;
}


