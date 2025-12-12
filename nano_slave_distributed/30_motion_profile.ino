// Motion profile (module)

void updateMotionProfile() {
  float dt = PROFILE_UPDATE_INTERVAL_US / 1e6;  // 0.01 sec
  float remaining = profileTargetRev - profileSetpointRev;
  float direction = (remaining >= 0.0f) ? 1.0f : -1.0f;
  float distanceRemaining = abs(remaining);

  // Select profile based on direction (or slow mode)
  float maxVel, maxAcc, maxDec;
  if (slowMoveMode) {
    maxVel = PROFILE_VEL_SLOW;
    maxAcc = PROFILE_ACCEL_SLOW;
    maxDec = PROFILE_DECEL_SLOW;
  } else {
    maxVel = movingUp ? PROFILE_VEL_UP : PROFILE_VEL_DOWN;
    maxAcc = movingUp ? PROFILE_ACCEL_UP : PROFILE_ACCEL_DOWN;
    maxDec = movingUp ? PROFILE_DECEL_UP : PROFILE_DECEL_DOWN;
  }

  // If very close to target, just snap to it and stop
  if (distanceRemaining < PROFILE_TOLERANCE_REV) {
    profileSetpointRev = profileTargetRev;
    profileVelocityRev = 0.0f;
    motionProfileActive = false;
    return;
  }

  // Calculate braking distance needed at current velocity
  float brakingDistance = (abs(profileVelocityRev) * abs(profileVelocityRev)) / (2.0f * maxDec);

  // Small safety margin for braking calculation
  float safetyMargin = 0.05f;

  // Decide: accelerate, cruise, or brake
  if (distanceRemaining <= brakingDistance + safetyMargin) {
    // BRAKE
    float decelAmount = maxDec * dt;
    if (abs(profileVelocityRev) <= decelAmount) {
      profileVelocityRev = 0.0f;
    } else {
      if (profileVelocityRev > 0) profileVelocityRev -= decelAmount;
      else profileVelocityRev += decelAmount;
    }
  } else {
    // ACCELERATE / CRUISE
    if (abs(profileVelocityRev) < maxVel) {
      profileVelocityRev += direction * maxAcc * dt;
      if (abs(profileVelocityRev) > maxVel) profileVelocityRev = direction * maxVel;
    }
  }

  // Integrate velocity to get new setpoint position
  profileSetpointRev += profileVelocityRev * dt;

  // Clamp setpoint to not overshoot target
  if ((direction > 0.0f && profileSetpointRev >= profileTargetRev) ||
      (direction < 0.0f && profileSetpointRev <= profileTargetRev)) {
    profileSetpointRev = profileTargetRev;
    profileVelocityRev = 0.0f;
    motionProfileActive = false;
  }
}

void resetMotionProfile() {
  motionProfileActive = false;
  profileVelocityRev = 0.0f;
  profileSetpointRev = 0.0f;
  profileTargetRev = 0.0f;
}


