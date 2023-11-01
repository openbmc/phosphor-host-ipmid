#pragma once

#include <stdint.h>

// These are per skiboot ipmi-sel code

// Minor command for soft shurdown
#define SOFT_OFF 0x00
// Major command for Any kind of power ops
#define CMD_POWER 0x04
// Major command for the heartbeat operation (verify host is alive)
#define CMD_HEARTBEAT 0xFF
