/* SPDX-License-Identifier: MPL-2.0
 * Copyright 2026 ViTech Intelligence Solutions */
#ifndef SWOOSH_FREERTOS_GATE_H
#define SWOOSH_FREERTOS_GATE_H
#include "FreeRTOS.h"
#include "task.h"
#include "swoosh_gate.h"
typedef uint64_t (*SwooshTickClock)(void);
/* Trusted startup binds the broker task BEFORE scheduling. Protected SRAM and
 * an MPU-enabled port are mandatory when workers are outside the trusted base.
 * These declarations are privileged broker calls, not MPU wrapper syscalls.
 */
SwooshStatus swoosh_freertos_configure(TaskHandle_t broker, const uint8_t boot_nonce[32],
    uint64_t policy, uint64_t epoch, uint64_t max_ttl, SwooshTickClock clock) PRIVILEGED_FUNCTION;
SwooshStatus swoosh_freertos_resume(void) PRIVILEGED_FUNCTION;
SwooshStatus swoosh_freertos_halt(void) PRIVILEGED_FUNCTION;
SwooshStatus swoosh_freertos_advance_epoch(uint64_t policy, uint64_t epoch) PRIVILEGED_FUNCTION;
SwooshStatus swoosh_freertos_admit(const SwooshVerifiedAdmission *) PRIVILEGED_FUNCTION;
SwooshStatus swoosh_freertos_execute(const SwooshRequest *, SwooshDispatch, void *) PRIVILEGED_FUNCTION;
bool swoosh_freertos_take_event(SwooshGateEvent *) PRIVILEGED_FUNCTION;
#endif
