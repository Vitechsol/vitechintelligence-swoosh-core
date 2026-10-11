/* SPDX-License-Identifier: MPL-2.0
 * Copyright 2026 ViTech Intelligence Solutions
 * Protected execution adapter. All *_locked calls require one broker-owned lock.
 * These functions are privileged host APIs, never worker syscalls or wire APIs.
 */
#ifndef SWOOSH_GATE_H
#define SWOOSH_GATE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SWOOSH_GATE_TASKS 16u
#define SWOOSH_GATE_EVENTS 32u
#define SWOOSH_DIGEST_BYTES 32u

typedef enum {
    SWOOSH_OK = 0, SWOOSH_BAD_INPUT, SWOOSH_HALTED, SWOOSH_STALE_STATE,
    SWOOSH_SCOPE_MISMATCH, SWOOSH_EXPIRED, SWOOSH_REPLAY,
    SWOOSH_CAPACITY, SWOOSH_EVIDENCE_FULL, SWOOSH_CLOCK_ROLLBACK,
    SWOOSH_DRIVER_FAILED, SWOOSH_OUTCOME_UNKNOWN
} SwooshStatus;

/* task_tag is a domain-separated digest of tenant, workflow and task.
 * action_digest is the canonical V3 receipt digest, binding the entire action.
 * subject/role are supplied by the protected identity adapter, not the worker.
 * effect_digest must describe the immutable command actually sent to the driver.
 */
typedef struct {
    uint8_t boot_nonce[32], task_tag[32], subject[32], role_digest[32];
    uint8_t action_digest[32], effect_digest[32];
    uint64_t generation, policy_version, trust_epoch;
} SwooshRequest;

typedef struct {
    SwooshRequest scope;
    uint64_t expires_tick;
} SwooshVerifiedAdmission;

typedef struct {
    bool occupied, usable;
    SwooshVerifiedAdmission admission;
} SwooshGateSlot;

typedef struct {
    uint64_t sequence, tick, generation, trust_epoch;
    uint8_t task_tag[32], action_digest[32];
    SwooshStatus outcome;
} SwooshGateEvent;

typedef struct {
    bool running;
    uint8_t boot_nonce[32];
    uint64_t policy_version, trust_epoch, max_ttl_ticks, last_tick, event_sequence;
    SwooshGateSlot slots[SWOOSH_GATE_TASKS];
    SwooshGateEvent events[SWOOSH_GATE_EVENTS];
    size_t event_head, event_count;
} SwooshGate;

/* Return OK only for a confirmed synchronous driver outcome. A lost or invalid
 * response is UNKNOWN. No return value ever makes the admission reusable.
 * The callback must be trusted, bounded, nonblocking and must not re-enter gate.
 */
typedef SwooshStatus (*SwooshDispatch)(void *, const SwooshRequest *);

SwooshStatus swoosh_gate_init(SwooshGate *, const uint8_t boot_nonce[32],
    uint64_t policy_version, uint64_t trust_epoch, uint64_t max_ttl_ticks, uint64_t now);
void swoosh_gate_halt_locked(SwooshGate *);
SwooshStatus swoosh_gate_resume_locked(SwooshGate *);
SwooshStatus swoosh_gate_advance_epoch_locked(SwooshGate *, uint64_t policy_version, uint64_t trust_epoch);
SwooshStatus swoosh_gate_revoke_task_locked(SwooshGate *, const uint8_t task_tag[32], uint64_t next_generation);
/* Admission follows canonical, pinned V3 ALLOW in the protected management path.
 * This API does not verify signatures. Never admit JSON, a model verdict, or an
 * unsigned receipt from another process/device without authenticated transport.
 */
SwooshStatus swoosh_gate_admit_verified_locked(SwooshGate *, const SwooshVerifiedAdmission *, uint64_t now);
SwooshStatus swoosh_gate_execute_locked(SwooshGate *, const SwooshRequest *, uint64_t now,
    SwooshDispatch, void *);
bool swoosh_gate_take_event_locked(SwooshGate *, SwooshGateEvent *);
#endif
