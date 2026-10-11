/* SPDX-License-Identifier: MPL-2.0
 * Copyright 2026 ViTech Intelligence Solutions */
#include "swoosh_gate.h"
#include <string.h>

static bool nonzero(const uint8_t value[32]) {
    uint8_t combined = 0;
    for (size_t i = 0; i < 32; ++i) combined |= value[i];
    return combined != 0;
}
static bool equal(const uint8_t a[32], const uint8_t b[32]) {
    return memcmp(a, b, 32) == 0;
}
static SwooshStatus tick(SwooshGate *gate, uint64_t now) {
    if (now < gate->last_tick) {
        swoosh_gate_halt_locked(gate);
        return SWOOSH_CLOCK_ROLLBACK;
    }
    gate->last_tick = now;
    return SWOOSH_OK;
}
static SwooshGateSlot *slot_for(SwooshGate *gate, const uint8_t task[32], bool create) {
    SwooshGateSlot *empty = NULL;
    for (size_t i = 0; i < SWOOSH_GATE_TASKS; ++i) {
        if (gate->slots[i].occupied && equal(gate->slots[i].admission.scope.task_tag, task)) return &gate->slots[i];
        if (!gate->slots[i].occupied && empty == NULL) empty = &gate->slots[i];
    }
    return create ? empty : NULL;
}
static bool valid_scope(const SwooshRequest *scope) {
    return scope->generation != 0 && scope->policy_version != 0 && scope->trust_epoch != 0
        && nonzero(scope->boot_nonce) && nonzero(scope->task_tag) && nonzero(scope->subject)
        && nonzero(scope->role_digest) && nonzero(scope->action_digest) && nonzero(scope->effect_digest);
}
static bool same_scope(const SwooshRequest *a, const SwooshRequest *b) {
    return equal(a->boot_nonce,b->boot_nonce) && equal(a->task_tag,b->task_tag)
        && equal(a->subject,b->subject) && equal(a->role_digest,b->role_digest)
        && equal(a->action_digest,b->action_digest) && equal(a->effect_digest,b->effect_digest)
        && a->generation == b->generation && a->policy_version == b->policy_version && a->trust_epoch == b->trust_epoch;
}
SwooshStatus swoosh_gate_init(SwooshGate *gate, const uint8_t boot[32],
    uint64_t policy, uint64_t epoch, uint64_t max_ttl, uint64_t now) {
    if (gate == NULL) return SWOOSH_BAD_INPUT;
    memset(gate,0,sizeof(*gate)); /* A failed initialization always leaves a halted gate. */
    if (boot == NULL || !nonzero(boot) || policy == 0 || epoch == 0 || max_ttl == 0) return SWOOSH_BAD_INPUT;
    memcpy(gate->boot_nonce,boot,32);
    gate->policy_version=policy;gate->trust_epoch=epoch;gate->max_ttl_ticks=max_ttl;gate->last_tick=now;
    return SWOOSH_OK;
}
void swoosh_gate_halt_locked(SwooshGate *gate) {
    if (gate == NULL) return;
    gate->running=false;
    for (size_t i=0;i<SWOOSH_GATE_TASKS;++i) gate->slots[i].usable=false;
}
SwooshStatus swoosh_gate_resume_locked(SwooshGate *gate) {
    if (gate == NULL || !nonzero(gate->boot_nonce) || gate->trust_epoch == 0 || gate->max_ttl_ticks == 0) return SWOOSH_BAD_INPUT;
    gate->running=true; /* Existing admissions remain invalidated after halt. */
    return SWOOSH_OK;
}
SwooshStatus swoosh_gate_advance_epoch_locked(SwooshGate *gate, uint64_t policy, uint64_t epoch) {
    if (gate == NULL) return SWOOSH_BAD_INPUT;
    if (epoch <= gate->trust_epoch || policy < gate->policy_version) return SWOOSH_STALE_STATE;
    swoosh_gate_halt_locked(gate);
    gate->policy_version=policy;gate->trust_epoch=epoch;
    return SWOOSH_OK;
}
SwooshStatus swoosh_gate_revoke_task_locked(SwooshGate *gate, const uint8_t task[32], uint64_t generation) {
    if (gate == NULL || task == NULL || !nonzero(task) || generation == 0) return SWOOSH_BAD_INPUT;
    SwooshGateSlot *slot=slot_for(gate,task,true);
    if (slot == NULL) return SWOOSH_CAPACITY;
    if (slot->occupied && generation <= slot->admission.scope.generation) return SWOOSH_STALE_STATE;
    memset(&slot->admission,0,sizeof(slot->admission));
    memcpy(slot->admission.scope.task_tag,task,32);
    slot->admission.scope.generation=generation;slot->occupied=true;slot->usable=false;
    return SWOOSH_OK;
}
SwooshStatus swoosh_gate_admit_verified_locked(SwooshGate *gate, const SwooshVerifiedAdmission *source, uint64_t now) {
    if (gate == NULL || source == NULL) return SWOOSH_BAD_INPUT;
    SwooshVerifiedAdmission admission=*source;
    SwooshStatus clock=tick(gate,now);
    if (clock != SWOOSH_OK) return clock;
    if (!gate->running) return SWOOSH_HALTED;
    if (!valid_scope(&admission.scope)) return SWOOSH_BAD_INPUT;
    if (!equal(admission.scope.boot_nonce,gate->boot_nonce)
        || admission.scope.policy_version != gate->policy_version || admission.scope.trust_epoch != gate->trust_epoch) return SWOOSH_STALE_STATE;
    if (admission.expires_tick <= now) return SWOOSH_EXPIRED;
    if (admission.expires_tick-now > gate->max_ttl_ticks) return SWOOSH_BAD_INPUT;
    SwooshGateSlot *slot=slot_for(gate,admission.scope.task_tag,true);
    if (slot == NULL) return SWOOSH_CAPACITY;
    if (slot->occupied && admission.scope.generation <= slot->admission.scope.generation) return SWOOSH_REPLAY;
    slot->admission=admission;slot->occupied=true;slot->usable=true;
    return SWOOSH_OK;
}
SwooshStatus swoosh_gate_execute_locked(SwooshGate *gate, const SwooshRequest *source, uint64_t now,
    SwooshDispatch dispatch, void *context) {
    if (gate == NULL || source == NULL || dispatch == NULL) return SWOOSH_BAD_INPUT;
    SwooshRequest request=*source;
    SwooshStatus clock=tick(gate,now);
    if (clock != SWOOSH_OK) return clock;
    if (!gate->running) return SWOOSH_HALTED;
    if (!valid_scope(&request)) return SWOOSH_BAD_INPUT;
    if (!equal(request.boot_nonce,gate->boot_nonce) || request.trust_epoch != gate->trust_epoch
        || request.policy_version != gate->policy_version) return SWOOSH_STALE_STATE;
    SwooshGateSlot *slot=slot_for(gate,request.task_tag,false);
    if (slot == NULL || !same_scope(&slot->admission.scope,&request)) return SWOOSH_SCOPE_MISMATCH;
    if (!slot->usable) return SWOOSH_REPLAY;
    if (now >= slot->admission.expires_tick) {slot->usable=false;return SWOOSH_EXPIRED;}
    if (gate->event_count >= SWOOSH_GATE_EVENTS || gate->event_sequence == UINT64_MAX) {
        swoosh_gate_halt_locked(gate);return SWOOSH_EVIDENCE_FULL;
    }
    /* Reserve bounded evidence and consume admission BEFORE calling the driver.
     * Caller retains the same protected lock through the driver admission point.
     * Restart/hardware durability needs the board's separately validated journal.
     */
    const size_t index=(gate->event_head+gate->event_count)%SWOOSH_GATE_EVENTS;
    SwooshGateEvent *event=&gate->events[index];
    memset(event,0,sizeof(*event));
    event->sequence=++gate->event_sequence;event->tick=now;event->generation=request.generation;event->trust_epoch=request.trust_epoch;
    memcpy(event->task_tag,request.task_tag,32);memcpy(event->action_digest,request.action_digest,32);
    event->outcome=SWOOSH_OUTCOME_UNKNOWN;++gate->event_count;slot->usable=false;
    SwooshStatus outcome=dispatch(context,&request);
    if (outcome != SWOOSH_OK && outcome != SWOOSH_DRIVER_FAILED) outcome=SWOOSH_OUTCOME_UNKNOWN;
    event->outcome=outcome;
    return outcome;
}
bool swoosh_gate_take_event_locked(SwooshGate *gate, SwooshGateEvent *event) {
    if (gate == NULL || event == NULL || gate->event_count == 0) return false;
    *event=gate->events[gate->event_head];
    gate->event_head=(gate->event_head+1)%SWOOSH_GATE_EVENTS;--gate->event_count;
    return true;
}
