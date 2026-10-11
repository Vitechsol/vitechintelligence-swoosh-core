/* SPDX-License-Identifier: MPL-2.0
 * Copyright 2026 ViTech Intelligence Solutions */
#include "swoosh_gate.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned effects;
static SwooshStatus driver(void *context,const SwooshRequest *request) {
    (void)request;++effects;return *(SwooshStatus *)context;
}
static SwooshVerifiedAdmission fixture(uint64_t generation) {
    SwooshVerifiedAdmission a;
    memset(&a,1,sizeof(a));a.scope.generation=generation;a.scope.policy_version=1;a.scope.trust_epoch=1;a.expires_tick=200;
    return a;
}
static void reset(SwooshGate *gate) {
    uint8_t boot[32];memset(boot,1,sizeof(boot));
    assert(swoosh_gate_init(gate,boot,1,1,200,100)==SWOOSH_OK);
    assert(!gate->running);assert(swoosh_gate_resume_locked(gate)==SWOOSH_OK);
}
int main(void) {
    SwooshGate gate;SwooshVerifiedAdmission a=fixture(1);SwooshStatus result=SWOOSH_OK;
    reset(&gate);assert(swoosh_gate_admit_verified_locked(&gate,&a,100)==SWOOSH_OK);
    assert(swoosh_gate_execute_locked(&gate,&a.scope,101,driver,&result)==SWOOSH_OK);
    assert(effects==1);assert(swoosh_gate_execute_locked(&gate,&a.scope,102,driver,&result)==SWOOSH_REPLAY);
    assert(swoosh_gate_admit_verified_locked(&gate,&a,102)==SWOOSH_REPLAY);
    SwooshGateEvent event;assert(swoosh_gate_take_event_locked(&gate,&event));assert(event.sequence==1 && event.outcome==SWOOSH_OK);
    assert(!swoosh_gate_take_event_locked(&gate,&event));
    /* Every fixed scope commitment rejects substitution before dispatch. */
    for (size_t field=0;field<6;++field) {
        reset(&gate);assert(swoosh_gate_admit_verified_locked(&gate,&a,100)==SWOOSH_OK);
        SwooshRequest request=a.scope;
        uint8_t *fields[]={request.boot_nonce,request.task_tag,request.subject,request.role_digest,request.action_digest,request.effect_digest};
        fields[field][0]^=1;
        assert(swoosh_gate_execute_locked(&gate,&request,101,driver,&result)!=SWOOSH_OK);
    }
    for (unsigned field=0;field<3;++field) {
        reset(&gate);assert(swoosh_gate_admit_verified_locked(&gate,&a,100)==SWOOSH_OK);
        SwooshRequest request=a.scope;
        if(field==0)++request.generation;else if(field==1)++request.policy_version;else ++request.trust_epoch;
        assert(swoosh_gate_execute_locked(&gate,&request,101,driver,&result)!=SWOOSH_OK);
    }
    reset(&gate);assert(swoosh_gate_admit_verified_locked(&gate,&a,100)==SWOOSH_OK);
    assert(swoosh_gate_execute_locked(&gate,&a.scope,200,driver,&result)==SWOOSH_EXPIRED);
    reset(&gate);assert(swoosh_gate_admit_verified_locked(&gate,&a,100)==SWOOSH_OK);
    swoosh_gate_halt_locked(&gate);assert(swoosh_gate_execute_locked(&gate,&a.scope,101,driver,&result)==SWOOSH_HALTED);
    assert(swoosh_gate_resume_locked(&gate)==SWOOSH_OK);assert(swoosh_gate_execute_locked(&gate,&a.scope,102,driver,&result)==SWOOSH_REPLAY);
    assert(swoosh_gate_admit_verified_locked(&gate,&a,102)==SWOOSH_REPLAY);
    reset(&gate);assert(swoosh_gate_admit_verified_locked(&gate,&a,100)==SWOOSH_OK);
    assert(swoosh_gate_advance_epoch_locked(&gate,2,2)==SWOOSH_OK);assert(!gate.running);
    assert(swoosh_gate_advance_epoch_locked(&gate,1,1)==SWOOSH_STALE_STATE);
    assert(swoosh_gate_resume_locked(&gate)==SWOOSH_OK);assert(swoosh_gate_execute_locked(&gate,&a.scope,101,driver,&result)==SWOOSH_STALE_STATE);
    reset(&gate);assert(swoosh_gate_admit_verified_locked(&gate,&a,100)==SWOOSH_OK);
    assert(swoosh_gate_revoke_task_locked(&gate,a.scope.task_tag,2)==SWOOSH_OK);
    assert(swoosh_gate_admit_verified_locked(&gate,&a,101)==SWOOSH_REPLAY);
    a.scope.generation=3;assert(swoosh_gate_admit_verified_locked(&gate,&a,101)==SWOOSH_OK);
    assert(swoosh_gate_execute_locked(&gate,&a.scope,99,driver,&result)==SWOOSH_CLOCK_ROLLBACK);assert(!gate.running);
    /* A failed/uncertain device response cannot cause implicit replay. */
    reset(&gate);assert(swoosh_gate_admit_verified_locked(&gate,&a,100)==SWOOSH_OK);
    result=SWOOSH_DRIVER_FAILED;assert(swoosh_gate_execute_locked(&gate,&a.scope,101,driver,&result)==SWOOSH_DRIVER_FAILED);
    assert(swoosh_gate_execute_locked(&gate,&a.scope,102,driver,&result)==SWOOSH_REPLAY);
    reset(&gate);assert(swoosh_gate_admit_verified_locked(&gate,&a,100)==SWOOSH_OK);
    result=SWOOSH_BAD_INPUT;assert(swoosh_gate_execute_locked(&gate,&a.scope,101,driver,&result)==SWOOSH_OUTCOME_UNKNOWN);
    assert(swoosh_gate_execute_locked(&gate,&a.scope,102,driver,&result)==SWOOSH_REPLAY);
    result=SWOOSH_OK;reset(&gate);
    for (uint64_t generation=1;generation<=SWOOSH_GATE_EVENTS;++generation) {
        a.scope.generation=generation;assert(swoosh_gate_admit_verified_locked(&gate,&a,100)==SWOOSH_OK);
        assert(swoosh_gate_execute_locked(&gate,&a.scope,100,driver,&result)==SWOOSH_OK);
    }
    unsigned before=effects;a.scope.generation=SWOOSH_GATE_EVENTS+1;
    assert(swoosh_gate_admit_verified_locked(&gate,&a,100)==SWOOSH_OK);
    assert(swoosh_gate_execute_locked(&gate,&a.scope,100,driver,&result)==SWOOSH_EVIDENCE_FULL);assert(effects==before && !gate.running);
    reset(&gate);
    for (size_t i=0;i<SWOOSH_GATE_TASKS;++i) {a.scope.task_tag[0]=(uint8_t)(i+1);assert(swoosh_gate_admit_verified_locked(&gate,&a,100)==SWOOSH_OK);}
    a.scope.task_tag[0]=99;assert(swoosh_gate_admit_verified_locked(&gate,&a,100)==SWOOSH_CAPACITY);
    reset(&gate);a=fixture(1);a.expires_tick=301;assert(swoosh_gate_admit_verified_locked(&gate,&a,100)==SWOOSH_BAD_INPUT);
    memset(a.scope.subject,0,32);assert(swoosh_gate_admit_verified_locked(&gate,&a,100)==SWOOSH_BAD_INPUT);
    assert(swoosh_gate_init(&gate,NULL,1,1,200,100)==SWOOSH_BAD_INPUT && !gate.running);
    puts("RTOS gate adversarial invariants: PASS");return 0;
}
