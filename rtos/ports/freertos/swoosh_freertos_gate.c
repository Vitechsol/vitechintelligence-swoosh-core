/* SPDX-License-Identifier: MPL-2.0
 * Copyright 2026 ViTech Intelligence Solutions */
#include "swoosh_freertos_gate.h"
#if defined(configNUMBER_OF_CORES) && configNUMBER_OF_CORES != 1
#error "This reference adapter requires a single-core FreeRTOS port"
#endif

static SwooshGate gate PRIVILEGED_DATA;
static TaskHandle_t broker_task PRIVILEGED_DATA;
static bool configured PRIVILEGED_DATA;
static SwooshTickClock monotonic_clock PRIVILEGED_DATA;

static bool owner(void) {
    return configured && xTaskGetCurrentTaskHandle()==broker_task;
}
SwooshStatus swoosh_freertos_configure(TaskHandle_t broker,const uint8_t boot[32],
    uint64_t policy,uint64_t epoch,uint64_t max_ttl,SwooshTickClock clock) {
    if (configured || broker==NULL || clock==NULL || xTaskGetSchedulerState()!=taskSCHEDULER_NOT_STARTED) return SWOOSH_BAD_INPUT;
    SwooshStatus status=swoosh_gate_init(&gate,boot,policy,epoch,max_ttl,clock());
    if(status==SWOOSH_OK) {broker_task=broker;monotonic_clock=clock;configured=true;}
    return status;
}
SwooshStatus swoosh_freertos_resume(void) {
    if(!owner()) return SWOOSH_BAD_INPUT;
    taskENTER_CRITICAL();SwooshStatus status=swoosh_gate_resume_locked(&gate);taskEXIT_CRITICAL();return status;
}
SwooshStatus swoosh_freertos_halt(void) {
    if(!owner()) return SWOOSH_BAD_INPUT;
    taskENTER_CRITICAL();swoosh_gate_halt_locked(&gate);taskEXIT_CRITICAL();return SWOOSH_OK;
}
SwooshStatus swoosh_freertos_advance_epoch(uint64_t policy,uint64_t epoch) {
    if(!owner()) return SWOOSH_BAD_INPUT;
    taskENTER_CRITICAL();SwooshStatus status=swoosh_gate_advance_epoch_locked(&gate,policy,epoch);taskEXIT_CRITICAL();return status;
}
SwooshStatus swoosh_freertos_admit(const SwooshVerifiedAdmission *admission) {
    if(!owner()) return SWOOSH_BAD_INPUT;
    taskENTER_CRITICAL();
    SwooshStatus status=swoosh_gate_admit_verified_locked(&gate,admission,monotonic_clock());
    taskEXIT_CRITICAL();return status;
}
SwooshStatus swoosh_freertos_execute(const SwooshRequest *request,SwooshDispatch dispatch,void *context) {
    if(!owner()) return SWOOSH_BAD_INPUT;
    /* Driver admission and halt/epoch publication use the SAME serialization
     * boundary. A driver callback cannot block, allocate, yield, or do network I/O.
     * Hardware ISR shutdown uses an independent board safety interlock.
     */
    taskENTER_CRITICAL();
    SwooshStatus status=swoosh_gate_execute_locked(&gate,request,monotonic_clock(),dispatch,context);
    taskEXIT_CRITICAL();return status;
}
bool swoosh_freertos_take_event(SwooshGateEvent *event) {
    if(!owner()) return false;
    taskENTER_CRITICAL();bool available=swoosh_gate_take_event_locked(&gate,event);taskEXIT_CRITICAL();return available;
}
