/* SPDX-License-Identifier: MPL-2.0
 * Synthetic admissions in real FreeRTOS POSIX tasks. This test does not assert MPU isolation or WCET. */
#include "swoosh_freertos_gate.h"
#include "queue.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static QueueHandle_t requests;
static SwooshVerifiedAdmission admission;
static unsigned effects;
static bool finished;
static uint64_t clock_ticks(void) {
    _Static_assert(sizeof(TickType_t)>=sizeof(uint64_t),"POSIX test uses a 64-bit tick counter");
    return (uint64_t)xTaskGetTickCount();
}
static SwooshStatus driver(void *context,const SwooshRequest *request) {
    (void)context;(void)request;++effects;return SWOOSH_OK;
}
static void worker(void *context) {
    (void)context;
    /* Worker cannot operate the privileged broker API, even in this trusted
     * POSIX demo. Hardware isolation itself requires a real MPU-enabled port. */
    assert(swoosh_freertos_resume()==SWOOSH_BAD_INPUT);
    assert(swoosh_freertos_halt()==SWOOSH_BAD_INPUT);
    assert(swoosh_freertos_admit(&admission)==SWOOSH_BAD_INPUT);
    assert(swoosh_freertos_execute(&admission.scope,driver,NULL)==SWOOSH_BAD_INPUT);
    for(unsigned i=0;i<3;++i) assert(xQueueSend(requests,&admission.scope,portMAX_DELAY)==pdPASS);
    vTaskSuspend(NULL);
}
static void broker(void *context) {
    (void)context;
    assert(swoosh_freertos_resume()==SWOOSH_OK);
    admission.expires_tick=(uint64_t)xTaskGetTickCount()+10000;
    assert(swoosh_freertos_admit(&admission)==SWOOSH_OK);
    SwooshRequest request;
    assert(xQueueReceive(requests,&request,portMAX_DELAY)==pdPASS);
    assert(swoosh_freertos_execute(&request,driver,NULL)==SWOOSH_OK);
    assert(xQueueReceive(requests,&request,portMAX_DELAY)==pdPASS);
    assert(swoosh_freertos_execute(&request,driver,NULL)==SWOOSH_REPLAY);
    assert(swoosh_freertos_halt()==SWOOSH_OK);
    assert(xQueueReceive(requests,&request,portMAX_DELAY)==pdPASS);
    assert(swoosh_freertos_execute(&request,driver,NULL)==SWOOSH_HALTED);
    assert(effects==1);
    SwooshGateEvent event;assert(swoosh_freertos_take_event(&event));
    assert(event.outcome==SWOOSH_OK && event.sequence==1);
    assert(swoosh_freertos_resume()==SWOOSH_OK);
    assert(swoosh_freertos_execute(&request,driver,NULL)==SWOOSH_REPLAY);
    finished=true;vTaskEndScheduler();
}
int main(void) {
    memset(&admission,1,sizeof(admission));admission.scope.generation=1;admission.scope.policy_version=1;admission.scope.trust_epoch=1;
    requests=xQueueCreate(3,sizeof(SwooshRequest));assert(requests!=NULL);
    TaskHandle_t broker_handle;
    assert(xTaskCreate(broker,"broker",4096,NULL,3,&broker_handle)==pdPASS);
    assert(xTaskCreate(worker,"worker",4096,NULL,2,NULL)==pdPASS);
    assert(swoosh_freertos_configure(broker_handle,admission.scope.boot_nonce,1,1,10000,clock_ticks)==SWOOSH_OK);
    vTaskStartScheduler();assert(finished && effects==1);
    puts("FreeRTOS POSIX broker/worker, replay, halt and resume: PASS");return 0;
}
