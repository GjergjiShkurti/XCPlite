/* trace.h -- the stand-in of the VX1000 Timing Bundle's header (VX1000If_Trace.h): the IDs of the threads and runnables it traces, as
 * anonymous enums every unit that includes it has a copy of, and its trace arrays, one word per traced core. */

#include <stdint.h>

enum {
    VX1000IF_OS_TASK_MAIN,
    VX1000IF_OS_TASK_IDLE,
    VX1000IF_OS_TASK_COUNT
};

enum {
    VX1000IF_OS_ISR_TICK = VX1000IF_OS_TASK_COUNT,
    VX1000IF_OS_ISR_CAN0_RX,
    VX1000IF_OS_THREAD_COUNT
};

enum {
    VX1000IF_RTE_R_STEP = 1,
    VX1000IF_RTE_R_LOG,
    VX1000IF_RTE_R_END_
};

#define VX1000IF_TRACE_NUM_CORES 2

extern volatile uint32_t VX1000If_Os_Trace[VX1000IF_TRACE_NUM_CORES] __attribute__((weak));
extern volatile uint32_t VX1000If_Rte_Trace[VX1000IF_TRACE_NUM_CORES] __attribute__((weak));
