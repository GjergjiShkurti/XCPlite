/* bundle.c -- the stand-in of the VX1000 Timing Bundle's own unit (VX1000If_Trace.c): its trace arrays, and a second copy of its enums. */

#include "trace.h"

volatile uint32_t VX1000If_Os_Trace[VX1000IF_TRACE_NUM_CORES];
volatile uint32_t VX1000If_Rte_Trace[VX1000IF_TRACE_NUM_CORES];

/* app.c gives this name 20 */
enum { VX1000IF_OS_XCP_EVENT = 21 };

int bundle_ids(void) {
    return VX1000IF_OS_THREAD_COUNT + VX1000IF_RTE_R_END_ + VX1000IF_OS_XCP_EVENT;
}
