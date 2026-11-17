/* app.c -- the stand-in firmware's own unit, with what mc-instrument's VX1000 headers and its runtime mc_vx.c write into it: MC_APP's
 * records, two MEASUREs (one multi-buffer), entries measured in place and one copied into its shadow, the Timing Bundle's template
 * records with their trace words, and mc_vx.c's channel arrays for the bundle's hooks.
 *
 * Built with -DSWITCHED_OFF (vx_bundle_off.out), MC_APP switches nothing on and the MEASUREs have no entries of their own: the
 * bundle's trace words are the only records. */

#include "records.h"
#include "trace.h"

#ifdef SWITCHED_OFF
#define SWITCHED_ON 0
#else
#define SWITCHED_ON 1
#endif

/* MC_APP(.name = "vx_bundle", .desc = ..., .timing_active = true, .timing_cores = 2, .vx_monitor_active = true), where mc_vx.c
 * writes the driver's channel modes (MCI_VX_W1_WRITES), with 31 channels */
const struct mci_app_meta __mci_appmeta RECORD("mci_app") = {
    .name = "vx_bundle",
    .desc = "The stand-in VX1000 firmware of xcpclient's tests",
    .timing_active = SWITCHED_ON,
    .timing_cores = 2,
    .vx_monitor_active = SWITCHED_ON,
    .w1_writes = 1,
    .channel_count = 31,
};
const uint16_t __mci_proto[5] RECORD("xcp_proto") = {255, 250, 0x34, 1, 0xA540};
const char __mci_epk[] RECORD("xcp_epk") = "vx_bundle 1.0";
const struct mci_meas_layout __mci_layout RECORD("mci_layout") = {
    sizeof(struct mci_meas_meta), sizeof(void *), 2,
    offsetof(struct mci_meas_meta, name), offsetof(struct mci_meas_meta, type), offsetof(struct mci_meas_meta, x_dim),
    offsetof(struct mci_meas_meta, flags), offsetof(struct mci_meas_meta, comment), offsetof(struct mci_meas_meta, unit),
    offsetof(struct mci_meas_meta, min), offsetof(struct mci_meas_meta, max), offsetof(struct mci_meas_meta, event),
    offsetof(struct mci_meas_meta, addr)};

/* The firmware's globals */
volatile int16_t Health;
volatile int32_t Ammo[4];
struct Position {
    int16_t x;
    int16_t y;
};
volatile struct Position Player;
volatile uint8_t Speed;
#ifndef SWITCHED_OFF
static volatile uint8_t __mci_sh_Speed;
#endif

/* MEASURE(Init, "once"), MEASURE(Frame, MC_MULTIBUF, "each frame", ...), then mc_vx.c's templates */
static const struct mci_evt_descriptor evt__Init RECORD("xcp_evts") = {"Init", 0, 0, {0xC6, 0x00}};
static const struct mci_evt_descriptor evt__Frame RECORD("xcp_evts") = {"Frame", 0, 0, {0xC6, 0x01}};
static const struct mci_evt_descriptor evt__OsTaskInfo RECORD("xcp_evts") = {"OsTaskInfo", 0, 0, {0xC6, 0x03}};
static const struct mci_evt_descriptor evt__OsRunInfo RECORD("xcp_evts") = {"OsRunInfo", 0, 0, {0xC6, 0x03}};

/* Frame's entries: a whole variable in place, an array element and a struct's first member in place (each with its .name, the
 * element's the array's own), and one copied into its shadow */
#define ENTRY(name_, type_, var_) {name_, type_, 1, 0, "", "", 0.0, 0.0, NULL, "Frame", (const void *)&(var_)}
#ifndef SWITCHED_OFF
static const struct mci_meas_meta __mci_desc_Health RECORD("mci_meas") __attribute__((aligned(8))) = ENTRY("Health", -2, Health);
static const struct mci_meas_meta __mci_desc_Ammo RECORD("mci_meas") __attribute__((aligned(8))) = ENTRY("Ammo", -4, Ammo[0]);
static const struct mci_meas_meta __mci_desc_Player RECORD("mci_meas") __attribute__((aligned(8))) = ENTRY("PlayerX", -2, Player.x);
static const struct mci_meas_meta __mci_desc_Speed RECORD("mci_meas") __attribute__((aligned(8))) = ENTRY("Speed", 1, __mci_sh_Speed);
#endif

/* mc_vx.c's trace words on the templates, the bundle's arrays referred to weakly */
static const struct mci_meas_meta __mci_desc_Os_Trace RECORD("mci_meas") __attribute__((aligned(8))) = {
    "Os_Trace", 4, 1, 0, "OS trace: FromThread<<24 | FromReason<<16 | ToThread<<8 | ToReason", "", 0.0, 0.0, NULL, "OsTaskInfo",
    (const void *)&VX1000If_Os_Trace[0]};
static const struct mci_meas_meta __mci_desc_Rte_Trace RECORD("mci_meas") __attribute__((aligned(8))) = {
    "Rte_Trace", 4, 1, 0, "Runnable trace: RunnableId<<8 | core, 0 = end", "", 0.0, 0.0, NULL, "OsRunInfo",
    (const void *)&VX1000If_Rte_Trace[0]};

/* mc_vx.c's channels for the bundle's hooks, room for six cores */
uint16_t mci_vx_timing_os_channel[6] = {0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF};
uint16_t mci_vx_timing_rte_channel[6] = {0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF};

/* A name of the bundle's prefix that this unit and bundle.c give different values */
enum { VX1000IF_OS_XCP_EVENT = 20 };

int main(void) {
#ifndef SWITCHED_OFF
    __mci_sh_Speed = Speed;
#endif
    return VX1000IF_OS_TASK_IDLE + VX1000IF_OS_ISR_CAN0_RX + VX1000IF_RTE_R_LOG + VX1000IF_OS_XCP_EVENT;
}
