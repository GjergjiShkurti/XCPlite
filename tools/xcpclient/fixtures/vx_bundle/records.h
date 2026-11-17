/* records.h -- the records mc-instrument's VX1000 headers (mc_vx.h) write into a firmware, as they lay them out, for the stand-in
 * firmware xcpclient's tests read (vx_bundle.out, built by make_vx_bundle.sh). */

#include <stddef.h>
#include <stdint.h>

#define RECORD(section_) __attribute__((section(section_), used))

/* One measurement entry, in mci_meas */
struct mci_meas_meta {
    const char *name;
    int8_t type; /* the A2L type id: the byte size, negative when signed */
    uint16_t x_dim;
    uint16_t flags;
    const char *comment;
    const char *unit;
    double min, max;
    uint32_t *idp;
    const char *event;
    const void *addr;
};

/* How to read mci_meas, in mci_layout */
struct mci_meas_layout {
    uint16_t rec_size;
    uint8_t ptr_size;
    uint8_t version;
    uint16_t o_name, o_type, o_x_dim, o_flags, o_comment, o_unit, o_min, o_max, o_event, o_addr;
};

/* The application, in mci_app: 218 bytes */
struct mci_app_meta {
    char name[64];
    char bind[16];
    uint16_t port;
    uint8_t tcp;
    uint8_t endpoint;
    char desc[128];
    uint8_t timing_active;
    uint8_t timing_cores;
    uint8_t vx_monitor_active;
    uint8_t w1_known;
    uint16_t channel_count;
};

/* One event, in xcp_evts: res[0] the marker 0xC6, res[1] the flags (0x01 multi-buffer, 0x02 a Timing Bundle template) */
struct mci_evt_descriptor {
    const char *name;
    uint32_t cycle_time_ns;
    uint8_t priority;
    uint8_t res[16 - sizeof(char *) - 4 - 1];
};

_Static_assert(sizeof(struct mci_app_meta) == 218, "the application record has no padding");
_Static_assert(sizeof(struct mci_evt_descriptor) == 16, "an event record is 16 bytes");
