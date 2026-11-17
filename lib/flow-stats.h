/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FLOW_STATS_H
#define FLOW_STATS_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ovs-atomic.h"

struct dp_packet_batch;
struct nlattr;

#ifdef __cplusplus
extern "C" {
#endif

/* Per-flow statistics maintained for an OVS_ACTION_ATTR_FLOW_STATS action.
 *
 * A single entry is shared by every datapath flow that installs the same
 * instance of the action, so the counters aggregate traffic of all the flows
 * referencing that action.  The counters are stored atomically and may be
 * read or reset from any thread. */
struct flow_stats_entry {
    uint64_t id;                /* Unique identifier, never reused. */
    atomic_ullong packet_count; /* Number of packets observed. */
    atomic_ullong byte_count;   /* Number of bytes observed. */
    uint32_t sflow_probability; /* Configured sFlow probability (0 = off). */
};

/* Callback used to hand a batch observed by a FLOW_STATS action to the
 * sFlow implementation.  'dp' is the datapath execution context passed to
 * odp_execute_actions(), 'action' is the FLOW_STATS netlink attribute and the
 * callback runs in the context of the datapath that executes the packet. */
typedef void (*flow_stats_sflow_cb)(void *dp, const struct nlattr *action,
                                    struct dp_packet_batch *batch);

/* Looks up the statistics entry associated with 'action', creating it on the
 * first use.  Returns NULL if the action is not a FLOW_STATS action. */
struct flow_stats_entry *flow_stats_entry_lookup(const struct nlattr *action);

/* Iterates over all existing statistics entries.  Must be used outside of
 * datapath packet processing and only while no flows are being modified. */
size_t flow_stats_entry_count(void);
const struct flow_stats_entry *flow_stats_entry_get(size_t index);

/* Resets the packet and byte counters of every statistics entry. */
void flow_stats_reset_counters(void);

/* Registers (or clears with NULL) the callback that forwards sampled packets
 * to sFlow. */
void flow_stats_set_sflow_cb(flow_stats_sflow_cb cb);

/* Records a batch of packets against the FLOW_STATS 'action' and forwards the
 * batch to the sFlow callback when sampling is enabled.  'dp' is the datapath
 * execution context forwarded to the sFlow callback.  The action never
 * consumes or modifies the packets. */
void flow_stats_record(void *dp, const struct nlattr *action,
                       struct dp_packet_batch *batch);

#ifdef __cplusplus
}
#endif

#endif /* FLOW_STATS_H */
