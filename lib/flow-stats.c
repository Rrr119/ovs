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

#include <config.h>
#include "flow-stats.h"

#include "cmap.h"
#include "coverage.h"
#include "dp-packet.h"
#include "hash.h"
#include "openvswitch/thread.h"
#include "util.h"
#include "openvswitch/vlog.h"
#include "odp-netlink.h"

VLOG_DEFINE_THIS_MODULE(flow_stats);

COVERAGE_DEFINE(flow_stats_action);
COVERAGE_DEFINE(flow_stats_sflow);

/* Registry entry.  The key is the address of the FLOW_STATS netlink
 * attribute inside the datapath's action buffer, which stays valid for the
 * whole lifetime of the installed flow. */
struct flow_stats_node {
    struct cmap_node node;
    const struct nlattr *action;
    struct flow_stats_entry stats;
};

static struct cmap flow_stats_table = CMAP_INITIALIZER;
static struct ovs_mutex flow_stats_mutex = OVS_MUTEX_INITIALIZER;
static uint64_t flow_stats_next_id OVS_GUARDED_BY(flow_stats_mutex) = 1;
static flow_stats_sflow_cb sflow_cb;

static uint32_t
flow_stats_get_probability(const struct nlattr *action)
{
    const struct nlattr *a;
    unsigned int left;

    NL_NESTED_FOR_EACH (a, left, action) {
        if (nl_attr_type(a) == OVS_FLOW_STATS_ATTR_SFLOW_PROBABILITY) {
            return nl_attr_get_u32(a);
        }
    }
    return 0;
}

struct flow_stats_entry *
flow_stats_entry_lookup(const struct nlattr *action)
{
    struct flow_stats_node *node;
    uint32_t hash;

    if (!action || nl_attr_type(action) != OVS_ACTION_ATTR_FLOW_STATS) {
        return NULL;
    }

    hash = hash_pointer(action, 0);
    CMAP_FOR_EACH_WITH_HASH (node, node, hash, &flow_stats_table) {
        if (node->action == action) {
            return &node->stats;
        }
    }

    ovs_mutex_lock(&flow_stats_mutex);
    CMAP_FOR_EACH_WITH_HASH (node, node, hash, &flow_stats_table) {
        if (node->action == action) {
            ovs_mutex_unlock(&flow_stats_mutex);
            return &node->stats;
        }
    }

    node = xzalloc(sizeof *node);
    node->action = action;
    node->stats.id = flow_stats_next_id++;
    node->stats.sflow_probability = flow_stats_get_probability(action);
    atomic_init(&node->stats.packet_count, 0);
    atomic_init(&node->stats.byte_count, 0);
    cmap_insert(&flow_stats_table, &node->node, hash);
    ovs_mutex_unlock(&flow_stats_mutex);

    return &node->stats;
}

size_t
flow_stats_entry_count(void)
{
    struct flow_stats_node *node;
    size_t count = 0;

    ovs_mutex_lock(&flow_stats_mutex);
    CMAP_FOR_EACH (node, node, &flow_stats_table) {
        count++;
    }
    ovs_mutex_unlock(&flow_stats_mutex);

    return count;
}

const struct flow_stats_entry *
flow_stats_entry_get(size_t index)
{
    struct flow_stats_node *node;
    size_t pos = 0;
    const struct flow_stats_entry *result = NULL;

    ovs_mutex_lock(&flow_stats_mutex);
    CMAP_FOR_EACH (node, node, &flow_stats_table) {
        if (pos++ == index) {
            result = &node->stats;
            break;
        }
    }
    ovs_mutex_unlock(&flow_stats_mutex);

    return result;
}

void
flow_stats_reset_counters(void)
{
    struct flow_stats_node *node;

    ovs_mutex_lock(&flow_stats_mutex);
    CMAP_FOR_EACH (node, node, &flow_stats_table) {
        atomic_store_relaxed(&node->stats.packet_count, 0);
        atomic_store_relaxed(&node->stats.byte_count, 0);
    }
    ovs_mutex_unlock(&flow_stats_mutex);
}

void
flow_stats_set_sflow_cb(flow_stats_sflow_cb cb)
{
    /* The callback is registered once during datapath initialization, before
     * any packet processing thread starts, so plain assignment is safe. */
    sflow_cb = cb;
}

void
flow_stats_record(void *dp, const struct nlattr *action,
                  struct dp_packet_batch *batch)
{
    struct flow_stats_entry *entry;
    struct dp_packet *packet;
    flow_stats_sflow_cb cb;
    unsigned long long old;
    size_t n_bytes = 0;
    size_t n_packets;

    entry = flow_stats_entry_lookup(action);
    if (!entry) {
        return;
    }

    n_packets = dp_packet_batch_size(batch);
    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        n_bytes += dp_packet_size(packet);
    }

    atomic_add_relaxed(&entry->packet_count, n_packets, &old);
    atomic_add_relaxed(&entry->byte_count, n_bytes, &old);
    COVERAGE_ADD(flow_stats_action, n_packets);

    cb = sflow_cb;

    if (entry->sflow_probability && cb) {
        COVERAGE_ADD(flow_stats_sflow, n_packets);
        cb(dp, action, batch);
    }
}
