#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
from bcc import BPF
from bcc import lib
import sys
import time
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
import json
import numpy as np
from datetime import datetime

curdir = os.path.dirname(__file__)
def usage():
    print("Usage: {0} <ifdev> <flag>".format(sys.argv[0]))
    exit(1)
bpf_text = """
#include <uapi/linux/bpf.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#define DEBUG_BUILD
#define TREE_LEAF -1
#define TREE_UNDEFINED -2
#define MAX_TREE_DEPTH DT_MAX_TREE_DEPTH
#define FIXED_POINT_DIGITS 16
#define NUM_FEATURES 12
#ifndef abs
#define abs(x) ((x)<0 ? -(x) : (x))
#endif
struct pkt_t {
  int64_t sport;
  int64_t dport;
  int64_t protocol;
  int64_t tot_len;
  int64_t interval_time;
  int64_t direction;
  int64_t last_packet_timestamp;
  int64_t is_anomaly;
};

struct pkt_key_t {
  u32 protocol;
  u32 saddr;
  u32 daddr;
  u32 sport;
  u32 dport;
};

struct pkt_leaf_t {
  u64 num_packets;
  u64 last_packet_timestamp;
  u64 saddr;
  u64 daddr;
  u64 sport;
  u64 dport;
  u64 features[6];
  bool is_anomaly;
};

BPF_TABLE("lru_hash", struct pkt_key_t, struct pkt_leaf_t, sessions, 1024);
#ifdef DEBUG_BUILD
BPF_HASH(tmp,  struct ethhdr, int);
BPF_HASH(tmp2, struct ethhdr, bool);
BPF_HASH(tmp3, struct ethhdr, int64_t);
BPF_HASH(feats2, struct ethhdr, struct pkt_t);
#endif
BPF_HASH(feats, struct ethhdr, struct pkt_t);
BPF_HASH(dropcnt, int, u32);
BPF_ARRAY(childrenLeft, s64, DT_CHILDREN_LEFT_SIZE);
BPF_ARRAY(childrenRight, s64, DT_CHILDREN_RIGHT_SIZE);
BPF_ARRAY(feature, s64, DT_FEATURE_SIZE);
BPF_ARRAY(threshold, s64, DT_THRESHOLD_SIZE);
BPF_ARRAY(value, s64, DT_VALUE_SIZE);

static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
    u32 check = (__force u32)iph->check;

    check += (__force u32)htons(0x0100);
    iph->check = (__force __sum16)(check + (check >= 0xFFFF));
    return --iph->ttl;
}

int dt_xdp_drop_packet(struct xdp_md *ctx) {
  int64_t ts = bpf_ktime_get_ns();
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;
  struct ethhdr *eth = data;
  u64 nh_off = sizeof(*eth);
  struct iphdr *iph;
  struct tcphdr *th;
  struct udphdr *uh;
  struct pkt_key_t pkt_key = {};
  struct pkt_leaf_t pkt_val = {};

  struct pkt_t pkt_test = {};

  pkt_key.protocol = 0;
  pkt_key.saddr = 0;
  pkt_key.daddr = 0;
  pkt_key.sport = 0;
  pkt_key.dport = 0;

  ethernet: {
    if (data + nh_off > data_end) {
      return XDP_DROP;
    }
    switch(eth->h_proto) {
      case htons(ETH_P_IP): goto ip;
      default: goto EOP;
    }
  }
  ip: {
    iph = data + nh_off;
    if ((void*)&iph[1] > data_end)
      return XDP_DROP;
    pkt_key.saddr    = iph->saddr;
    pkt_key.daddr    = iph->daddr;
    pkt_key.protocol = iph->protocol;

    pkt_test.protocol = iph->protocol;
    pkt_test.tot_len = iph->tot_len;
    pkt_test.direction = 1;
    pkt_test.interval_time = 1;
    // pkt_key.tot_len  = ntohs(iph->tot_len);
    switch(iph->protocol) {
      case IPPROTO_TCP: goto tcp;
      case IPPROTO_UDP: goto udp;
      default: goto EOP;
    }
  }
  tcp: {
    th = (struct tcphdr *)(iph + 1);
    if ((void*)(th + 1) > data_end) {
      return XDP_DROP;
    }
    pkt_key.sport = ntohs(th->source);
    pkt_key.dport = ntohs(th->dest);

    pkt_test.sport = ntohs(th->source);
    pkt_test.dport = ntohs(th->dest);
    goto dt;
  }
  udp: {
    uh = (struct udphdr *)(iph + 1);
    if ((void*)(uh + 1) > data_end) {
      return XDP_DROP;
    }
    pkt_key.sport = ntohs(uh->source);
    pkt_key.dport = ntohs(uh->dest);

    pkt_test.sport = ntohs(uh->source);
    pkt_test.dport = ntohs(uh->dest);
    goto dt;
  }
  dt: {
    struct pkt_leaf_t *pkt_leaf = sessions.lookup(&pkt_key);
    if (!pkt_leaf) {
      struct pkt_leaf_t zero = {};
      zero.sport = pkt_key.sport;
      zero.dport = pkt_key.dport;
      zero.saddr = pkt_key.saddr;
      zero.daddr = pkt_key.daddr;
      zero.num_packets = 0;
      zero.last_packet_timestamp = ts;
      sessions.lookup_or_try_init(&pkt_key, &zero);
      pkt_leaf = sessions.lookup(&pkt_key);
    }
    if (pkt_leaf != NULL) {
      pkt_leaf->num_packets += 1;
      int64_t sport = pkt_leaf->sport;
      int64_t dport = pkt_leaf->dport;
      int64_t protocol = iph->protocol;
      int64_t tot_len = ntohs(iph->tot_len);
      int64_t interval_time = 0;
      if (pkt_leaf->last_packet_timestamp > 0) {
        interval_time = ts - pkt_leaf->last_packet_timestamp;
      }
      pkt_leaf->last_packet_timestamp = ts;
      int64_t direction = pkt_key.sport == sport;
      struct pkt_t pkt = {sport, dport, protocol, tot_len, interval_time, direction, pkt_leaf->last_packet_timestamp};

      sport <<= FIXED_POINT_DIGITS;
      dport <<= FIXED_POINT_DIGITS;
      protocol <<= FIXED_POINT_DIGITS;
      tot_len <<= FIXED_POINT_DIGITS;
      interval_time <<= FIXED_POINT_DIGITS;
      direction <<= FIXED_POINT_DIGITS;

      pkt_leaf->features[0] += tot_len;
      pkt_leaf->features[1] += interval_time;
      pkt_leaf->features[2] += direction;

      int64_t avg_tot_len       = pkt_leaf->features[0]/pkt_leaf->num_packets;
      int64_t avg_interval_time = pkt_leaf->features[1]/pkt_leaf->num_packets;
      int64_t avg_direction     = pkt_leaf->features[2]/pkt_leaf->num_packets;

      pkt_leaf->features[3] += abs(tot_len - avg_tot_len);
      pkt_leaf->features[4] += abs(interval_time - avg_interval_time);
      pkt_leaf->features[5] += abs(direction - avg_direction);

      int64_t avg_dev_tot_len       = pkt_leaf->features[3]/pkt_leaf->num_packets;
      int64_t avg_dev_interval_time = pkt_leaf->features[4]/pkt_leaf->num_packets;
      int64_t avg_dev_direction     = pkt_leaf->features[5]/pkt_leaf->num_packets;

      int64_t feat[NUM_FEATURES] = {sport, dport, protocol, tot_len, interval_time, direction, avg_tot_len, avg_interval_time, avg_direction, avg_dev_tot_len, avg_dev_interval_time, avg_dev_direction};
      sessions.update(&pkt_key, pkt_leaf);
      // feats2.update(eth, &pkt_test);


      int i = 0;
      int current_node = 0;

      for (i = 0; i < MAX_TREE_DEPTH; i++) {
        int64_t* current_left_child  = childrenLeft.lookup(&current_node);
        int64_t* current_right_child = childrenRight.lookup(&current_node);
        int64_t* current_feature     = feature.lookup(&current_node);
        int64_t* current_threshold   = threshold.lookup(&current_node);
        if (current_left_child == NULL || current_right_child == NULL || current_feature == NULL || current_threshold == NULL || *current_left_child == TREE_LEAF || *current_feature == TREE_UNDEFINED) {
          break;
        } else {
          if (*current_feature >= 0 && *current_feature < NUM_FEATURES ) {
            int64_t current_feature_value = feat[*current_feature];
            if (current_feature_value) {
              if (current_feature_value <= *current_threshold) {
                current_node = (int) *current_left_child;
              } else {
                current_node = (int) *current_right_child;
              }
            }
          }
        }
      }
      int64_t* current_value = value.lookup(&current_node);
      if (current_value) {
        if (*current_value == 0 || *current_value == 1) {
          bool is_anomaly = (bool)(*current_value);
          tmp.update(eth, &current_node);
          tmp2.update(eth, &is_anomaly);
          tmp3.update(eth, current_value);
          pkt.is_anomaly = *current_value;
          // feats.update(eth, &pkt);
          int _zero = 0;
          u32 val = 0, *vp;
          vp = dropcnt.lookup_or_init(&_zero, &val);
          *vp += 1;
          // goto forward;
          if (is_anomaly) {
            #ifdef DEBUG_BUILD
            return XDP_PASS;
            #else
            return XDP_DROP;
            #endif
          }
          return XDP_PASS;
        }
      }
    }
  }
  forward : {
    struct bpf_fib_lookup fib_params = {};
    if (iph->ttl <= 1) {
        return XDP_PASS;
    }
    __builtin_memset(&fib_params, 0, sizeof(fib_params));
    if (eth->h_proto == htons(ETH_P_IP)) {
        if ((void*)&iph[1] > data_end) {
            return XDP_DROP;
        }
        fib_params.family = AF_INET;
        fib_params.tos = iph->tos;
        fib_params.l4_protocol = iph->protocol;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = bpf_ntohs(iph->tot_len);
        fib_params.ipv4_src = iph->saddr;
        fib_params.ipv4_dst = iph->daddr;
        fib_params.ifindex = ctx->ingress_ifindex;
    } else {
        return XDP_PASS;
    }
    long rc;
    int _zero = 0;
    u32 val = 0, *vp;
    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
    // feats2.update(eth, &rc);
    switch(rc) {
    case BPF_FIB_LKUP_RET_SUCCESS:
        ip_decrease_ttl(iph);
        __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
        return bpf_redirect(fib_params.ifindex, 0);
    case BPF_FIB_LKUP_RET_BLACKHOLE:
    case BPF_FIB_LKUP_RET_UNREACHABLE:
    case BPF_FIB_LKUP_RET_PROHIBIT:
        return XDP_DROP;
    case BPF_FIB_LKUP_RET_NOT_FWDED:
    case BPF_FIB_LKUP_RET_FWD_DISABLED:
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:
    case BPF_FIB_LKUP_RET_NO_NEIGH:
    case BPF_FIB_LKUP_RET_FRAG_NEEDED:
        return XDP_PASS;
    }
  }
  EOP: {
    return XDP_PASS;
  }

  return XDP_PASS;
}

"""

def map_bpf_table(hashmap, values):
    MAP_SIZE = len(values)
    assert len(hashmap.items()) == MAP_SIZE
    keys = (hashmap.Key * MAP_SIZE)()
    new_values = (hashmap.Leaf * MAP_SIZE)()

    for i in range(MAP_SIZE):
        keys[i] = ct.c_int(i)
        new_values[i] = ct.c_longlong(values[i])
    hashmap.items_update_batch(keys, new_values)

if __name__ == '__main__':
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        usage()
    device = sys.argv[1]
    resdir = sys.argv[2]
    flags = 0
    offload_device = None
    if len(sys.argv) == 3:
        if "-S" in sys.argv:
            # XDP_FLAGS_SKB_MODE
            flags |= BPF.XDP_FLAGS_SKB_MODE
        if "-D" in sys.argv:
            # XDP_FLAGS_DRV_MODE
            flags |= BPF.XDP_FLAGS_DRV_MODE
        if "-H" in sys.argv:
            # XDP_FLAGS_HW_MODE
            offload_device = device
            flags |= BPF.XDP_FLAGS_HW_MODE
    prefix_path = f"{curdir}/runs"
    with open(f'{prefix_path}/childrenLeft', 'r') as f:
        children_left = np.array(json.load(f))
    with open(f'{prefix_path}/childrenRight', 'r') as f:
        children_right = np.array(json.load(f))
    with open(f'{prefix_path}/threshold', 'r') as f:
        threshold = np.array(json.load(f))
    with open(f'{prefix_path}/feature', 'r') as f:
        feature = np.array(json.load(f))
    with open(f'{prefix_path}/value', 'r') as f:
        value = np.array(json.load(f))

    bpf_text = bpf_text.replace('DT_CHILDREN_LEFT_SIZE', f"{len(children_left)}")
    bpf_text = bpf_text.replace('DT_CHILDREN_RIGHT_SIZE', f"{len(children_right)}")
    bpf_text = bpf_text.replace('DT_FEATURE_SIZE', f"{len(feature)}")
    bpf_text = bpf_text.replace('DT_VALUE_SIZE', f"{len(value)}")
    bpf_text = bpf_text.replace('DT_THRESHOLD_SIZE', f"{len(threshold)}")
    bpf_text = bpf_text.replace('DT_MAX_TREE_DEPTH', f"20")

    b = BPF(text=bpf_text)
    ret = []
    # for i in range(0, lib.bpf_num_functions(b.module)):
    #     func_name = lib.bpf_function_name(b.module, i)
    #     print(func_name, lib.bpf_function_size(b.module, func_name))

    try:
        b.attach_xdp(device, fn = b.load_func("dt_xdp_drop_packet", BPF.XDP), flags=flags)

        dropcnt  = b.get_table("dropcnt")
        # feats = b.get_table("feats")

        map_children_right = b.get_table("childrenRight")
        map_children_left  = b.get_table("childrenLeft")
        map_value          = b.get_table("value")
        map_threshold      = b.get_table("threshold")
        map_feature        = b.get_table("feature")

        map_bpf_table(map_children_right, children_right)
        map_bpf_table(map_children_left, children_left)
        map_bpf_table(map_value, value)
        map_bpf_table(map_threshold, threshold)
        map_bpf_table(map_feature, feature)
        # for k, v in map_value.items():
        #     print(k.value, v.value)

        prev = 0
        interval = 110
        start = datetime.now()
        while True:
            try:
                dropcnt.clear()
                start1 = datetime.now()
                time.sleep(1)
                end = datetime.now()
                for k, v in dropcnt.items():
                    # print(v.value)
                    ret.append(int(v.value / (end - start1).total_seconds()))
                duration = (end - start).total_seconds()
                if duration > interval:
                    break
            except KeyboardInterrupt:
                break
    finally:
        b.remove_xdp(device, flags)
        filename = f"{resdir}/rxpps.log"
        if "-S" in sys.argv:
            # XDP_FLAGS_SKB_MODE
            filename = f"{resdir}/rxpps.log"
        if "-D" in sys.argv:
            filename = f"{resdir}/rxpps.log"
        with open (filename, 'w') as f:
            for d in ret:
                f.write(f"{d}\n")

