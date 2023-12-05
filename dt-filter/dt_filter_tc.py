#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
from bcc import BPF
from bcc import lib, table
from pyroute2 import IPRoute
import sys
import time
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
import json
import numpy as np
from datetime import datetime

curdir = os.path.dirname(__file__)
ipr = IPRoute()

bpf_text = """
#include <uapi/linux/bpf.h>
#include <linux/inet.h>
#include <linux/pkt_cls.h>
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
#endif
BPF_HASH(dropcnt, int, u32);
BPF_HASH(tmp, int, u32);
BPF_HASH(feats, struct ethhdr, struct pkt_t);
BPF_ARRAY(childrenLeft, int64_t, DT_CHILDREN_LEFT_SIZE);
BPF_ARRAY(childrenRight, int64_t, DT_CHILDREN_RIGHT_SIZE);
BPF_ARRAY(feature, int64_t, DT_FEATURE_SIZE);
BPF_ARRAY(threshold, int64_t, DT_THRESHOLD_SIZE);
BPF_ARRAY(value, int64_t, DT_VALUE_SIZE);

int dt_tc_drop_packet(struct __sk_buff *skb) {
  int64_t ts = bpf_ktime_get_ns();
  void* data_end = (void*)(long)skb->data_end;
  void* data = (void*)(long)skb->data;

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
      return TC_ACT_SHOT;
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
      if (current_node != -1) {
        int64_t* current_value = value.lookup(&current_node);
        if (current_value) {
          if (*current_value == 0 || *current_value == 1) {
            bool is_anomaly = (bool)(*current_value);
            pkt.is_anomaly = *current_value;
            int _zero = 0;
            u32 val = 0, *vp;
            vp = dropcnt.lookup_or_init(&_zero, &val);
            *vp += 1;
            #ifdef DEBUG_BUILD
            feats.update(eth, &pkt);
            #endif
            if (is_anomaly) {
              #ifdef DEBUG_BUILD
              return TC_ACT_OK;
              #else
              return TC_ACT_SHOT;
              #endif
            }
          }
        }
      }
    }
  }

  EOP: {
    return TC_ACT_OK;
  }

  return TC_ACT_OK;
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


    device = sys.argv[1]
    resdir = sys.argv[2]

    INGRESS = "ffff:ffff2"
    EGRESS = "ffff:ffff3"

    ret = []
    try:
        b = BPF(text=bpf_text, debug=0)
        fn = b.load_func("dt_tc_drop_packet", BPF.SCHED_CLS)
        idx = ipr.link_lookup(ifname=device)[0]
        ipr.tc("add", "clsact", idx);
        ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent=INGRESS, classid=1, direct_action=True)

        for i in range(0, lib.bpf_num_functions(b.module)):
            func_name = lib.bpf_function_name(b.module, i)
            print(func_name, lib.bpf_function_size(b.module, func_name))

        dropcnt  = b.get_table("dropcnt")
        feats = b.get_table("feats")

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
        interval = 100
        start = datetime.now()
        while True:
            try:
                dropcnt.clear()
                start1 = datetime.now()
                time.sleep(1)
                end = datetime.now()
                for k, v in dropcnt.items():
                    print(v.value)
                    ret.append(int(v.value / (end - start1).total_seconds()))
                duration = (end - start).total_seconds()
                if duration > interval:
                    break
            except KeyboardInterrupt:
                break
    finally:
        if "idx" in locals():
            ipr.tc("del", "clsact", idx)
        filename = f"{resdir}/rxpps.log"
        with open (filename, 'w') as f:
            for d in ret:
                f.write(f"{d}\n")
