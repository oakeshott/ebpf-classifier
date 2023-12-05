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
#define NUM_FEATURES 12
#define FIXED_POINT_DIGITS 16

struct pkt_key_t {
  u32 protocol;
  u32 saddr;
  u32 daddr;
  u32 sport;
  u32 dport;
};

struct pkt_leaf_t {
  u32 num_packets;
  u64 last_packet_timestamp;
  u32 saddr;
  u32 daddr;
  u32 sport;
  u32 dport;
  u64 features[6];
  bool is_anomaly;
};

BPF_TABLE("lru_hash", struct pkt_key_t, struct pkt_leaf_t, sessions, 1024);
BPF_HASH(dropcnt, int, u32);
BPF_HASH(pkt_len, int64_t, int64_t);

int xdp_drop_packet(struct xdp_md *ctx) {
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
    if ((void*)&iph[1] > data_end) {
      return XDP_DROP;
    }
    pkt_key.saddr    = iph->saddr;
    pkt_key.daddr    = iph->daddr;
    pkt_key.protocol = iph->protocol;

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
    goto drop;
  }
  udp: {
    uh = (struct udphdr *)(iph + 1);
    if ((void*)(uh + 1) > data_end) {
      return XDP_DROP;
    }
    pkt_key.sport = ntohs(uh->source);
    pkt_key.dport = ntohs(uh->dest);
    goto drop;
  }
  drop: {
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
      int _zero = 0;
      u32 val = 0, *vp;
      vp = dropcnt.lookup_or_init(&_zero, &val);
      *vp += 1;
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
    ret = []
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
    b = BPF(text=bpf_text)
    # b = BPF(text=bpf_text, device=offload_device)
    # for i in range(0, lib.bpf_num_functions(b.module)):
    #     func_name = lib.bpf_function_name(b.module, i)
    #     print(func_name, lib.bpf_function_size(b.module, func_name))

    try:
        fn = b.load_func("xdp_drop_packet", BPF.XDP)
        b.attach_xdp(device, fn=fn, flags=flags)
        # fn = b.load_func("forward_packet", BPF.XDP)
        # b.attach_xdp(device2, fn=fn, flags=flags)

        dropcnt = b.get_table("dropcnt")

        prev = 0
        interval = 100
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
        # b.remove_xdp('router-veth2', flags)

