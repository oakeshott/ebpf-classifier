#!/usr/bin/python3
# -*- coding: utf-8 -*-


import os
from bcc import BPF
from pyroute2 import IPRoute
import pyroute2
import sys
import time
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
import joblib
from datetime import datetime

curdir = os.path.dirname(__file__)
def usage():
    print("Usage: {0} <ifdev>".format(sys.argv[0]))
    exit(1)
ipr = IPRoute()

bpf_text = """
#include <uapi/linux/bpf.h>
#include <linux/inet.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#define DEBUG_BUILD
#define FIXED_POINT_DIGITS 16
#define NUM_FEATURES 12

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
BPF_HASH(feats, struct ethhdr, struct pkt_t);
BPF_HASH(dropcnt, int, u32);
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
    u32 check = (__force u32)iph->check;

    check += (__force u32)htons(0x0100);
    iph->check = (__force __sum16)(check + (check >= 0xFFFF));
    return --iph->ttl;
}

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
    if ((void*)&iph[1] > data_end) {
      return TC_ACT_SHOT;
    }
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
      return TC_ACT_SHOT;
    }
    pkt_key.sport = ntohs(th->source);
    pkt_key.dport = ntohs(th->dest);

    pkt_test.sport = ntohs(th->source);
    pkt_test.dport = ntohs(th->dest);
    goto drop;
  }

  udp: {
    uh = (struct udphdr *)(iph + 1);
    if ((void*)(uh + 1) > data_end) {
      return TC_ACT_SHOT;
    }
    pkt_key.sport = ntohs(uh->source);
    pkt_key.dport = ntohs(uh->dest);

    pkt_test.sport = ntohs(uh->source);
    pkt_test.dport = ntohs(uh->dest);
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
      // feats.update(eth, &pkt_test);

      int _zero = 0;
      u32 val = 0, *vp;
      vp = dropcnt.lookup_or_init(&_zero, &val);
      *vp += 1;
      #ifdef DEBUG_BUILD
      return TC_ACT_OK;
      #else
      return TC_ACT_SHOT;
      #endif
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
    device = sys.argv[1]
    resdir = sys.argv[2]

    INGRESS = "ffff:ffff2"
    EGRESS = "ffff:ffff3"

    ret = []
    try:
        b = BPF(text=bpf_text, debug=0)
        fn = b.load_func("dt_tc_drop_packet", BPF.SCHED_CLS)
        # idx = ipr.link_lookup(ifname=device)[0]

        # ipr.tc("add", "clsact", idx);
        # ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent=INGRESS, classid=1, direct_action=True)
        ip = pyroute2.IPRoute()
        ipdb = pyroute2.IPDB(nl=ip)
        idx = ipdb.interfaces[device].index
        ip.tc("add", "clsact", idx)
        ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
              parent="ffff:fff2", classid=1, direct_action=True)

        dropcnt  = b.get_table("dropcnt")
        # feats = b.get_table("feats")

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
