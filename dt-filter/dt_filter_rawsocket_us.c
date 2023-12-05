/**
 * @author      : t-hara (t-hara@$HOSTNAME)
 * @file        : packetcapture
 * @created     : Thursday Oct 20, 2022 18:53:52 JST
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <unistd.h>
#include <assert.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <time.h>
#include "hashmap.h"
#include "hashmap.c"
#include "jhash.h"

#define DEBUG_BUILD
#define DEVICE "eno12409"
#ifdef DEBUG_BUILD
#define DEBUG printf
#endif
#define TREE_LEAF -1
#define TREE_UNDEFINED -2
#define FIXED_POINT_DIGITS 16
#define NUM_FEATURES 12
#define abs(x) ((x)<0 ? -(x) : (x))
#define TC_CLS_DEFAULT -1
#define TC_CLS_NOMATCH  0
#define DADDR 33619978

static unsigned long get_nsecs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

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
  int64_t protocol;
  int64_t saddr;
  int64_t daddr;
  int64_t sport;
  int64_t dport;
};

struct pkt_leaf_t {
  int64_t num_packets;
  int64_t last_packet_timestamp;
  int64_t saddr;
  int64_t daddr;
  int64_t sport;
  int64_t dport;
  int64_t features[6];
  int64_t is_anomaly;
};

static uint64_t hash_fn(const void *k, void *ctx)
{
  // XXX: This is bad since it only returns 32 bits
  return (uint64_t) jhash(k, sizeof(struct pkt_key_t), 0);
}

static bool equal_fn(const void *a, const void *b, void *ctx)
{
  struct pkt_key_t* as = (struct pkt_key_t*) a;
  struct pkt_key_t* bs = (struct pkt_key_t*) b;
  return as->protocol == bs->protocol && as->saddr == bs->saddr && as->daddr == bs->daddr && as->sport == bs->sport && as->dport == bs->dport;
}
int filter(uint8_t* data, int64_t *childrenLeft, int64_t *childrenRight, int64_t *value, int64_t *feature, int64_t *threshold, int n) {
  u_int64_t ts = get_nsecs();
  u_char *buf;
  int dropcnt = 0;
  struct ether_header *eth;
  struct iphdr *iph;
  struct tcphdr *th;
  struct udphdr *uh;
  struct hashmap* sessions = hashmap__new(hash_fn, equal_fn, NULL);
  struct pkt_key_t pkt_key;
  int MAX_TREE_DEPTH = n;
  pkt_key.protocol = 0;
  pkt_key.saddr = 0;
  pkt_key.daddr = 0;
  pkt_key.sport = 0;
  pkt_key.dport = 0;

  buf = data;
  /* printf("\nData Size =%d\n", len); */
  eth = (struct ether_header *)data;
  buf += sizeof(struct ether_header);
  switch (ntohs(eth->ether_type)) {
    case ETHERTYPE_IP: goto ip;
    default: goto EOP;
  }
  ip: {
    iph = (struct iphdr *)buf;
    buf += sizeof(struct iphdr);
    pkt_key.protocol = iph->protocol;
    pkt_key.saddr = iph->saddr;
    pkt_key.daddr = iph->daddr;
    switch (iph->protocol) {
      case IPPROTO_TCP: goto tcp;
      case IPPROTO_UDP: goto udp;
      default: goto EOP;
    }
  }
  tcp: {
    th = (struct tcphdr *)buf;
    pkt_key.sport = ntohs(th->source);
    pkt_key.dport = ntohs(th->dest);
    goto dt;
  }
  udp: {
    uh = (struct udphdr *)buf;
    pkt_key.sport = ntohs(uh->source);
    pkt_key.dport = ntohs(uh->dest);
    goto dt;
  }
  dt: {
    struct pkt_leaf_t *pkt_leaf = NULL;
    bool ret = hashmap__find(sessions, &pkt_key, &pkt_leaf);
    /* printf("%s\n", (ret ? "true" : "false")); */
    if (!ret) {
      struct pkt_leaf_t *zero = (struct pkt_leaf_t*) calloc(1, sizeof(struct pkt_leaf_t));
      zero->sport = pkt_key.sport;
      zero->dport = pkt_key.dport;
      zero->saddr = pkt_key.saddr;
      zero->daddr = pkt_key.daddr;
      zero->num_packets = 0;
      zero->last_packet_timestamp = ts;
      zero->num_packets = 0;
      zero->last_packet_timestamp = ts;
      struct pkt_key_t *pkt_key_allocated = (struct pkt_key_t*) calloc(1, sizeof(struct pkt_key_t));
      int err = hashmap__add(sessions, pkt_key_allocated, zero);
      /* assert(err == 0); */
      bool ret = hashmap__find(sessions, pkt_key_allocated, &pkt_leaf);
      #ifdef DEBUG_BUILD
      /* DEBUG("PKT_KEY: %ld\t%ld\t%ld\t%ld\t%ld\n", ts, pkt_key.saddr, pkt_key.daddr, pkt_key.sport, pkt_key.dport); */
      #endif
      /* DEBUG("PKT_LEAF: %ld\t%ld\t%ld\t%ld\t%ld\n", ts, pkt_leaf->saddr, pkt_leaf->daddr, pkt_leaf->sport, pkt_leaf->dport); */
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
      struct pkt_t pkt;
      pkt.sport    = sport;
      pkt.dport    = dport;
      pkt.protocol = protocol;
      pkt.tot_len  = tot_len;
      pkt.interval_time = interval_time;
      pkt.direction = direction;
      pkt.last_packet_timestamp = pkt_leaf->last_packet_timestamp;

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

      int err = hashmap__add(sessions, &pkt_key, &pkt_leaf);
      #ifdef DEBUG_BUILD
      /* DEBUG("FEAT: %ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\n", ts, feat[0], feat[1], feat[2], feat[3], feat[4], feat[5]); */
      #endif

      int current_node = 0;
      int i;

      for (i = 0; i < MAX_TREE_DEPTH; i++) {
        int64_t current_left_child  = childrenLeft[current_node];
        int64_t current_right_child = childrenRight[current_node];
        int64_t current_feature     = feature[current_node];
        int64_t current_threshold   = threshold[current_node];
        if (current_left_child == TREE_LEAF || current_feature == TREE_UNDEFINED) {
          break;
        } else {
          if (current_feature >= 0 && current_feature < NUM_FEATURES ) {
            int64_t current_feature_value = feat[current_feature];
            if (current_feature_value <= current_threshold) {
              current_node = (int) current_left_child;
            } else {
              current_node = (int) current_right_child;
            }
          }
        }
      }
      int64_t current_value = value[current_node];
      if (current_value == 0 || current_value == 1) {
        bool is_anomaly = (bool)(current_value);
        pkt.is_anomaly = current_value;
        #ifdef DEBUG_BUILD
        /* DEBUG("PACKET: %ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\n", ts, pkt.sport, pkt.dport, pkt.protocol, pkt.tot_len, pkt.interval_time, pkt.direction, pkt.last_packet_timestamp, pkt.is_anomaly); */
        #endif
        if (pkt_key.saddr == DADDR) {
          return -2;
        }
        if (is_anomaly) {
          dropcnt += 1;
          //   u32 val = 0, *vp;
          //   vp = dropcnt.lookup_or_init(eth, &val);
          //   *vp += 1;
          //   return TC_ACT_SHOT;
        #ifdef DEBUG_BUILD
          return TC_CLS_DEFAULT;
          perror("DROP_PACKET");
        #else
          return TC_CLS_NOMATCH;
        #endif
        }
      }
    }
  }
  EOP: {
    return TC_CLS_DEFAULT;
  }
  return TC_CLS_DEFAULT;
}
void dt_filter(int seconds, int64_t *childrenLeft, int64_t *childrenRight, int64_t *value, int64_t *feature, int64_t *threshold, int n, int* counter) {
  /* int i; */
  /* for (i = 0; i < n; i++) { */
  /*   printf("%d\t%ld\t%ld\t%ld\t%ld\t%ld\n", i, childrenLeft[i], childrenRight[i], value[i], feature[i], threshold[i]); */
  /* } */
  struct sockaddr_ll sockaddr;
  struct ifreq ifreq;
  u_char data[1500];
  int len;

  int sock;
  sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock < 0) {
    perror("socket");
  }

  memset(&ifreq, 0, sizeof(struct ifreq));
  strncpy(ifreq.ifr_name, DEVICE, sizeof(ifreq.ifr_name) - 1);
  if (ioctl(sock, SIOCGIFINDEX, &ifreq) != 0) {
    perror("ioctl");
  }
  sockaddr.sll_ifindex = ifreq.ifr_ifindex;
  sockaddr.sll_family = PF_PACKET;
  sockaddr.sll_protocol = htons(ETH_P_ALL);
  /* sockaddr.sll_pkttype = PACKET_INCOMING; */
  if (bind(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr))!=0) {
    perror("bind");
  }

  int i = 0;
  u_int64_t ts1, ts2;
  u_int64_t cnt = 0;
  u_int64_t start, end;
  u_int64_t one_second = 1000000000;
  u_int64_t interval = one_second * seconds;
  ts1 = get_nsecs();
  start = get_nsecs();
  while (true) {
    if ((len=recv(sock, data, sizeof(data), 0)) <= 0) {
      perror("recv");
    } else {
      int flag = filter(data, childrenLeft, childrenRight, value, feature, threshold, n);
      /* printf("%d\n", flag); */
      if (flag == -2) {
        cnt++;
      }
    }
    ts2 = get_nsecs();
    if (ts2 - ts1 > one_second) {
      /* DEBUG("%ld\t%ld\n", ts2, cnt); */
      if (sockaddr.sll_pkttype == PACKET_OUTGOING) {
        continue;
      }
      counter[i] = cnt;
      cnt = 0;
      i++;
      ts1 = get_nsecs();
    }
    end = get_nsecs();
    if (end - start > interval) {
      break;
    }
  }
  close(sock);
  return;
}
