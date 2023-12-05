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
#include <pthread.h>
#include <string.h>
#include "hashmap.h"
#include "hashmap.c"
#include "jhash.h"
#include "mlp.h"
#include "mlp.c"
#include "mlp_params.h"
#include "mlp_params.c"
#include "nn.h"
#include "nn.c"
#include "nn_math.h"
#include "nn_math.c"

/* #define DEBUG_BUILD */
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
#define SADDR 33619978

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

struct param_key_t {
  int id;
};
struct param_val_t {
  int layer_1_s_x;
  int layer_2_s_x;
  int layer_3_s_x;
  int layer_1_s_x_inv;
  int layer_2_s_x_inv;
  int layer_3_s_x_inv;
  int* layer_1_s_w_inv;
  int* layer_2_s_w_inv;
  int* layer_3_s_w_inv;
  int8_t* layer_1_weight;
  int8_t* layer_2_weight;
  int8_t* layer_3_weight;
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

static uint64_t param_hash_fn(const void *k, void *ctx)
{
  // XXX: This is bad since it only returns 32 bits
  return (uint64_t) jhash(k, sizeof(struct param_key_t), 0);
}

static bool param_equal_fn(const void *a, const void *b, void *ctx)
{
  struct param_key_t* as = (struct param_key_t*) a;
  struct param_key_t* bs = (struct param_key_t*) b;
  return as->id == bs->id;
}


int filter(uint8_t* data, struct hashmap* sessions, struct hashmap* params) {
  u_int64_t ts = get_nsecs();
  u_char *buf;
  int dropcnt = 0;
  struct ether_header *eth;
  struct iphdr *iph;
  struct tcphdr *th;
  struct udphdr *uh;
  struct pkt_key_t pkt_key;
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
      /* struct pkt_key_t *pkt_key_allocated = (struct pkt_key_t*) calloc(1, sizeof(struct pkt_key_t)); */
      int err = hashmap__add(sessions, &pkt_key, zero);
      assert(err == 0);
      bool ret = hashmap__find(sessions, &pkt_key, &pkt_leaf);
      /* int err = hashmap__add(sessions, pkt_key_allocated, zero); */
      /* assert(err == 0); */
      /* bool ret = hashmap__find(sessions, pkt_key_allocated, &pkt_leaf); */
      #ifdef DEBUG_BUILD
      DEBUG("PKT_KEY: %ld\t%ld\t%ld\t%ld\t%ld\n", ts, pkt_key.saddr, pkt_key.daddr, pkt_key.sport, pkt_key.dport);
      DEBUG("PKT_LEAF: %ld\t%ld\t%ld\t%ld\t%ld\n", ts, pkt_leaf->saddr, pkt_leaf->daddr, pkt_leaf->sport, pkt_leaf->dport);
      #endif
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

      int err = hashmap__add(sessions, &pkt_key, pkt_leaf);


      struct param_key_t param_key;
      param_key.id = 1;
      struct param_val_t *param_val = (struct param_val_t*) calloc(1, sizeof(struct param_val_t));
      err = hashmap__find(params, &param_key, &param_val);
      assert(err == 1);
      int layer_1_s_x = param_val->layer_1_s_x;
      int layer_2_s_x = param_val->layer_2_s_x;
      int layer_3_s_x = param_val->layer_3_s_x;
      int layer_1_s_x_inv = param_val->layer_1_s_x_inv;
      int layer_2_s_x_inv = param_val->layer_2_s_x_inv;
      int layer_3_s_x_inv = param_val->layer_3_s_x_inv;
      int* layer_1_s_w_inv = param_val->layer_1_s_w_inv;
      int* layer_2_s_w_inv = param_val->layer_2_s_w_inv;
      int* layer_3_s_w_inv = param_val->layer_3_s_w_inv;
      int8_t* layer_1_weight = param_val->layer_1_weight;
      int8_t* layer_2_weight = param_val->layer_2_weight;
      int8_t* layer_3_weight = param_val->layer_3_weight;

      #ifdef DEBUG_BUILD
      /* DEBUG("FEAT: %ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\n", ts, feat[0], feat[1], feat[2], feat[3], feat[4], feat[5]); */
      #endif

      int indices[1];
      int N = 1;
      run_mlp(feat, N, indices,
          layer_1_s_x, layer_2_s_x, layer_3_s_x,
          layer_1_s_x_inv, layer_2_s_x_inv, layer_3_s_x_inv,
          layer_1_s_w_inv, layer_2_s_w_inv, layer_3_s_w_inv,
          layer_1_weight, layer_2_weight, layer_3_weight);
      if (pkt_key.saddr == SADDR) {
        return -2;
      }
      int i;
      for (i = 0; i < N; i++) {
        if (indices[i] == 1) {
          return TC_CLS_NOMATCH;
        }
        /* printf("%d", indices[i]); */
      }
    }
  }
  EOP: {
    return TC_CLS_DEFAULT;
  }
  return TC_CLS_DEFAULT;
}
void nn_filter(int seconds, int* counter) {
  struct hashmap* params = hashmap__new(param_hash_fn, param_equal_fn, NULL);
  struct hashmap* sessions = hashmap__new(hash_fn, equal_fn, NULL);
  int ret;
  int weight1_inv[16] = {3094, 2362, 140, 871, 1137, 1248, 3548, 1953, 863, 1089, 1108, 1582, 144, 2199, 1059, 1174};
  int weight2_inv[16] = {1022, 895, 1671, 624, 2265, 1567, 1962, 1076, 838, 927, 2378, 984, 769, 3372, 925, 2158};
  int weight3_inv[2] = {2530, 2472};
  int8_t weight1[192] = {4, -5, -22, -10, -10, 16, 0, 0, 38, -1, 26, -3, -118, 4, -69, -6, -127, -127, 9, 127, 127, -18, 64, 24, 56, 91, 5, 63, -62, -111, 36, 5, -6, 31, 117, -4, 106, -61, -1, -14, -127, -23, -61, 8, 90, 1, -6, -44, -64, 21, -127, 36, 111, -127, -3, -38, 116, -37, 127, 127, -1, 44, -127, 127, 0, 0, -88, -77, -108, -11, -8, -56, 11, 111, 76, -49, -65, 36, 25, -12, 1, 11, -40, 13, 13, 7, -1, -23, 26, 2, 6, -3, -101, -6, 4, -19, 10, -31, -56, -59, 0, 37, -24, -72, -29, 1, -56, -68, -123, -44, 28, -41, -5, -86, 111, 3, 41, 48, -127, 59, 49, -63, -36, 57, -111, -83, 0, 79, 4, 6, -93, -40, 8, 29, 1, 24, -14, -3, -47, 23, -27, 2, 29, -51, 11, -12, -62, -20, -32, 39, -38, -127, 20, 60, -58, -25, 72, -34, 9, 18, 11, -63, -101, -77, -22, 67, -45, 4, -58, -127, -28, 12, 71, -127, 6, 55, -2, 27, -127, 45, -19, -16, 4, -2, -11, 36, 19, 15, -127, 14, -25, 58};
  int8_t weight2[256] = {-41, 86, -31, -30, -18, -29, 0, -15, 29, -22, 0, -29, -16, 15, -31, -35, -1, 127, 5, -2, 10, 1, 15, -23, 110, -7, -1, -6, 30, 13, -5, 6, -10, 0, -6, -7, -3, -5, -5, 3, -15, 16, 1, -10, 11, -2, 3, -5, 73, 26, 13, 117, 25, 29, 39, 88, -35, 108, 15, 122, 127, -22, 127, 41, 69, -57, 41, 127, 7, 38, 32, 58, -33, 63, -27, 42, 66, -26, 63, 4, -18, -2, -12, -60, -2, -15, -7, -8, 14, -30, 0, -24, -46, -5, -24, -127, -127, 81, -127, -115, -127, -127, -6, -127, 127, -127, -127, -127, -46, 36, -123, -59, 12, -82, 24, -46, 26, 40, -127, 15, -45, 9, 36, -18, -24, 23, 17, -47, 10, -113, 13, 17, 19, 13, 15, 34, -102, 16, -36, 22, -40, -12, 14, -58, 60, 8, 23, 22, 17, 19, -47, 36, 7, 30, -51, 56, -1, 5, 10, 19, -60, -30, -2, -22, -7, -39, 61, -46, -81, -37, -35, -6, -16, -12, -33, 28, 18, -39, 8, 29, 9, 17, 14, 28, -37, 28, 26, 31, 4, -20, 22, 10, -9, -1, 4, 22, 6, 2, -4, -8, 20, -11, 4, 15, 15, 4, -8, -7, 52, -108, 26, 100, 7, 28, 7, 31, -120, 47, -8, 43, 78, 6, 57, 39, 59, -57, 14, 6, -10, 13, 11, 37, -36, 59, 53, 77, 42, -30, 56, -34, 43, -3, 6, 54, -9, 12, 26, 27, 4, 19, 19, 52, 45, -127, 44, 51};
  int8_t weight3[32] = {49, -47, -87, 86, 69, -64, 44, -46, 72, -73, 58, -58, -103, 104, 47, -36, -59, 64, 42, -40, -127, 127, 41, -51, 15, -28, -114, 117, 47, -50, -113, 114};

  struct param_key_t param_key;
  param_key.id = 1;
  struct param_val_t *param_val = (struct param_val_t*) calloc(1, sizeof(struct param_val_t));
  param_val->layer_1_s_x = 8323072;
  param_val->layer_2_s_x = 2336756;
  param_val->layer_3_s_x = 1056437;
  param_val->layer_1_s_x_inv = 516;
  param_val->layer_2_s_x_inv = 1838;
  param_val->layer_3_s_x_inv = 4066;
  param_val->layer_1_s_w_inv = weight1_inv;
  param_val->layer_2_s_w_inv = weight2_inv;
  param_val->layer_3_s_w_inv = weight3_inv;
  param_val->layer_1_weight = weight1;
  param_val->layer_2_weight = weight2;
  param_val->layer_3_weight = weight3;
  ret = hashmap__add(params, &param_key, param_val);
  struct param_val_t *zero = (struct param_val_t*) calloc(1, sizeof(struct param_val_t));
  ret = hashmap__find(params, &param_key, &zero);
  /* if (ret) { */
  /*   for (int i = 0; i < 16; i++) { */
  /*     printf("%d\t%d\n", i, zero->layer_1_s_w_inv[i]); */
  /*   } */
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
  sockaddr.sll_ifindex  = ifreq.ifr_ifindex;
  sockaddr.sll_family   = PF_PACKET;
  sockaddr.sll_protocol = htons(ETH_P_ALL);
  /* setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifreq, sizeof(ifreq)); */
  if (bind(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr))!=0) {
    perror("bind");
  }

  u_int64_t ts1, ts2;
  u_int64_t cnt = 0;
  u_int64_t start, end;
  u_int64_t one_second = 1000000000;
  u_int64_t interval = one_second * seconds;
  ts1 = get_nsecs();
  start = get_nsecs();
  int i = 0;
  while (true) {
    if ((len=recv(sock, data, sizeof(data), 0)) <= 0) {
      perror("recv");
    } else {
      if (sockaddr.sll_pkttype == PACKET_OUTGOING) {
        continue;
      }
      int flag = filter(data, sessions, params);
      /* printf("%d\n", flag); */
      /* cnt++; */
      if (flag == -2) {
        cnt++;
      }
    }
    ts2 = get_nsecs();
    if (ts2 - ts1 > one_second) {
      printf("%ld\t%ld\n", ts2, cnt);
      counter[i] = cnt * one_second * (ts2 - ts1);
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
