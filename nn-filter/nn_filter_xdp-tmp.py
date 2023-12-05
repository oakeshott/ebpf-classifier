#!/usr/bin/python3
# -*- coding: utf-8 -*-


from bcc import BPF
from bcc import lib
import sys
import time
import json
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
import joblib
from datetime import datetime

def usage():
    print("Usage: {0} <ifdev> <flag>".format(sys.argv[0]))
    exit(1)

bpf_text = """
#include <uapi/linux/bpf.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#define MAX(a,b) (((a)>(b))?(a):(b))
#define MIN(a,b) (((a)<(b))?(a):(b))
// nn_math.h
#define INT8_MAX_VALUE 127
#define FXP_VALUE 16
#define ROUND_CONST (1 << (FXP_VALUE - 1)) // = 0.5 to before right shifting to improve rounding
// mlp_params.h
#define N 1
#define INPUT_DIM 12
#define H1 16
#define H2 16
#define OUTPUT_DIM 2

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
  u32 sport;
  u32 dport;
  u64 features[6];
};

BPF_ARRAY(out_input, int64_t, 16);
BPF_ARRAY(layer_1_weight, int, LAYER_1_WEIGHT);
BPF_ARRAY(layer_2_weight, int, LAYER_2_WEIGHT);
BPF_ARRAY(layer_3_weight, int, LAYER_3_WEIGHT);
BPF_ARRAY(layer_1_s_w_inv, int, LAYER_1_S_W_INV);
BPF_ARRAY(layer_2_s_w_inv, int, LAYER_2_S_W_INV);
BPF_ARRAY(layer_3_s_w_inv, int, LAYER_3_S_W_INV);
BPF_ARRAY(data_min, int64_t, DATA_MIN);
BPF_ARRAY(data_scale, int64_t, DATA_SCALE);
BPF_ARRAY(layer_1_s_x, int, 1);
BPF_ARRAY(layer_2_s_x, int, 1);
BPF_ARRAY(layer_3_s_x, int, 1);
BPF_ARRAY(layer_1_s_x_inv, int, 1);
BPF_ARRAY(layer_2_s_x_inv, int, 1);
BPF_ARRAY(layer_3_s_x_inv, int, 1);
BPF_TABLE("lru_hash", struct pkt_key_t, struct pkt_leaf_t, sessions, 1024);
BPF_TABLE("prog", int, int, jmp_table, 8);
BPF_HASH(dropcnt, int, u32);


static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
    u32 check = (__force u32)iph->check;

    check += (__force u32)htons(0x0100);
    iph->check = (__force __sum16)(check + (check >= 0xFFFF));
    return --iph->ttl;
}
int forward(struct xdp_md *ctx) {
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;
  struct ethhdr *eth = data;
  u64 nh_off = sizeof(*eth);
  struct iphdr *iph;
  struct tcphdr *th;
  struct udphdr *uh;
  int _zero = 0;
  int64_t _zero64 = 0;

  ethernet: {
    if (data + nh_off > data_end) {
      return XDP_DROP;
    }
    goto ip;
  }
  ip: {
    iph = data + nh_off;
    if ((void*)&iph[1] > data_end)
      return XDP_DROP;
    goto forward;
  }
  forward: {
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
    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
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
  return XDP_PASS;
}
int nn1(struct xdp_md *ctx) {
  unsigned int k, m, _k, _m;
  int _zero = 0;
  int64_t _zero64 = 0;
  int rounded_value, tensor_int, tensor_frac, scale_factor_int, scale_factor_frac, accumulator, s_w_inv, s_x, s_x_inv, out_value;
  int64_t out;
  int8_t weight, x_q[H1];
  // linear_layer(out_input, layer_2_weight, out_h1, layer_2_s_w_inv, dimension_layer2);
  // quantize(x, x_q, layer_2_s_x, layer_2_s_x_inv, N*H1);
  s_x = *((int*)layer_2_s_x.lookup_or_init(&_zero, &_zero));
  s_x_inv = *((int*)layer_2_s_x_inv.lookup_or_init(&_zero, &_zero));
  scale_factor_int = (s_x + ROUND_CONST) >> FXP_VALUE;
  scale_factor_frac = s_x - (scale_factor_int << FXP_VALUE);
  for (m = 0; m < H1; m++) {
    _m = m;
    out = *out_input.lookup_or_init(&_m, &_zero64);
    tensor_int = (out + ROUND_CONST) >> FXP_VALUE;
    if (tensor_int > INT8_MAX_VALUE*s_x_inv) {
      x_q[m] = (int8_t)INT8_MAX_VALUE;
    } else if (tensor_int < -INT8_MAX_VALUE*s_x_inv) {
      x_q[m] = -(int8_t)INT8_MAX_VALUE;
    } else {
      tensor_frac = out - (tensor_int << FXP_VALUE);
      rounded_value = tensor_int*scale_factor_frac + scale_factor_int*tensor_frac;
      rounded_value += (tensor_frac*scale_factor_frac + ROUND_CONST) >> FXP_VALUE;
      rounded_value = ((rounded_value + ROUND_CONST) >> FXP_VALUE) + tensor_int*scale_factor_int;
      x_q[m] = (int8_t)rounded_value; /* store quantized value in output tensor */
    }
  }
  // mat_mult(x_q, w, output, dimension_layer);
  for (m = 0; m < H2; m++) {
    accumulator = 0;
    for (k = 0; k < H1; k++) {
      _k = k*H2 + m;
      weight = *(int8_t*)layer_2_weight.lookup_or_init(&_k, &_zero);
      accumulator += x_q[k] * weight;
    }
    // dequantize_per_row(output, w_scale_factor_inv, layer_2_s_x_inv, N, H2);
    _m = m;
    // s_w_inv = *((int*)layer_2_s_w_inv.lookup_or_init(&_m, &_zero));
    out_value = *layer_2_s_w_inv.lookup_or_init(&_m, &_zero);
    // out_value = s_w_inv * s_x_inv;
    out = (int64_t)accumulator;
    if (out_value > (1 << FXP_VALUE)) {
      out *= ((out_value + ROUND_CONST) >> FXP_VALUE);
    }
    else {
      out = (out_value*out + ROUND_CONST) >> FXP_VALUE;
    }
    // relu(output, N*M);
    out = MAX(out, 0);
    out_input.update(&_m, &out);
  }
  jmp_table.call(ctx, 1);
  return XDP_DROP;
}
int nn2(struct xdp_md *ctx) {
  unsigned int k, m, _k, _m;
  int _zero = 0;
  int64_t _zero64 = 0;
  int rounded_value, tensor_int, tensor_frac, scale_factor_int, scale_factor_frac, accumulator, s_w_inv, s_x, s_x_inv, out_value;
  int64_t out;
  int8_t weight, x_q[H2];
  s_x = *((int*)layer_3_s_x.lookup_or_init(&_zero, &_zero));
  s_x_inv = *layer_3_s_x_inv.lookup_or_init(&_zero, &_zero);
  scale_factor_int = (s_x + ROUND_CONST) >> FXP_VALUE;
  scale_factor_frac = s_x - (scale_factor_int << FXP_VALUE);
  for (m = 0; m < H2; m++) {
    _m = m;
    out = *out_input.lookup_or_init(&_m, &_zero64);
    tensor_int = (out + ROUND_CONST) >> FXP_VALUE;
    if (tensor_int > INT8_MAX_VALUE*s_x_inv) {
      x_q[m] = (int8_t)INT8_MAX_VALUE;
    } else if (tensor_int < -INT8_MAX_VALUE*s_x_inv) {
      x_q[m] = -(int8_t)INT8_MAX_VALUE;
    } else {
      tensor_frac = out - (tensor_int << FXP_VALUE);
      rounded_value = tensor_int*scale_factor_frac + scale_factor_int*tensor_frac;
      rounded_value += (tensor_frac*scale_factor_frac + ROUND_CONST) >> FXP_VALUE;
      rounded_value = ((rounded_value + ROUND_CONST) >> FXP_VALUE) + tensor_int*scale_factor_int;
      x_q[m] = (int8_t)rounded_value; /* store quantized value in output tensor */
    }
  }
  // mat_mult(x_q, w, output, dimension_layer);
  unsigned int argmax_over_cols = 0;
  rounded_value = 0;
  for (m = 0; m < OUTPUT_DIM; m++) {
    accumulator = 0;
    for (k = 0; k < H2; k++) {
      _k = k*OUTPUT_DIM + m;
      weight = *(int8_t*)layer_3_weight.lookup_or_init(&_k, &_zero);
      accumulator += x_q[k] * weight;
    }
    _m = m;
    // s_w_inv = *((int*)layer_3_s_w_inv.lookup_or_init(&_m, &_zero));
    out_value = *layer_3_s_w_inv.lookup_or_init(&_m, &_zero);
    // out_value = s_w_inv * s_x_inv;
    out = (int64_t)accumulator;
    if (out_value > (1 << FXP_VALUE)) {
      out *= ((out_value + ROUND_CONST) >> FXP_VALUE);
    } else {
      out = (out_value*out + ROUND_CONST) >> FXP_VALUE;
    }
    if (out > rounded_value) {
      rounded_value = out;
      argmax_over_cols = m; // return column
    }
  }
  u32 val = 0, *vp;
  vp = dropcnt.lookup_or_init(&_zero, &val);
  *vp += 1;
  if (argmax_over_cols != 0) {
    // return XDP_DROP;
    // jmp_table.call(ctx, 2);
    // return XDP_PASS;
  }
  // jmp_table.call(ctx, 2);
  return XDP_PASS;
  return XDP_DROP;
}
int nn_xdp_drop_packet(struct xdp_md *ctx) {
  int64_t ts = bpf_ktime_get_ns();
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;
  struct ethhdr *eth = data;
  u64 nh_off = sizeof(*eth);
  struct iphdr *iph;
  struct tcphdr *th;
  struct udphdr *uh;
  struct pkt_key_t pkt_key = {};
  int _zero = 0;
  int64_t _zero64 = 0;

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
      default: return XDP_PASS;
    }
  }
  ip: {
    iph = data + nh_off;
    if ((void*)&iph[1] > data_end)
      return XDP_DROP;
    pkt_key.saddr    = iph->saddr;
    pkt_key.daddr    = iph->daddr;
    pkt_key.protocol = iph->protocol;

    switch(iph->protocol) {
      case IPPROTO_TCP: goto tcp;
      // case IPPROTO_UDP: goto udp;
      default: return XDP_PASS;
    }
  }
  tcp: {
    th = (struct tcphdr *)(iph + 1);
    if ((void*)(th + 1) > data_end) {
      return XDP_DROP;
    }
    pkt_key.sport = ntohs(th->source);
    pkt_key.dport = ntohs(th->dest);

    goto nn;
  }
  // udp: {
  //   uh = (struct udphdr *)(iph + 1);
  //   if ((void*)(uh + 1) > data_end) {
  //     return XDP_DROP;
  //   }
  //   pkt_key.sport = ntohs(uh->source);
  //   pkt_key.dport = ntohs(uh->dest);

  //   goto nn;
  // }
  nn: {
    struct pkt_leaf_t *pkt_leaf = sessions.lookup(&pkt_key);
    if (!pkt_leaf) {
      struct pkt_leaf_t zero = {};
      zero.sport = pkt_key.sport;
      zero.dport = pkt_key.dport;
      zero.num_packets = 0;
      zero.last_packet_timestamp = ts;
      sessions.lookup_or_try_init(&pkt_key, &zero);
    }
    if (pkt_leaf != NULL) {
      int64_t x[INPUT_DIM] = {0};
      pkt_leaf->num_packets += 1;
      x[0] = pkt_leaf->sport;
      x[1] = pkt_leaf->dport;
      x[2] = iph->protocol;
      x[3] = ntohs(iph->tot_len);
      x[4] = 0;
      if (pkt_leaf->last_packet_timestamp > 0) {
        x[4] = ts - pkt_leaf->last_packet_timestamp;
      }
      pkt_leaf->last_packet_timestamp = ts;
      x[5] = pkt_key.sport == x[0];

      x[0] <<= FXP_VALUE;
      x[1] <<= FXP_VALUE;
      x[2] <<= FXP_VALUE;
      x[3] <<= FXP_VALUE;
      x[4] <<= FXP_VALUE;
      x[5] <<= FXP_VALUE;

      pkt_leaf->features[0] += x[3];
      pkt_leaf->features[1] += x[4];
      pkt_leaf->features[2] += x[5];

      x[6] = pkt_leaf->features[0]/pkt_leaf->num_packets;
      x[7] = pkt_leaf->features[1]/pkt_leaf->num_packets;
      x[8] = pkt_leaf->features[2]/pkt_leaf->num_packets;

      pkt_leaf->features[3] += abs(x[3] - x[6]);
      pkt_leaf->features[4] += abs(x[4] - x[7]);
      pkt_leaf->features[5] += abs(x[5] - x[8]);

      x[9]  = pkt_leaf->features[3]/pkt_leaf->num_packets;
      x[10] = pkt_leaf->features[4]/pkt_leaf->num_packets;
      x[11] = pkt_leaf->features[5]/pkt_leaf->num_packets;

      unsigned int k, m, _k, _m;

      int64_t out, _data_scale;
      // NORMALIZATION
      for (k = 0; k < INPUT_DIM; k++) {
        unsigned int _k = k;
        out = *data_min.lookup_or_init(&_k, &_zero64);
        _data_scale = *data_scale.lookup_or_init(&_k, &_zero64);
        x[k] = (x[k] - out) * _data_scale;
      }

      int rounded_value, tensor_int, tensor_frac, scale_factor_int, scale_factor_frac, accumulator, s_w_inv, s_x, s_x_inv, out_value;
      int8_t weight, x_q[INPUT_DIM];

      // linear_layer(x, layer_1_weight, out_input, layer_1_s_w_inv, dimension_layer1);
      // quantize(x, x_q, x_scale_factor, x_scale_factor_inv, N*INPUT_DIM);
      s_x = *((int*)layer_1_s_x.lookup_or_init(&_zero, &_zero));
      s_x_inv = *((int*)layer_1_s_x_inv.lookup_or_init(&_zero, &_zero));
      scale_factor_int = (s_x + ROUND_CONST) >> FXP_VALUE;
      scale_factor_frac = s_x - (scale_factor_int << FXP_VALUE);
      for (m = 0; m < INPUT_DIM; m++) {
        tensor_int = (x[m] + ROUND_CONST) >> FXP_VALUE;
        if (tensor_int > INT8_MAX_VALUE*s_x_inv) {
          x_q[m] = (int8_t)INT8_MAX_VALUE;
        } else if (tensor_int < -INT8_MAX_VALUE*s_x_inv) {
          x_q[m] = -(int8_t)INT8_MAX_VALUE;
        } else {
          tensor_frac = x[m] - (tensor_int << FXP_VALUE);
          rounded_value = tensor_int*scale_factor_frac + scale_factor_int*tensor_frac;
          rounded_value += (tensor_frac*scale_factor_frac + ROUND_CONST) >> FXP_VALUE;
          rounded_value = ((rounded_value + ROUND_CONST) >> FXP_VALUE) + tensor_int*scale_factor_int;
          x_q[m] = (int8_t)rounded_value; /* store quantized value in output tensor */
        }
      }
      // mat_mult(x_q, w, output, dimension_layer);
      for (m = 0; m < H1; m++) {
        accumulator = 0;
        for (k = 0; k < INPUT_DIM; k++) {
          _k = k*H1 + m;
          weight = *(int8_t*)layer_1_weight.lookup_or_init(&_k, &_zero);
          accumulator += x_q[k] * weight;
        }
        // dequantize_per_row(output, w_scale_factor_inv, x_scale_factor_inv, N, M);
        _m = m;
        // s_w_inv = *((int*)layer_1_s_w_inv.lookup_or_init(&_m, &_zero));
        out_value = *layer_1_s_w_inv.lookup_or_init(&_m, &_zero);
        // out_value = s_w_inv * s_x_inv;
        out = (int64_t)accumulator;
        if (out_value > (1 << FXP_VALUE)) {
          out *= ((out_value + ROUND_CONST) >> FXP_VALUE);
        } else {
          out = (out_value*out + ROUND_CONST) >> FXP_VALUE;
        }
        // relu(output, N*H1);
        out = MAX(out, 0);
        out_input.update(&_m, &out);
      }
      jmp_table.call(ctx, 0);
    }
  }
  return XDP_PASS;
}

"""

def map_bpf_table(hashmap, values, c_type='int'):
    MAP_SIZE = len(values)
    assert len(hashmap.items()) == MAP_SIZE
    keys = (hashmap.Key * MAP_SIZE)()
    new_values = (hashmap.Leaf * MAP_SIZE)()

    for i in range(MAP_SIZE):
        keys[i] = ct.c_int(i)
        if c_type == 'int':
            new_values[i] = ct.c_int(values[i])
        elif c_type == 'int8_t':
            new_values[i] = ct.c_char(values[i])
        elif c_type == 'longlong':
            new_values[i] = ct.c_longlong(values[i])
        else:
            new_values[i] = ct.c_longlong(values[i])
    hashmap.items_update_batch(keys, new_values)

if __name__ == '__main__':
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        usage()
    device = sys.argv[1]
    resdir = sys.argv[2]
    maptype = "percpu_array"
    flags = 0
    offload_device = None
    if len(sys.argv) == 4:
        if "-S" in sys.argv:
            # XDP_FLAGS_SKB_MODE
            flags |= BPF.XDP_FLAGS_SKB_MODE
        if "-D" in sys.argv:
            # XDP_FLAGS_DRV_MODE
            flags |= BPF.XDP_FLAGS_DRV_MODE
        if "-H" in sys.argv:
            # XDP_FLAGS_HW_MODE
            maptype = "array"
            offload_device = device.encode()
            flags |= BPF.XDP_FLAGS_HW_MODE
    prefix_path = "runs"
    with open('mlp_params.json') as f:
        params = json.load(f)

    bpf_text = bpf_text.replace('LAYER_1_S_W_INV', str(len(params["layer_1_s_w_inv"])))
    bpf_text = bpf_text.replace('LAYER_2_S_W_INV', str(len(params["layer_2_s_w_inv"])))
    bpf_text = bpf_text.replace('LAYER_3_S_W_INV', str(len(params["layer_3_s_w_inv"])))
    bpf_text = bpf_text.replace('LAYER_1_WEIGHT', str(len(params["layer_1_weight"])))
    bpf_text = bpf_text.replace('LAYER_2_WEIGHT', str(len(params["layer_2_weight"])))
    bpf_text = bpf_text.replace('LAYER_3_WEIGHT', str(len(params["layer_3_weight"])))
    bpf_text = bpf_text.replace('DATA_MIN', str(len(params["data_min"])))
    bpf_text = bpf_text.replace('DATA_SCALE', str(len(params["data_scale"])))

    # print(offload_device)

    ret = []
    # b = BPF(text=bpf_text, debug=0,  cflags=["-w", "-DMAPTYPE={maptype}"],
    b = BPF(text=bpf_text, debug=0,  cflags=["-w"],
            # allow_rlimit=True,
            device=offload_device)
    for i in range(0, lib.bpf_num_functions(b.module)):
        func_name = lib.bpf_function_name(b.module, i)
        print(func_name, lib.bpf_function_size(b.module, func_name))
    try:
        fn = b.load_func("nn_xdp_drop_packet", BPF.XDP)
        b.attach_xdp(device, fn, flags=flags)

        jmp_table = b.get_table("jmp_table")
        nn1_fn = b.load_func("nn1", BPF.XDP);
        nn2_fn = b.load_func("nn2", BPF.XDP);
        fwd_fn = b.load_func("forward", BPF.XDP);
        jmp_table[ct.c_int(0)] = ct.c_int(nn1_fn.fd)
        jmp_table[ct.c_int(1)] = ct.c_int(nn2_fn.fd)
        jmp_table[ct.c_int(2)] = ct.c_int(fwd_fn.fd)

        layer_1_weight  = b.get_table("layer_1_weight")
        layer_2_weight  = b.get_table("layer_2_weight")
        layer_3_weight  = b.get_table("layer_3_weight")
        layer_1_s_w_inv = b.get_table("layer_1_s_w_inv")
        layer_2_s_w_inv = b.get_table("layer_2_s_w_inv")
        layer_3_s_w_inv = b.get_table("layer_3_s_w_inv")
        layer_1_s_x     = b.get_table("layer_1_s_x")
        layer_2_s_x     = b.get_table("layer_2_s_x")
        layer_3_s_x     = b.get_table("layer_3_s_x")
        layer_1_s_x_inv = b.get_table("layer_1_s_x_inv")
        layer_2_s_x_inv = b.get_table("layer_2_s_x_inv")
        layer_3_s_x_inv = b.get_table("layer_3_s_x_inv")
        data_min        = b.get_table("data_min")
        data_scale      = b.get_table("data_scale")
        dropcnt          = b.get_table("dropcnt")

        map_bpf_table(layer_1_weight,  params['layer_1_weight'],  'int')
        map_bpf_table(layer_2_weight,  params['layer_2_weight'],  'int')
        map_bpf_table(layer_3_weight,  params['layer_3_weight'],  'int')
        map_bpf_table(layer_1_s_w_inv, params['layer_1_s_w_inv'], 'int')
        map_bpf_table(layer_2_s_w_inv, params['layer_2_s_w_inv'], 'int')
        map_bpf_table(layer_3_s_w_inv, params['layer_3_s_w_inv'], 'int')
        map_bpf_table(layer_1_s_x_inv, params['layer_1_s_x_inv'], 'int')
        map_bpf_table(layer_2_s_x_inv, params['layer_2_s_x_inv'], 'int')
        map_bpf_table(layer_3_s_x_inv, params['layer_3_s_x_inv'], 'int')
        map_bpf_table(layer_1_s_x,     params['layer_1_s_x'],     'int')
        map_bpf_table(layer_2_s_x,     params['layer_2_s_x'],     'int')
        map_bpf_table(layer_3_s_x,     params['layer_3_s_x'],     'int')
        map_bpf_table(data_min,        params['data_min'],        'int64_t')
        map_bpf_table(data_scale,      params['data_scale'],      'int64_t')
        prev = 0
        interval = 110
        start = datetime.now()
        while True:
            try:
                dropcnt.clear()
                time.sleep(1)
                for k, v in dropcnt.items():
                    # print(v.value)
                    ret.append(v.value)
                end = datetime.now()
                duration = (end - start).total_seconds()
                if duration > interval:
                    break
            except KeyboardInterrupt:
                break
    finally:
        b.remove_xdp(device, flags)
        filename = f"{resdir}/xdp.log"
        if "-S" in sys.argv:
            # XDP_FLAGS_SKB_MODE
            filename = f"{resdir}/xdp-skb.log"
        if "-D" in sys.argv:
            filename = f"{resdir}/xdp-drv.log"
        with open (filename, 'w') as f:
            for d in ret:
                f.write(f"{d}\n")

