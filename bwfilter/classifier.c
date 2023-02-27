// +build ignore

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

//

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/* the maximum delay we are willing to add (drop packets beyond that) */
#define TIME_HORIZON_NS (2000 * 1000 * 1000)
#define NS_PER_SEC 1000000000
#define ECN_HORIZON_NS 5000000
#define THROTTLE_RATE_BPS (1 * 1000 * 1000)

#define uint32_t __u32
#define uint64_t __u64

/* flow_key => last_tstamp timestamp used */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, uint32_t);
  __type(value, uint64_t);
  __uint(max_entries, 65536);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} flow_map SEC(".maps");

static inline uint32_t get_flow_key(struct __sk_buff *skb) {
  struct iphdr *iph = (void *)(long)skb->data;
  uint32_t key = 0;

  if ((void *)(iph + 1) > (void *)(long)skb->data_end) {
    return 0;
  }

  if (iph->version == 4) {
    key = iph->saddr;
  }

  return key;
}

static inline int throttle_flow(struct __sk_buff *skb) {
  int key = 0;
  uint64_t *last_tstamp = bpf_map_lookup_elem(&flow_map, &key);
  uint64_t delay_ns =
      ((uint64_t)skb->wire_len) * NS_PER_SEC / THROTTLE_RATE_BPS;
  uint64_t now = bpf_ktime_get_ns();
  uint64_t tstamp, next_tstamp = 0;

#if 0
  tstamp = skb->tstamp;
  if (tstamp < now) {
    tstamp = now;
  }
#else
  tstamp = now;
#endif

  if (last_tstamp) {
    next_tstamp = *last_tstamp + delay_ns;
  }

  /* should we throttle? */
  if (next_tstamp <= tstamp) {
    if (bpf_map_update_elem(&flow_map, &key, &tstamp, BPF_ANY)) {
      return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
  }

  /* do not queue past the time horizon */
  if (next_tstamp - now >= TIME_HORIZON_NS) {
    return TC_ACT_SHOT;
  }

  /* set ecn bit, if needed */
  if (next_tstamp - now >= ECN_HORIZON_NS) {
    bpf_skb_ecn_set_ce(skb);
  }

  if (bpf_map_update_elem(&flow_map, &key, &next_tstamp, BPF_EXIST)) {
    return TC_ACT_SHOT;
  }
  skb->tstamp = next_tstamp;

  return TC_ACT_OK;
}

SEC("classifier") int tc_prog(struct __sk_buff *skb) {
  return throttle_flow(skb);
}
