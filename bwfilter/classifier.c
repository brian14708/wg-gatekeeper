// +build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

//

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/* the maximum delay we are willing to add (drop packets beyond that) */
#define TIME_HORIZON_NS (2000 * 1000 * 1000)
#define NS_PER_SEC 1000000000
#define ECN_HORIZON_NS 5000000
#define THROTTLE_RATE_BPS (1 * 1000 * 1000)

#define uint16_t __u16
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

struct client_info {
  uint32_t account_id;
  uint32_t throttle_in_rate_bps;
  uint32_t throttle_out_rate_bps;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, uint32_t);
  __type(value, struct client_info);
  __uint(max_entries, 65536);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} client_account_map SEC(".maps");

struct account_metric {
  uint32_t bytes_in;
  uint32_t bytes_out;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, uint32_t); // account_id
  __type(value, struct account_metric);
  __uint(max_entries, 65536);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} account_metric_map SEC(".maps");

enum flags {
  FLAGS_OUT = 1,
};

static inline void get_flow_key(struct __sk_buff *skb, struct client_info **cli,
                                int *flags) {
  *flags = FLAGS_OUT;
  *cli = NULL;

  struct iphdr *iph = (void *)(long)skb->data;
  if ((void *)(iph + 1) > (void *)(long)skb->data_end) {
    return;
  }
  if (iph->version != 4) {
    return;
  }

  uint32_t ip = bpf_ntohl(iph->saddr);
  *cli = (struct client_info *)bpf_map_lookup_elem(&client_account_map, &ip);

  if (*cli == NULL) {
    ip = bpf_ntohl(iph->daddr);
    *cli = (struct client_info *)bpf_map_lookup_elem(&client_account_map, &ip);
    *flags &= ~FLAGS_OUT;
  }
}

static inline int throttle_flow(int key, uint64_t limit,
                                struct __sk_buff *skb) {
  uint64_t *last_tstamp = bpf_map_lookup_elem(&flow_map, &key);
  uint64_t delay_ns = ((uint64_t)skb->wire_len) * NS_PER_SEC / limit;
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
  struct client_info *cli;
  int flag;
  get_flow_key(skb, &cli, &flag);

  if (cli == NULL) {
    return throttle_flow(0, THROTTLE_RATE_BPS, skb);
  }

  int act;
  if (flag & FLAGS_OUT) {
    act = throttle_flow((1 << 31) | cli->account_id,
                        cli->throttle_out_rate_bps / 8, skb);
  } else {
    act = throttle_flow(cli->account_id, cli->throttle_in_rate_bps / 8, skb);
  }

  if (act != TC_ACT_OK) {
    return act;
  }

  struct account_metric *metric =
      bpf_map_lookup_elem(&account_metric_map, &cli->account_id);
  if (metric == NULL) {
    struct account_metric value = {
        .bytes_in = (flag & FLAGS_OUT) ? 0 : skb->wire_len,
        .bytes_out = (flag & FLAGS_OUT) ? skb->wire_len : 0,
    };

    bpf_map_update_elem(&account_metric_map, &cli->account_id, &value, BPF_ANY);
  } else {
    struct account_metric value = {
        .bytes_in = metric->bytes_in + ((flag & FLAGS_OUT) ? 0 : skb->wire_len),
        .bytes_out =
            metric->bytes_out + ((flag & FLAGS_OUT) ? skb->wire_len : 0),
    };

    bpf_map_update_elem(&account_metric_map, &cli->account_id, &value,
                        BPF_EXIST);
  }

  return act;
}
