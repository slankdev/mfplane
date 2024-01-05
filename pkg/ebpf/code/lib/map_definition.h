#ifndef _MAP_DEFINITION_H_
#define _MAP_DEFINITION_H_

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(key_size, sizeof(struct trie4_key));
  __uint(value_size, sizeof(struct trie4_val));
  __uint(max_entries, 50);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, fib4) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(key_size, sizeof(struct trie6_key));
  __uint(value_size, sizeof(struct trie6_val));
  __uint(max_entries, 50);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, fib6) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(key_size, sizeof(struct overlay_fib4_key));
  __uint(value_size, sizeof(struct overlay_fib4_val));
  __uint(max_entries, 100);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, overlay_fib4) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct flow_processor);
  __uint(max_entries, RING_SIZE * MAX_RULES);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, lb_backend) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct in6_addr);
  __uint(max_entries, 1);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, encap_source) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, NAT_CACHE_MAX_RULES);
  __type(key, struct addr_port);
  __type(value, struct addr_port_stats);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, nat_out) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, NAT_CACHE_MAX_RULES);
  __type(key, struct addr_port);
  __type(value, struct addr_port_stats);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, nat_ret) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65535);
  __type(key, struct mf_redir_rate_stat_key);
  __type(value, struct mf_redir_rate_stat_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, rate_stats) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));   // TODO: nos sure it is needed or not
  __uint(value_size, sizeof(__u32)); // TODO: nos sure it is needed or not
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, events) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(key_size, sizeof(struct neigh_key));
  __uint(value_size, sizeof(struct neigh_val));
  __uint(max_entries, 100);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, neigh) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(struct counter_val));
  __uint(max_entries, 1);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, counter) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(struct metadata));
  __uint(max_entries, 1);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, metadata) SEC(".maps");

#endif /* _MAP_DEFINITION_H_ */
