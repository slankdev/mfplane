#ifndef _MAP_DEFINITION_H_
#define _MAP_DEFINITION_H_

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
