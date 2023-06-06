#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_F_NO_PREALLOC 1
#define PIN_GLOBAL_NS           2
struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

struct lpm_trie_key {
    __u32 prefixlen;
    __u32 ip;
};

struct lpm_trie_val {
    __u32 protocol;
    __u32 start_port;
    __u32 end_port;
};

struct bpf_map_def_pvt SEC("maps") ingress_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size =sizeof(struct lpm_trie_key),
    .value_size = sizeof(struct lpm_trie_val[16]),
    .max_entries = 100,
    .map_flags = BPF_F_NO_PREALLOC,
    .pinning = PIN_GLOBAL_NS,
};

SEC("tc_cls")
int handle_ingress(struct __sk_buff *skb)
{
	struct keystruct trie_key;
	trie_key.prefix_len = 32;
	trie_key.ip[0] = 10; 
	trie_key.ip[1] = 1;
	trie_key.ip[2] = 1;
	trie_key.ip[3] = 100;
	trie_val = bpf_map_lookup_elem(&ingress_map, &trie_key);
	if (trie_val == NULL) {
		return BPF_DROP;
	}
	return BPF_OK;
}

char _license[] SEC("license") = "GPL";
