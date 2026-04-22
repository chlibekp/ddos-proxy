//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define SEC(NAME) __attribute__((section(NAME), used))

// Helper for byte swapping if needed (e.g. __builtin_bswap16)
#define bpf_htons(x) ((__u16)(__builtin_constant_p(x) ? \
    (((__u16)(x) & 0xffU) << 8) | (((__u16)(x) & 0xff00U) >> 8) : \
    __builtin_bswap16(x)))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

struct bpf_map_def SEC("maps") blocklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 100000,
};

SEC("xdp")
int xdp_drop_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u8 *blocked = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (blocked) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual MIT/GPL";
