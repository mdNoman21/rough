#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h> // struct iphdr
#include <bpf/bpf_endian.h> // bpf_ntohs

// warning: declaration of 'struct bpf_map' will not be visible outside of this function [-Wvisibility]
// #include <bpf/libbpf.h>
struct bpf_map;

union ip_str {
    __u8 ip_arr[4];
    __u32 ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, union ip_str);
    __type(value, long);
    __uint(max_entries, 64);
} blocked_ips SEC(".maps");

struct callback_ctx {
    union ip_str *ip;
    int output;
};

static __u64 check_filter(struct bpf_map *map, __u32 *key, __u64 *val, struct callback_ctx *data) {
    if (data->ip->ip == *key) {
        data->output = XDP_DROP;
        __sync_fetch_and_add(val, 1);
    }
    return 0;
}

SEC("xdp")
int xdp_block_prog(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    // Check if the packet is large enough
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;
    
    struct ethhdr *eth = data;
    
    // We only need IP Packets
    // eth->h_proto is 2 bytes
    // bpf_ntohs takes care of byte order
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Check if the packet is large enough
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_DROP;

    struct iphdr *iph = data + sizeof(struct ethhdr);

    // We only need TCP Packets
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Get IP address
    union ip_str ip = {
        .ip = iph->saddr,
    };

    // Create a context
    struct callback_ctx ctx_data = {
        .ip = &ip,
        .output = XDP_PASS,
    };

    // Check if the IP address is blocked
    bpf_for_each_map_elem(&blocked_ips, check_filter, &ctx_data, 0);

    return ctx_data.output;
}

char _license[] SEC("license") = "GPL";