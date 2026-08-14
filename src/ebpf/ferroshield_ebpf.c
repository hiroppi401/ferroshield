#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define bpf_ntohs(x) __builtin_bswap16(x)

char LICENSE[] SEC("license") = "GPL";

// Struct to send connection event to userspace
struct ConnectEvent {
    __u32 pid;
    __u32 saddr;
    __u16 sport;
    __u16 dport;
    char comm[16];
} __attribute__((packed));

// Map for blacklisted IPs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
} BLACKLIST_IPS SEC(".maps");

// Map for blacklisted domains
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __uint(key_size, 64);
    __uint(value_size, sizeof(__u8));
} BLACKLIST_DOMAINS SEC(".maps");

// Perf Event Array for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} EVENTS SEC(".maps");

// Tracepoint structure for syscall entry
struct sys_enter_connect_args {
    unsigned long long unused;
    long int id;
    unsigned long int args[6];
};

SEC("tracepoint/syscalls/sys_enter_connect")
int sys_enter_connect(struct sys_enter_connect_args *ctx) {
    struct sockaddr_in *uservaddr = (struct sockaddr_in *)ctx->args[1];
    if (!uservaddr) {
        return 0;
    }

    // Read the address family from userspace
    short family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), &uservaddr->sin_family) != 0) {
        return 0;
    }

    // We only monitor IPv4 connections
    if (family == AF_INET) {
        struct sockaddr_in addr_in;
        if (bpf_probe_read_user(&addr_in, sizeof(addr_in), uservaddr) != 0) {
            return 0;
        }

        __u32 ip = addr_in.sin_addr.s_addr;
        __u8 *blocked = bpf_map_lookup_elem(&BLACKLIST_IPS, &ip);
        if (blocked) {
            // Trigger alert event to userspace
            struct ConnectEvent event = {};
            event.pid = bpf_get_current_pid_tgid() >> 32;
            event.saddr = ip;
            event.sport = bpf_ntohs(addr_in.sin_port);
            event.dport = bpf_ntohs(addr_in.sin_port);
            bpf_get_current_comm(&event.comm, sizeof(event.comm));

            bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &event, sizeof(event));
        }
    }

    return 0;
}

SEC("uprobe/getaddrinfo")
int getaddrinfo(struct pt_regs *ctx) {
    // PT_REGS_PARM1 gets the first parameter (domain name string 'node')
    const char *node = (const char *)PT_REGS_PARM1(ctx);
    if (!node) {
        return 0;
    }

    char domain[64] = {};
    if (bpf_probe_read_user_str(domain, sizeof(domain), node) < 0) {
        return 0;
    }

    // Check if the domain name exists in our blacklist map
    __u8 *blocked = bpf_map_lookup_elem(&BLACKLIST_DOMAINS, domain);
    if (blocked) {
        // Send a notification event with saddr = 0 to signal a domain violation
        struct ConnectEvent event = {};
        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.saddr = 0; // 0 indicates a blocked domain name lookup
        event.sport = 0;
        event.dport = 0;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));

        bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }

    return 0;
}
