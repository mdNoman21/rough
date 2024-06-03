#include <stdio.h>
#include <xdp/libxdp.h>
#include <unistd.h> // sleep
#include <stdlib.h> // exit
#include <signal.h> // SIG*
#include <net/if.h> // if_nametoindex
#include <arpa/inet.h>
#include <netdb.h>

#define BUFFER_SIZE 32

union ip_str {
    __u8 ip_arr[4];
    __u32 ip;
};

struct ip_list {
    int count;
    union ip_str* ips;
};

// Global variables
static int ifindex;
struct xdp_program *prog = NULL;
int ret = 1;

// Detach XDP program on exit
static void int_exit(int sig) {
    if (!ret) {
        xdp_program__detach(prog, ifindex, XDP_MODE_SKB, 0);
    }
    xdp_program__close(prog);
    printf("\n");
    exit(0);
}

void format_bytes(union ip_str* ip_obj, char* buffer) {
    snprintf(buffer, BUFFER_SIZE, "%u.%u.%u.%u", ip_obj->ip_arr[0], ip_obj->ip_arr[1], ip_obj->ip_arr[2], ip_obj->ip_arr[3]);
}

struct ip_list* get_ip_address(char* domain_name) {
    // Get host information using gethostbyname
    struct hostent *hostinfo = gethostbyname(domain_name);
    if (hostinfo == NULL) {
        herror("gethostbyname");
        exit(1);
    }

    // Check for multiple IP addresses (not always guaranteed)
    if (hostinfo->h_addr_list[0] == NULL) {
        fprintf(stderr, "No IP address found for %s\n", domain_name);
        exit(1);
    }

    // Calculate the number of IP addresses
    int count = 0;
    for (int i = 0; hostinfo->h_addr_list[i] != NULL; i++) count++;

    // Store all IP addresses
    union ip_str* my_ips = (union ip_str*)malloc(count * sizeof(union ip_str));
    for (int i = 0; i < count; i++) {
        struct in_addr *address = (struct in_addr *)hostinfo->h_addr_list[i];
        my_ips[i].ip = address->s_addr;
    }

    // Return the IP addresses list
    struct ip_list* my_ip_list = (struct ip_list*)malloc(sizeof(struct ip_list));
    my_ip_list->count = count;
    my_ip_list->ips = my_ips;

    return my_ip_list;
}

static void poll_stats(int map_fd, int interval, struct ip_list* my_ip_list) {
    int count = my_ip_list->count;
    union ip_str *ips = my_ip_list->ips;

    int ncpus = libbpf_num_possible_cpus();
    if (ncpus < 0) {
        printf("Failed to get possible cpus\n");
        return;
    }

    while (1) {
        sleep(interval);
        printf("\033[H\033[J");
        for (int i = 0; i < count; i++) {
            long values[ncpus];
            if (bpf_map_lookup_elem(map_fd, &ips[i], values) == 0) {
                long num = 0;
                for (int j = 0; j < ncpus; j++) {
                    num += values[j];
                }
                char buff[BUFFER_SIZE];
                format_bytes(&ips[i], buff);
                printf("IP: %s, Count: %ld\n", buff, num);
            }
        }
        fflush(stdout);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <domain-name>\n", argv[0]);
        exit(1);
    }

    // Get IP addresses
    struct ip_list* my_ip_list = get_ip_address(argv[1]);
    int count = my_ip_list->count;
    union ip_str *ips = my_ip_list->ips;

    const char* filename = "xdp_block.o";
    const char* secname = "xdp"; // section name

    // Interface name
    // Command: ip a
    const char* ifname = "eth0";

    // Interface name to index
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        printf("Failed to get interface index from interface name\n");
        return 1;
    }

    // Load XDP program
    prog = xdp_program__open_file(filename, secname, NULL);
    if (!prog) {
        printf("Failed to load XDP program\n");
        return 1;
    }

    // Attach XDP program to interface with SKB mode
    // Please set ulimit if you got an -EPERM error
    ret = xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0);
    if (ret) {
        printf("Failed to attach XDP program to %d interface\n", ifindex);
        return ret;
    }

    int map_fd;
    struct bpf_object *bpf_obj;
    bpf_obj = xdp_program__bpf_obj(prog);
    map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "blocked_ips");
    if (map_fd < 0) {
        printf("Error, get map fd from bpf obj failed\n");
        return map_fd;
    }

    // Add blocked IPs to the map
    for (int i = 0; i < count; i++) {
        long values[2] = {0, 0};
        if (bpf_map_update_elem(map_fd, &ips[i], values, BPF_ANY) < 0) {
            printf("Failed to add IP to the map\n");
            return 1;
        }
    }

    // Detach XDP program when it is interrupted or killed
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    poll_stats(map_fd, 1, my_ip_list);

    // Sleep indefinitely
    while (1) sleep(1);

    return 0;
}