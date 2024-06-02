//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>
#include "../packet.h"

#define IP_VERSION 4

#define POD_MAX_AMOUNT 1024

char __license[] SEC("license") = "Dual MIT/GPL";

// Ring Buffer event. I.E., the information that is read by the userspace program.
struct event
{
  unsigned char saddr[4];
  unsigned char daddr[4];
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

/*
  Ring Buffer. In eBPF maps are used to communicate with other processes (both other eBPF programs and userspace programs)
  Events submitted to a Ring Buffer map, can be read by other processes by listening to the "map" or in reality the
  file descriptor
*/
struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 64 * 4096);
} event_buff SEC(".maps");

// Hash Map key: Source IPv4 address and Destination IPv4 address
struct key
{
  __u32 saddr;
  __u32 daddr;
};

// 
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct key);
  __type(value, __u32);
  // NOTE: Maximum of 1024 pods possible (PoC)
  __uint(max_entries, POD_MAX_AMOUNT);
} network_policy_map SEC(".maps");

static __always_inline __u16 validate_source_and_destination_path(__u32 saddr, __u32 daddr);
static __always_inline void initialize_notify_event(struct iphdr *iph, struct event *notify_event);

SEC("tc")
int policy_check(struct __sk_buff *skb)
{

  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  // Initializes all packet structures
  struct hdr_cursor cursor;
  cursor.pos = data;
  struct ethhdr *eth = get_eth_packet(data_end, &cursor);
  struct iphdr *iph = 0;
  struct iphdr *iph_inner = 0;
  struct event *notify_event = 0;

  if(eth != 0 && bpf_ntohs(eth->h_proto) == ETH_P_IP){
    iph = get_ip_packet(data_end, &cursor);
  }

  if(iph == 0)
    return TC_ACT_OK;

  if(iph != 0 && iph->protocol == IPPROTO_IPIP){
    iph_inner = get_ip_packet(data_end, &cursor);

    if(iph_inner != 0)
      iph = iph_inner;
  }

__u16 is_valid = validate_source_and_destination_path(iph->saddr, iph->daddr);

if(is_valid == 0){
  notify_event = bpf_ringbuf_reserve(&event_buff, sizeof(struct event), 0);

  if(notify_event != 0){
    initialize_notify_event(iph, notify_event);
    bpf_ringbuf_submit(notify_event, 0);
  }

  return TC_ACT_SHOT;
}

return TC_ACT_OK;
}


static __always_inline __u16 validate_source_and_destination_path(__u32 saddr, __u32 daddr){
  // bpf_printk("Searching for policy. Saddr: %d, Daddr: %d", bpf_ntohl(saddr), bpf_ntohl(daddr));
  struct key key = {bpf_ntohl(saddr), bpf_ntohl(daddr)};
  __u32 * path_allowed = bpf_map_lookup_elem(&network_policy_map, &key);

  if(path_allowed != 0 && *path_allowed == 1){
    return 1;
  }

  if(path_allowed != 0 && *path_allowed == 0){
    return 0;
  }

  struct key key_ingress = {0, bpf_ntohl(daddr)};
  __u32 * ingress_allowed = bpf_map_lookup_elem(&network_policy_map, &key_ingress);

  if(ingress_allowed != 0 && *ingress_allowed == 0)
    return 0;

  struct key key_egress = {bpf_ntohl(saddr), 0};
  __u32 * egress_allowed = bpf_map_lookup_elem(&network_policy_map, &key_egress);

  if(egress_allowed != 0 && *egress_allowed == 0)
    return 0;

  return 1;
}

static __always_inline void initialize_notify_event(struct iphdr *iph, struct event *notify_event){
  // Initialize the destination address
  notify_event->daddr[0] = (unsigned char)(iph->daddr & 0xFF);
	notify_event->daddr[1] = (unsigned char)(iph->daddr>>8) & 0xFF;
	notify_event->daddr[2] = (unsigned char)(iph->daddr>>16) & 0xFF;
	notify_event->daddr[3] = (unsigned char)(iph->daddr>>24) & 0xFF;

  // Initialize the source address
	notify_event->saddr[0] = (unsigned char)(iph->saddr & 0xFF);
	notify_event->saddr[1] = (unsigned char)(iph->saddr>>8) & 0xFF;
	notify_event->saddr[2] = (unsigned char)(iph->saddr>>16) & 0xFF;
	notify_event->saddr[3] = (unsigned char)(iph->saddr>>24) & 0xFF;
}
