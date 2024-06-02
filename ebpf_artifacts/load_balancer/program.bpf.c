//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>
#include "../packet.h"

#define IP_VERSION 4

#define SERVICE_MAX 1024

#define ENDPOINT_MAX 16

#define FLOW_MAX 4096

char __license[] SEC("license") = "Dual MIT/GPL";

// Ring Buffer event. I.E., the information that is read by the userspace program.
struct event
{
  unsigned char saddr[4];
  unsigned char daddr[4];
  // Original destinatin address
  unsigned char odaddr[4];
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

struct endpoints_meta {
  __u16 endpoints_amount;
};

struct endpoint
{
  __u32 ip;
  __u16 port;
};

struct flow_endpoint
{
  __u32 ip;
  __u16 port;
  __u8 is_destination;
};

// Padding different between go application in userspace 0x00 (userspace) -> 0xff (eBPF)
struct key
{
  __u32 ip;
  __u32 port;
};

struct flow_key
{
  __u32 saddr;
  __u32 sport;
  __u32 daddr;
  __u32 dport;
};

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

// Port Map. Key: Index 0-1024, Value: Port struct (port and target port).
struct endpoints_array
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct endpoint);
  __uint(max_entries, ENDPOINT_MAX);
} endpoints SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct key);
  __type(value, struct endpoints_meta);
  // NOTE: Maximum of 1024 services possible
  __uint(max_entries, SERVICE_MAX);
} service_ref_meta_map SEC(".maps");

// Port Map. Key: Destionation IP address and port, Value: An BPF array containing all endpoints for a referenced service resource.
struct
{
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __type(key, struct key);
  // NOTE: Maximum of 1024 services possible
  __uint(max_entries, SERVICE_MAX);
  __array(values, struct endpoints_array);
} service_refs_map SEC(".maps");


// Reason for not requiring to delete entries after they are over -> might cause inconsistencies
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct flow_key);
  __type(value, struct flow_endpoint);
  // Two entries per flow, see store_flows(struct iphdr *iph, __u16 sport, __u16 dport, struct endpoint * ep)
  __uint(max_entries, 2*FLOW_MAX);
} flow_map SEC(".maps");

static __always_inline void select_service_endpoint(struct key *key, struct endpoint ** ep);
static __always_inline void search_flows(struct iphdr *iph, __u16 sport, __u16 dport, struct flow_endpoint ** ep);
static __always_inline long store_flows(struct iphdr *iph, __u16 sport, __u16 dport, struct endpoint * ep);
static __always_inline long long swap_destination(struct __sk_buff *skb, struct iphdr *old_iph, struct iphdr *iph, struct tcphdr *tcph, struct udphdr *udph, struct endpoint * ep);
static __always_inline long long swap_source(struct __sk_buff *skb, struct iphdr *old_iph, struct iphdr *iph, struct tcphdr *tcph, struct udphdr *udph, struct flow_endpoint * ep);
static __always_inline void initialize_notify_event(struct iphdr *iph, struct event *notify_event, struct endpoint *endpoint);

SEC("tc")
int reverse_load_balance(struct __sk_buff *skb){
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  // Initializes all packet structures
  struct hdr_cursor cursor;
  cursor.pos = data;
  struct ethhdr *eth = get_eth_packet(data_end, &cursor);
  struct iphdr *iph = 0;
  struct tcphdr *tcph = 0;
  struct udphdr *udph = 0;
  struct flow_endpoint *r_ep = 0;
  __u16 dport = 0;
  __u16 sport = 0;

  load_l3_and_l4_packet(skb, &iph, &tcph, &udph);

  if(iph == 0)
    return TC_ACT_OK;

  if(tcph == 0 && udph == 0)
    return TC_ACT_OK;

  if(tcph != 0){
    dport = tcph->dest;
    sport = tcph->source;
  }

  if(udph != 0){
    dport = udph->dest;
    sport = udph->source;
  }

  search_flows(iph, sport, dport, &r_ep);
  if(r_ep != 0){
    struct iphdr old_iph = *iph;
    if(r_ep->is_destination == 1)
      return TC_ACT_OK;

    swap_source(skb, &old_iph, iph, tcph, udph, r_ep);

    // // Copies the packet to same interface (egress) -> This is only used for debugging/explanation
    // bpf_clone_redirect(skb, skb->ifindex, 0);
    // // Discards the packet
    // return TC_ACT_SHOT;
  }

  return TC_ACT_OK;
}

SEC("tc")
int load_balance(struct __sk_buff *skb)
{
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  // Initializes all packet structures
  struct hdr_cursor cursor;
  cursor.pos = data;
  struct ethhdr *eth = get_eth_packet(data_end, &cursor);
  struct iphdr *iph = 0;
  struct tcphdr *tcph = 0;
  struct udphdr *udph = 0;
  struct event *notify_event = 0;
  struct endpoint *ep = 0;
  struct flow_endpoint *r_ep = 0;
  __u16 dport = 0;
  __u16 sport = 0;

  load_l3_and_l4_packet(skb, &iph, &tcph, &udph);

  if(iph == 0)
    return TC_ACT_OK;

  if(tcph == 0 && udph == 0)
    return TC_ACT_OK;

  if(tcph != 0){
    dport = tcph->dest;
    sport = tcph->source;
  }

  if(udph != 0){
    dport = udph->dest;
    sport = udph->source;
  }

  search_flows(iph, sport, dport, &r_ep);
  if(r_ep != 0){
    
    struct iphdr old_iph = *iph;
    if(r_ep->is_destination != 1)
      return TC_ACT_OK;

    struct endpoint endpoint = {r_ep->ip, r_ep->port};
    swap_destination(skb, &old_iph, iph, tcph, udph, &endpoint);

    // // Copies the packet to same interface (ingress) -> This is only used for debugging/explanation
    // bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
    // // Discards the packet
    // return TC_ACT_SHOT;
  } else {
    //TODO: Check if the first byte is equal to 10 (all service endpoints starts with 10)
    struct key key = {bpf_ntohl(iph->daddr), bpf_ntohs(dport)};

    select_service_endpoint(&key, &ep);

    if(ep != 0){
      store_flows(iph, sport, dport, ep);
      struct iphdr old_iph = *iph;
      swap_destination(skb, &old_iph, iph, tcph, udph, ep);

      // Reload the iphdr struct after updating the destination IP address and checksum
      load_ip_packet(skb, &iph);
      if(iph != 0){
        notify_event = bpf_ringbuf_reserve(&event_buff, sizeof(struct event), 0);

        if(notify_event == 0)
          return TC_ACT_OK;

        initialize_notify_event(&old_iph, notify_event, ep);
        // Submits the initialized event
        bpf_ringbuf_submit(notify_event, 0);
      }

      // // Copies the packet to same interface (ingress) -> This is only used for debugging/explanation
      // bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
      // // Discards the packet
      // return TC_ACT_SHOT;
    }
  }

  return TC_ACT_OK;
}


static __always_inline void select_service_endpoint(struct key *key, struct endpoint ** ep)
{
  if(key != 0){
    // Combines the source IP address with the destination IP address, and uses it to lookup
    int *map_ptr = bpf_map_lookup_elem(&service_refs_map, key);
    if(map_ptr != 0)
    {
      struct endpoints_meta *meta = bpf_map_lookup_elem(&service_ref_meta_map, key);

      if(meta != 0 && meta->endpoints_amount > 0){
        
        // Select a random index, that is to be used to select the endpoint for the eBPF map
        // NOTE: This part is what achieves the load balancing (randomly)
        // The Kubernetes Service resource also provides functionality for session affinity https://kubernetes.io/docs/reference/networking/virtual-ips/#session-affinity
        __u32 rand = (bpf_get_prandom_u32() % meta->endpoints_amount);

        // Lookup the endpoint element    
        *ep = bpf_map_lookup_elem(map_ptr, &rand);
      }
    }
  }
}

static __always_inline void search_flows(struct iphdr *iph, __u16 sport, __u16 dport, struct flow_endpoint ** ep){
  struct flow_key rkey = {bpf_ntohl(iph->saddr), bpf_ntohs(sport), bpf_ntohl(iph->daddr), bpf_ntohs(dport)};

  *ep = bpf_map_lookup_elem(&flow_map, &rkey);
}

static __always_inline long store_flows(struct iphdr *iph, __u16 sport, __u16 dport, struct endpoint * ep){
  struct flow_key rkey1 = {bpf_ntohl(iph->saddr), bpf_ntohs(sport), bpf_ntohl(iph->daddr), bpf_ntohs(dport)};
  struct flow_endpoint rep1 = {ep->ip, ep->port, 1};

  bpf_map_update_elem(&flow_map, &rkey1, &rep1, BPF_NOEXIST);

  // Reverse flow
  struct flow_key rkey2 = {ep->ip, ep->port, bpf_ntohl(iph->saddr), bpf_ntohs(sport)};
  struct flow_endpoint rep2 = {bpf_ntohl(iph->daddr), bpf_ntohs(dport), 0};

  return bpf_map_update_elem(&flow_map, &rkey2, &rep2, BPF_NOEXIST);
}

static __always_inline long long swap_destination(struct __sk_buff *skb, struct iphdr *old_iph, struct iphdr *iph, struct tcphdr *tcph, struct udphdr *udph, struct endpoint * ep){
  // Swap L4 destination
  if(tcph != 0){
    struct tcphdr old_tcph = *tcph;
    __u16 new_port = bpf_ntohs(ep->port);
    swap_destination_tcp_port(skb, new_port);

    load_l3_and_l4_packet(skb, &iph, &tcph, &udph);

    if(tcph != 0)
      update_tcp_csum(skb, &old_tcph, tcph);
  } else {
    struct udphdr old_udph = *udph;
    __u16 new_port = bpf_ntohs(ep->port);
    swap_destination_udp_port(skb, new_port);

    load_l3_and_l4_packet(skb, &iph, &tcph, &udph);

    if(iph != 0 && udph != 0)
      update_udp_csum(skb, &old_udph, udph);
  }

  load_ip_packet(skb, &iph);
  if(iph != 0){
    // Swap IP Address (L3):
    __u32 new_daddr = bpf_ntohl(ep->ip);
    long long result = swap_destination_ip_address(skb, new_daddr);

    if(result < 0)
      return result;

    load_ip_packet(skb, &iph);
    
    if(iph != 0){
      result = update_l3_csum(skb, old_iph, iph);

      load_ip_packet(skb, &iph);
    }

    return result;
  }

  return -1;
}

static __always_inline long long swap_source(struct __sk_buff *skb, struct iphdr *old_iph, struct iphdr *iph, struct tcphdr *tcph, struct udphdr *udph, struct flow_endpoint * ep){
  // Swap L4 destination
  if(tcph != 0){
    struct tcphdr old_tcph = *tcph;
    __u16 new_port = bpf_ntohs(ep->port);
    swap_source_tcp_port(skb, new_port);

    load_l3_and_l4_packet(skb, &iph, &tcph, &udph);

    if(tcph != 0)
      update_tcp_csum(skb, &old_tcph, tcph);
  } else {
    struct udphdr old_udph = *udph;
    __u16 new_port = bpf_ntohs(ep->port);
    swap_source_udp_port(skb, new_port);

    load_l3_and_l4_packet(skb, &iph, &tcph, &udph);

    if(udph != 0)
      update_udp_csum(skb, &old_udph, udph);
  }

  load_ip_packet(skb, &iph);
  if(iph != 0){
    // Swap IP Address (L3):
    __u32 new_saddr = bpf_ntohl(ep->ip);
    long long result = swap_source_ip_address(skb, new_saddr);

    if(result < 0)
      return result;

    load_ip_packet(skb, &iph);
    
    if(iph != 0){
      result = update_l3_csum(skb, old_iph, iph);

      load_ip_packet(skb, &iph);
    }
    return result;
  }
  
  return -1;
}

static __always_inline void initialize_notify_event(struct iphdr *iph, struct event *notify_event, struct endpoint *endpoint){
  // Initialize the source address
	notify_event->saddr[0] = (unsigned char)(iph->saddr & 0xFF);
	notify_event->saddr[1] = (unsigned char)(iph->saddr>>8) & 0xFF;
	notify_event->saddr[2] = (unsigned char)(iph->saddr>>16) & 0xFF;
	notify_event->saddr[3] = (unsigned char)(iph->saddr>>24) & 0xFF;

  if(endpoint != 0) {
    // Initialize the original destination address
    notify_event->odaddr[0] = (unsigned char)(iph->daddr & 0xFF);
    notify_event->odaddr[1] = (unsigned char)(iph->daddr>>8) & 0xFF;
    notify_event->odaddr[2] = (unsigned char)(iph->daddr>>16) & 0xFF;
    notify_event->odaddr[3] = (unsigned char)(iph->daddr>>24) & 0xFF;

    // Initialize the destination address
    __u32 new_daddr = bpf_ntohl(endpoint->ip);
    notify_event->daddr[0] = (unsigned char)(new_daddr & 0xFF);
    notify_event->daddr[1] = (unsigned char)(new_daddr>>8) & 0xFF;
    notify_event->daddr[2] = (unsigned char)(new_daddr>>16) & 0xFF;
    notify_event->daddr[3] = (unsigned char)(new_daddr>>24) & 0xFF;
  }
}


