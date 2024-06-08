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
  // Original destinatin address
  unsigned char odaddr[4];
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

// Hash Map key: Source and destination IPv4 address
struct key
{
  __u32 saddr;
  __u16 sport;
  __u32 daddr;
  __u16 dport;
};

// 
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct key);
  __type(value, __u32);
  // NOTE: Maximum of 1024 pods possible (PoC)
  __uint(max_entries, POD_MAX_AMOUNT);
} packet_count_map SEC(".maps");

static __always_inline __u32 *increment_count(struct iphdr *iph, __u16 sport, __u16 dport);
static __always_inline void initialize_notify_event(struct iphdr *iph, struct event *notify_event);

SEC("tc")
int observe(struct __sk_buff *skb)
{
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  // Initializes all packet structures
  struct hdr_cursor cursor;
  cursor.pos = data;
  struct ethhdr *eth = get_eth_packet(data_end, &cursor);
  struct iphdr *iph = 0;
  struct iphdr *iph_inner = 0;
  struct tcphdr *tcph = 0;
  struct udphdr *udph = 0;
  struct event *notify_event = 0;
  __u16 dport = 0;
  __u16 sport = 0;

  if(eth != 0 && bpf_ntohs(eth->h_proto) == ETH_P_IP){
    iph = get_ip_packet(data_end, &cursor);
  }


  if(iph == 0){
    return TC_ACT_OK;
  }

  if(iph->protocol == IPPROTO_IPIP){
    iph_inner = get_ip_packet(data_end, &cursor);
    
    if(iph_inner != 0)
      iph = iph_inner;
  }


  if(iph->protocol == IPPROTO_TCP){
    tcph = get_tcp_packet(data_end, &cursor);

    if(tcph != 0){
      dport = tcph->dest;
      sport = tcph->source;
    }
  } else if(iph->protocol == IPPROTO_UDP){
    udph = get_udp_packet(data_end, &cursor);

    if(udph != 0){
      dport = udph->dest;
      sport = udph->source;
    }
  }
  // Increments of packet count of the current flow
  increment_count(iph, sport, dport);

  notify_event = bpf_ringbuf_reserve(&event_buff, sizeof(struct event), 0);


  if(notify_event == 0)
    return TC_ACT_OK;

  initialize_notify_event(iph, notify_event);
  // Submits the initialized event
  bpf_ringbuf_submit(notify_event, 0);

  return TC_ACT_OK;
}

// Increments the count of packets sent between a source and destination (L3 and L4)
static __always_inline __u32 *increment_count(struct iphdr *iph, __u16 sport, __u16 dport){
  struct key key = {iph->saddr, sport, iph->daddr, dport};

  __u32 *count = bpf_map_lookup_elem(&packet_count_map, &key);

  if(count == 0){
    __u32 init_count = 1;
    bpf_map_update_elem(&packet_count_map, &key, &init_count, BPF_NOEXIST);
    count = &init_count;
  } else {
    (*count)++;
  }

  return count;
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
