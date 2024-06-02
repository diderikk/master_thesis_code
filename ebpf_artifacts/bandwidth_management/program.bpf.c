//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>
#include "../packet.h"

// Because of testing, it is unreasonably great
#define MAX_PACKETS_RATE 102400

char __license[] SEC("license") = "Dual MIT/GPL";

// Ring Buffer event. I.E., the information that is read by the userspace program.
struct event
{
  unsigned char saddr[4];
  unsigned char daddr[4];
	__u64 count;
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


struct ipv4_key {
  __u32 saddr;
  __u32 daddr;
};
// IPv4 Hash Map. Key: Source IPv4 Address, Value: Counter
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ipv4_key);
    __type(value, __u64);
    __uint(max_entries, 1024);
} pkt_count SEC(".maps");

static __always_inline __u64 *get_and_increment_flow_count(struct iphdr *iph);
static __always_inline void initialize_notify_event(struct iphdr *iph, __u64 count, struct event *notify_event);

SEC("tc")
int rate_limit(struct __sk_buff *skb)
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

    // Checks if the received ethernet packet contains a IPv4 packet
    if (eth != 0 && bpf_ntohs(eth->h_proto) == ETH_P_IP){
      iph = get_ip_packet(data_end, &cursor);
    }

    if(iph == 0)
      return TC_ACT_OK;

    if(iph != 0 && iph->protocol == IPPROTO_IPIP){
      iph_inner = get_ip_packet(data_end, &cursor);

      if(iph_inner != 0)
        iph = iph_inner;
    }

			
    // Checks if a IPv4 has been initialized
    if (iph != 0){
        __u64 * count; 
        // Fetches and increments the count from the counter map
        count = get_and_increment_flow_count(iph);

        // Packets are dropped if the counter is greater than the set MAX_PACKETS_RATE
        // The counter is reset by the userspace program, by updating the respective counter maps.
        // The resets does not affect the eBPF program, hence why it should not affect the latency either.
        if(*count > MAX_PACKETS_RATE){

          if(*count - 1 == MAX_PACKETS_RATE){
            // Reserve *size* bytes of payload in a Ring Buffer map.
            notify_event = bpf_ringbuf_reserve(&event_buff, sizeof(struct event), 0);

            if (notify_event){
              initialize_notify_event(iph, *count, notify_event);
              bpf_ringbuf_submit(notify_event, 0);
            }
          }
          

          // Discards packet
          return TC_ACT_SHOT;
        }
    }
    return TC_ACT_OK;
}

// Fetches and increments a counter from an eBPF map
static __always_inline __u64 *get_and_increment_flow_count(struct iphdr *iph) {
  // Combines the source IP address with the destination IP address, and uses it to lookup the counter
  struct ipv4_key key = {iph->saddr, iph->daddr};
	__u64 *count = bpf_map_lookup_elem(&pkt_count, &key);

  // If the key does not exist in the map, create a new entry with value 1.
	if (!count){
		__u64 value = 1;
		bpf_map_update_elem(&pkt_count, &key, &value, BPF_NOEXIST);
		count = &value;
	}
  // Otherwise, increment the entry
	else {
			(*count)++;
	}

	return count;
}

static __always_inline void initialize_notify_event(struct iphdr *iph, __u64 count, struct event *notify_event){
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

  notify_event->count = count;
}