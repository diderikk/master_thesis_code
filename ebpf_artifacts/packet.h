#include <bpf/bpf_endian.h>
#include <stddef.h>
#include <netinet/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>

#define ETH_P_IP 0x0800
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TCP_CSUM_OFF \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define TCP_DEST_OFF \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define TCP_SRC_OFF \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define UDP_CSUM_OFF \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define UDP_DEST_OFF \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest))
#define UDP_SRC_OFF \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source))

struct hdr_cursor
{
	void *pos;
};

static __always_inline struct ethhdr *get_eth_packet(void *data_end, struct hdr_cursor *cursor)
{
	struct ethhdr *eth = 0;

	// Check Eth packet fits in the data
	if (cursor->pos + sizeof(struct ethhdr) > data_end)
		return eth;

	eth = cursor->pos;
	// Update cursor position
	cursor->pos += sizeof(struct ethhdr);

	return eth;
}

static __always_inline struct iphdr *get_ip_packet(void *data_end, struct hdr_cursor *cursor)
{
	struct iphdr *iph = 0;

	// Check IP packet fits in the data (after Eth packet)
	if (cursor->pos + sizeof(struct iphdr) > data_end)
		return iph;

	struct iphdr *iph_ = cursor->pos;

	// Variable IP size;
	int hdr_size = iph_->ihl * 4;

	if (hdr_size < sizeof(struct iphdr))
		return iph;

	if (cursor->pos + hdr_size > data_end)
		return iph;

	iph = iph_;
	cursor->pos += hdr_size;

	return iph;
}

static __always_inline struct ipv6hdr *get_ipv6_packet(void *data_end, struct hdr_cursor *cursor)
{
	struct ipv6hdr *iph = 0;

	// Check IP packet fits in the data (after Eth packet)
	if (cursor->pos + sizeof(struct ipv6hdr) > data_end)
		return iph;

	struct ipv6hdr *iph_ = cursor->pos;

	if (cursor->pos + sizeof(struct ipv6hdr) > data_end)
		return iph;

	iph = iph_;
	cursor->pos += sizeof(struct ipv6hdr);

	return iph;
}



static __always_inline struct icmphdr *get_icmp_packet(void *data_end, struct hdr_cursor *cursor)
{
	struct icmphdr *icmph = 0;

	if (cursor->pos + sizeof(struct icmphdr) > data_end)
		return icmph;

	icmph = cursor->pos;
	cursor->pos += sizeof(struct icmphdr);

	return icmph;
}

static __always_inline struct icmp6hdr *get_icmpv6_packet(void *data_end, struct hdr_cursor *cursor)
{
	struct icmp6hdr *icmph = 0;

	if (cursor->pos + sizeof(struct icmp6hdr) > data_end)
		return icmph;

	icmph = cursor->pos;
	cursor->pos += sizeof(struct icmp6hdr);

	return icmph;
}

static __always_inline struct tcphdr *get_tcp_packet(void *data_end, struct hdr_cursor *cursor)
{
	struct tcphdr *tcph = 0;

	if (cursor->pos + sizeof(struct tcphdr) > data_end)
		return tcph;

	struct tcphdr *tcph_ = cursor->pos;

	int hdr_size = tcph_->doff * 4;

	if (hdr_size < sizeof(struct tcphdr))
		return tcph;

	if (cursor->pos + hdr_size > data_end)
		return tcph;

	tcph = tcph_;
	cursor->pos += hdr_size;

	return tcph;
}

static __always_inline struct udphdr *get_udp_packet(void *data_end, struct hdr_cursor *cursor)
{
	struct udphdr *udph = 0;

	if (cursor->pos + sizeof(struct udphdr) > data_end)
		return udph;

	struct udphdr *udph_ = cursor->pos;

	int hdr_diff = bpf_ntohs(udph_->len) - sizeof(struct udphdr);

	if (hdr_diff < 0)
		return udph;

	udph = udph_;

	return udph;
}

static __always_inline void load_ip_packet(struct __sk_buff *skb, struct iphdr **iph){
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  // Initializes all packet structures
  struct hdr_cursor cursor;
  cursor.pos = data;
	struct ethhdr *eth = get_eth_packet(data_end, &cursor);
	struct iphdr *_iph = 0;

	  
	if(eth != 0 && bpf_ntohs(eth->h_proto) == ETH_P_IP){
    _iph = get_ip_packet(data_end, &cursor);
  }

	*iph = _iph;
}

static __always_inline void load_l3_and_l4_packet(struct __sk_buff *skb, struct iphdr **iph, struct tcphdr **tcph, struct udphdr **udph){
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  // Initializes all packet structures
  struct hdr_cursor cursor;
  cursor.pos = data;
	struct ethhdr *eth = get_eth_packet(data_end, &cursor);
	struct iphdr *_iph = 0;
	struct tcphdr *_tcph = 0;
  struct udphdr *_udph = 0;

	  
	if(eth != 0 && bpf_ntohs(eth->h_proto) == ETH_P_IP){
    _iph = get_ip_packet(data_end, &cursor);
  }

	if(_iph == 0){
		*iph = 0;
		*tcph = 0;
		*udph = 0;
    return;
  }

  if(_iph->protocol == IPPROTO_IPIP){
    struct iphdr *iph_inner = get_ip_packet(data_end, &cursor);
    
    if(iph_inner != 0)
      _iph = iph_inner;
  }

  if(_iph->protocol == IPPROTO_TCP){
    _tcph = get_tcp_packet(data_end, &cursor);
  } else if(_iph->protocol == IPPROTO_UDP){
    _udph = get_udp_packet(data_end, &cursor);
  }

	*iph = _iph;
	*tcph = _tcph;
	*udph = _udph;
}

static __always_inline long swap_destination_ip_address(struct __sk_buff *skb, __u32 new_ip_address){
	void *from = (void*)(long)&new_ip_address;
	return bpf_skb_store_bytes(skb, IP_DST_OFF, from, 4, 0);
}

static __always_inline long swap_source_ip_address(struct __sk_buff *skb, __u32 new_ip_address){
	void *from = (void*)(long)&new_ip_address;
	return bpf_skb_store_bytes(skb, IP_SRC_OFF, from, 4, 0);
}

static __always_inline long swap_destination_tcp_port(struct __sk_buff *skb, __u16 new_port){
	void *from = (void*)(long)&new_port;
	return bpf_skb_store_bytes(skb, TCP_DEST_OFF, from, 2, 0);
}

static __always_inline long swap_source_tcp_port(struct __sk_buff *skb, __u16 new_port){
	void *from = (void*)(long)&new_port;
	return bpf_skb_store_bytes(skb, TCP_SRC_OFF, from, 2, 0);
}

static __always_inline long swap_destination_udp_port(struct __sk_buff *skb, __u16 new_port){
	void *from = (void*)(long)&new_port;
	return bpf_skb_store_bytes(skb, UDP_DEST_OFF, from, 2, 0);
}

static __always_inline long swap_source_udp_port(struct __sk_buff *skb, __u16 new_port){
	void *from = (void*)(long)&new_port;
	return bpf_skb_store_bytes(skb, UDP_SRC_OFF, from, 2, 0);
}

static __always_inline long long update_l3_csum(struct __sk_buff *skb, struct iphdr *old_iph, struct iphdr *iph){
	__u32 csum_diff = bpf_csum_diff((__be32 *)old_iph, sizeof(*old_iph), (__be32 *)iph, sizeof(*iph), 0);

	if(csum_diff < 0)
		return csum_diff;

	return bpf_l3_csum_replace(skb, IP_CSUM_OFF, 0, csum_diff, 0);
}

static __always_inline long long update_tcp_csum(struct __sk_buff *skb, struct tcphdr *old_tcph, struct tcphdr *tcph){
	__u32 csum_diff = bpf_csum_diff((__be32 *)old_tcph, sizeof(*old_tcph), (__be32 *)tcph, sizeof(*tcph), 0);

	if(csum_diff < 0)
		return csum_diff;

	return bpf_l3_csum_replace(skb, IP_CSUM_OFF, 0, csum_diff, 0);
}

static __always_inline long long update_udp_csum(struct __sk_buff *skb, struct udphdr *old_udph, struct udphdr *udph){
	__u32 csum_diff = bpf_csum_diff((__be32 *)old_udph, sizeof(*old_udph), (__be32 *)udph, sizeof(*udph), 0);

	if(csum_diff < 0)
		return csum_diff;

	return bpf_l3_csum_replace(skb, IP_CSUM_OFF, 0, csum_diff, 0);
}