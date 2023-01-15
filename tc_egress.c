#include <linux/types.h>

// types.h on which bpf_helpers.h macro depends must be included before
// bpf helpers

#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

// rule map

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __type(key, struct in_addr);
  __type(value, __u_char);  // not used; should be fillled with 0x0
} rule SEC(".maps");

SEC("classifier")
int tc_egress(struct __sk_buff *skb) {
  // bpf_printk("Hello, world!");

  if ((skb->data + sizeof(struct iphdr) + ETH_HLEN) > skb->data_end) {
    return TC_ACT_UNSPEC;
  }

  struct ethhdr *eth = (void *)(long)skb->data;
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
    return TC_ACT_UNSPEC;
  }

  struct iphdr *ip = (void *)(long)skb->data + ETH_HLEN;
  if (ip->protocol != IPPROTO_ICMP) {
    return TC_ACT_UNSPEC;
  }

  // if (bpf_ntohl(ip->daddr) == 0x08080404) {  // 8.8.4.4
  //   bpf_printk("tc_egress: ICMP packet to 8.8.4.4, drop!\n");
  //   return TC_ACT_SHOT;
  // }

  struct in_addr dst_address = {
      .s_addr = bpf_ntohl(ip->daddr),
  };
  __u_char *value = bpf_map_lookup_elem(&rule, &dst_address);
  if (value != NULL) {
    bpf_printk("tc_egress: ICMP packet to a denied address, drop!\n");
    return TC_ACT_SHOT;
  }

  bpf_printk("tc_egress: Allowed ICMP packet, ignore\n");
  return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
