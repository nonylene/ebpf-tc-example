#include <linux/types.h>

// types.h on which bpf_helpers.h macro depends must be included before bpf
// helpers

#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

SEC("classifier")
int tc_egress(struct __sk_buff *skb) {
  bpf_printk("Hello, world!");
  return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
