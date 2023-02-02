BPF_TARGETS := tc_egress
MAP_TARGETS := rule

# Tun interface connected to VM
INTERFACE := ens4

BPF_C = ${BPF_TARGETS:=.c}
BPF_OBJ = ${BPF_C:.c=.o}

BPF_LOAD = ${BPF_TARGETS:=_load}
BPF_UNLOAD = ${BPF_TARGETS:=_unload}
BPF_ATTACH = ${BPF_TARGETS:=_attach}
BPF_DETATCH = ${BPF_TARGETS:=_detach}
BPF_RELOAD = ${BPF_TARGETS:=_reload}

MAP_UNPIN = ${MAP_TARGETS:=_unpin}

CLANG ?= clang

all: $(BPF_OBJ)

$(BPF_OBJ): %.o: %.c vmlinux.h
	$(CLANG) -target bpf \
		-Wall \
		-O3 -g -c -o $@ $<

## PROGS ##

$(BPF_LOAD):  %_load: /sys/fs/bpf/%

tc_qdisc:
ifeq ($(shell tc qdisc show dev ${INTERFACE} clsact),)
	tc qdisc add dev ${INTERFACE} clsact
endif

tc_qdisc_delete:
	- tc qdisc del dev ${INTERFACE} clsact

/sys/fs/bpf/tc_egress: /sys/fs/bpf/%: %.o
	bpftool prog load $*.o /sys/fs/bpf/$* map name rule pinned /sys/fs/bpf/rule

# load without map pin (for the first load)
tc_egress_load_init: %_load_init: %.o
	bpftool prog load $*.o /sys/fs/bpf/$*

tc_egress_attach: %_attach: %_load tc_qdisc
	tc filter add dev ${INTERFACE} egress bpf da pinned /sys/fs/bpf/tc_egress

tc_egress_detach: %_detach:
	- tc filter del dev ${INTERFACE} egress

$(BPF_RELOAD): %_reload: | %_unload %_attach

$(BPF_UNLOAD): %_unload: %_detach
	rm -rf /sys/fs/bpf/$*

## MAPS ##

$(MAP_UNPIN): %_unpin:
	rm -rf /sys/fs/bpf/$*

## UTILS ##

init: | tc_egress_load_init tc_egress_attach

reload: | tc_egress_unload /sys/fs/bpf/tc_egress tc_egress_attach

unload: | tc_egress_unload tc_qdisc_delete rule_unpin

log:
	cat /sys/kernel/debug/tracing/trace_pipe

clean: | unload
	rm -f $(BPF_OBJ)

.PHONY: tc_qdisc tc_qdisc_delete clean log unload init $(CLANG) $(LLC) $(BPF_LOAD) $(BPF_ATTACH) $(BPF_DETATCH) $(BPF_UNLOAD) $(BPF_RELOAD) $(MAP_PIN) $(MAP_UNPIN)
