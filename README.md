# ebpf-tc-example
eBPF example repository for study purpose

## Requirements

### Ubuntu 22.04

```
# apt install linux-tools-generic libbpf-dev clang build-essential gcc-multilib
```

### ArchLinux

Enable multilib and

```
# pacman -S base-devel libbpf bpf lib32-glibc clang
```

## Setup

```
$ sudo make init # Install eBPF program
$ sudo make reload # Reload eBPF program while preserving maps
$ sudo make unload # Uninstall eBPF program
```

## Memo

### Generating vmlinux.h

```
$ sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```
