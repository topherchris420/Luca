#!/bin/sh
# Reports whether this host can build and run the Luca observatory.
# Read-only and safe without root; it attaches nothing.
# Usage: sh scripts/check-host.sh [build-dir]

BUILD_DIR="${1:-build}"
status=0

say() { printf '  %-34s %s\n' "$1" "$2"; }

kernel_config() {
    if [ -r /proc/config.gz ]; then
        zcat /proc/config.gz 2>/dev/null
    elif [ -r "/boot/config-$(uname -r)" ]; then
        cat "/boot/config-$(uname -r)"
    fi
}

echo "Luca observatory host check"
say "kernel" "$(uname -r) ($(uname -m))"

CONFIG="$(kernel_config)"
check_config() {
    # $1 option, $2 meaning, $3 "required" or "optional"
    if [ -z "$CONFIG" ]; then
        say "$1" "unknown (no /proc/config.gz or /boot/config-*)"
        return
    fi
    if printf '%s\n' "$CONFIG" | grep -E "^$1=(y|m)" >/dev/null; then
        say "$1" "yes ($2)"
    elif [ "$3" = "required" ]; then
        say "$1" "MISSING ($2)"
        status=1
    else
        say "$1" "no ($2)"
    fi
}
check_config CONFIG_BPF_SYSCALL "bpf() syscall" required
check_config CONFIG_NET_CLS_BPF "cls_bpf classifier, used without tcx" optional
check_config CONFIG_NET_SCH_INGRESS "clsact qdisc, used without tcx" optional
check_config CONFIG_NET_XGRESS "tcx links, kernel >= 6.6" optional
check_config CONFIG_BPF_EVENTS "BPF on tracepoints, for drop reasons" optional
check_config CONFIG_DEBUG_INFO_BTF "kernel BTF, for drop reasons" optional

if [ -r /sys/kernel/btf/vmlinux ]; then
    say "/sys/kernel/btf/vmlinux" "present: drop reasons can load"
else
    say "/sys/kernel/btf/vmlinux" "absent: drop reasons need --btf FILE"
fi

# The drop program is a raw tracepoint: it needs the tracepoint to exist,
# not tracefs. Symbol names in kallsyms are readable without root.
if grep -Eq ' (__tracepoint|__traceiter)_kfree_skb$' /proc/kallsyms 2>/dev/null; then
    say "kfree_skb tracepoint" "present"
else
    say "kfree_skb tracepoint" "not found in /proc/kallsyms"
fi

if [ -r /sys/kernel/security/lockdown ]; then
    say "kernel lockdown" "$(cat /sys/kernel/security/lockdown)"
fi

if command -v clang >/dev/null 2>&1; then
    say "clang" "$(clang --version | head -n 1)"
else
    say "clang" "MISSING (needed to build the BPF objects)"
    status=1
fi

if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libbpf 2>/dev/null; then
    say "system libbpf" "$(pkg-config --modversion libbpf)"
else
    say "system libbpf" "not found (make will build the pinned release)"
fi

major="$(uname -r | cut -d. -f1)"
minor="$(uname -r | cut -d. -f2 | sed 's/[^0-9].*//')"
if [ "$major" -lt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -lt 10 ]; }; then
    say "kernel version" "older than 5.10: unsupported"
    status=1
elif [ "$major" -eq 5 ] && [ "$minor" -lt 17 ]; then
    say "kernel version" "drop events without reason codes (< 5.17)"
fi

for f in luca-observatory luca_observatory.bpf.o luca_drops.bpf.o; do
    if [ -e "$BUILD_DIR/$f" ]; then
        say "$BUILD_DIR/$f" "built"
    else
        say "$BUILD_DIR/$f" "not built"
    fi
done

if [ "$status" -ne 0 ]; then
    echo "Result: this host cannot run the observatory as configured."
else
    echo "Result: no blocking problem found. Only a real attach (make test, as root) proves it works."
fi
exit "$status"
