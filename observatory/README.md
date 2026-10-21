# Luca Kernel Observatory

An optional, opt-in telemetry path that records what the access point's Linux
kernel sees of the inspected device's traffic, next to Luca's existing TShark
capture, Zeek and Suricata analysis. It adds observations the capture cannot
make (protocols outside the `tcp or udp` filter, kernel drop reasons, an
independent packet count to test the capture against) and labels every
statement with how it is known.

It replaces nothing. With the observatory disabled or absent, Luca behaves as
before; the capture, the analysis and the report do not depend on it.

> **Validation status.** The eBPF programs have been built, loaded and
> attached only where the CI workflow [`observatory.yml`](../.github/workflows/observatory.yml)
> runs them: GitHub-hosted Ubuntu 24.04 virtual machines (x86-64 and arm64)
> and Debian containers on those kernels, using veth pairs in network
> namespaces. They have **not** been run on a Luca access point with Wi-Fi
> hardware. Treat results from the experiment runner as properties of the
> recorded kernel and virtual topology, not of a real deployment. The offline
> example in the UI and the unit-test fixtures are synthetic.

## Contents

| Path | Purpose |
| --- | --- |
| `bpf/luca_observatory.bpf.c` | TC classifiers (ingress and egress of `network.in`). No CO-RE; loads without BTF. |
| `bpf/luca_drops.bpf.c` | `skb:kfree_skb` raw tracepoint: drop reasons. CO-RE; needs kernel BTF. Optional. |
| `src/luca_observatory.c` | Collector: loads, attaches, samples, writes `luca.observatory/1` JSON snapshots. |
| `luca_observatory/` | Python: settings, snapshot and pcap/pcapng readers, correlation, heuristics, service, client, evidence bundles. |
| `luca-observatoryd` | Service entry point (`serve`, `render-settings`). |
| `systemd/luca-observatory.service` | Unit: dedicated user, three capabilities, hardened sandbox. |
| `scripts/install-observatory.sh` | Opt-in installer (`--rebuild`, `--uninstall`). |
| `scripts/check-host.sh` | Read-only host compatibility report. |
| `experiments/` | Preregistered experiments A–E and their runner. |
| `examples/` | Generator and output of the labelled synthetic example. |
| `tests/` | Unit tests (any OS), kernel smoke test and service test (Linux, root). |

## What is measured

**TC classifiers** (TCX links on kernels ≥ 6.6 with libbpf ≥ 1.3, a `clsact`
qdisc otherwise). Both return `TC_ACT_UNSPEC`: they never drop, redirect or
modify packets. Per flow (5-tuple, IPv4 and IPv6, keyed from the device's
side) they keep:

- packets and bytes per direction, first and last `CLOCK_MONOTONIC`
  timestamps, TTL / hop-limit range, OR of TCP flags;
- TCP handshake timing (SYN, SYN-ACK, ACK) and the side that sent the SYN;
- `retrans_or_reorder`: TCP segments whose sequence number did not advance.
  At this vantage point a retransmission and a reordering look alike, so they
  are counted together and never reported as retransmissions.

Per interface, per CPU: socket buffers, segments (GSO-aware), bytes, what a
`tcp or udp` capture filter would have matched (`pcap_filter_skbs`,
`pcap_filter_segments`), fragments, ARP / EAPOL / other layer-2, parse
errors, flows that did not fit the table (`flows_not_recorded`) and packets
per IP protocol.

**Drop reasons** (`kfree_skb`, kernel ≥ 5.17 for named reasons; counts only
on 5.10–5.16). Drops of packets that arrived on, or were leaving through, the
access-point interface, keyed by reason, direction, protocol and remote end.
Drops that do not fit the table are counted as `drops_not_keyed`.

**Health and loss**: map occupancy and capacity, map memory, collector CPU
time and RSS, the largest gap between samples, snapshot write failures and
whether the timeline was truncated. With `--prog-stats` (needs
`CAP_SYS_ADMIN`; overhead experiments only) the kernel's run count and run
time per program.

The collector reads no payload. Maps are fixed-size (`max_flows`,
`max_drops`); when full, packets are still counted in the totals and the
shortfall is reported, never silently discarded.

### Direction

`tx` is traffic the device sent (ingress of the access-point interface),
`rx` traffic it received (egress). On an interface that faces the network
(an uplink, as in experiment C3) the roles reverse: the kernel's local end is
the remote host. The correlator detects this and maps directions
accordingly.

## Provenance labels

Every statement in an observatory summary carries one label:

| Label | Meaning |
| --- | --- |
| **OBSERVED** | Recorded by one telemetry path (the kernel or the capture). |
| **CORRELATED** | The same traffic is recorded by both independent paths (kernel TC and AF_PACKET capture) and their counts agree. |
| **INFERRED** | A conclusion drawn from observations by a stated rule (for example a TTL decrement suggesting forwarding). Never shown as a measurement. |
| **UNAVAILABLE** | The telemetry needed was not collected; the reason is stated. Nothing is substituted. |

Each statement also has a category (`corroborated`, `single_source`,
`uncertain`, `missing`, `inferred`), its reasons and the evidence it rests on:
JSON pointers into the original snapshot, Zeek `conn.log` records, the pcap
and Suricata alerts, which are copied unchanged. A summary also lists the
conclusions it does **not** support, including which application produced
the traffic: forwarded packets are not associated with any local process, and
the observatory never attributes them.

**Capture coverage** compares, between two interior kernel samples, the
capture's packet count with the kernel's lower bound (`pcap_filter_skbs`)
and upper bound (`pcap_filter_segments`). A capture with fewer packets than
the lower bound, beyond a tolerance of 2 packets plus 0.1 %, is reported
`incomplete` with the proven minimum loss. Packets whose direction the
capture cannot determine are never counted as lost. Across a NAT boundary
(collector and capture on different interfaces) coverage is `unknown`.

**Heuristics** (KNO-01 to KNO-05) are evaluated only when the collector
observes the device's interface: ICMP to remote hosts and non-TCP/UDP
protocols outside the capture (OBSERVED), packets from outside the access
point's prefixes (OBSERVED), and forwarding or a second network stack behind
the device from TTL values (INFERRED).

## Requirements

| | Minimum | Notes |
| --- | --- | --- |
| Kernel | 5.10 | `CONFIG_BPF_SYSCALL`, `CONFIG_NET_CLS_BPF`, `CONFIG_NET_SCH_INGRESS` |
| Named drop reasons | 5.17 | needs `/sys/kernel/btf/vmlinux` (`CONFIG_DEBUG_INFO_BTF`) or `btf:` |
| TCX attachment | 6.6 and libbpf 1.3 | otherwise `clsact`; `attach: tc` forces it |
| libbpf | 0.6 | older or missing: `make` builds a pinned libbpf 1.5.0 statically |
| Build | clang ≥ 12 (BPF target), gcc, make, pkg-config, libelf, zlib | only when the observatory is installed; if the default clang is older, install a newer one and run the installer with `CLANG=clang-NN` |

`sh scripts/check-host.sh` reports, without attaching anything, which of
these the host provides. Kernel lockdown in `confidentiality` mode forbids
BPF programs to read kernel memory, so drop reasons are unavailable there;
the observatory does not try to work around it, and the classifiers and
Luca's capture are unaffected.

## Installing

The Debian installer asks whether to install the observatory; the default
is no, and no eBPF dependency is installed unless you answer yes. To add it
later:

```bash
sudo bash /usr/share/luca/observatory/scripts/install-observatory.sh
```

This installs the build dependencies, builds the collector, creates the
`luca-observatory` system user, installs and starts the unit, and sets
`observatory.enabled: true`. `--rebuild` rebuilds after an update;
`--uninstall` stops and removes the unit and user and sets `enabled: false`.

### Settings (`config.yaml`)

```yaml
observatory:
  enabled: false            # opt-in
  allowed_interfaces: []    # if set, network.in must be listed to be observed
  attach: auto              # auto | tcx | tc
  drop_reasons: true
  btf: ''                   # path to a BTF file when the kernel exposes none
  sample_interval: 1        # seconds
  flush_interval: 10        # seconds between snapshot writes
  max_flows: 65536
  max_drops: 4096
  max_session_seconds: 7200
  retention_days: 7
  retention_sessions: 20
```

A missing section means disabled; existing configuration files keep
working. Invalid values are replaced by defaults and reported. The service
reads its settings when it starts: after changing them, run
`sudo systemctl restart luca-observatory`.

## Security and privacy

- **Privileges.** The service runs as user `luca-observatory` with only
  `CAP_BPF`, `CAP_NET_ADMIN` and `CAP_PERFMON` (ambient and bounding set),
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectKernelModules`,
  `ProtectKernelTunables`, `MemoryDenyWriteExecute`, address families limited
  to `AF_UNIX` and `AF_NETLINK`, and memory, CPU and task limits. Luca's
  Flask applications do not need, and are not given, any of these.
  `config.yaml` is read by a root `ExecStartPre` step that writes the
  validated settings to `/run/luca-observatory/settings.json`; the service
  itself never reads the configuration file.
- **Interfaces.** The service observes only `network.in`, Luca's
  access-point interface. If `allowed_interfaces` is set, `network.in` must
  be in it; an interface that is also the uplink (`network.out`) is refused
  unless listed explicitly. Clients cannot choose another interface.
- **Local communication only.** Luca talks to the service over the Unix
  socket `/run/luca-observatory/control.sock` (mode 0660, group
  `luca-observatory`); the service checks each peer's credentials
  (`SO_PEERCRED`) and accepts root and members of that group. There is no
  network listener.
- **Data.** Snapshots hold addresses, ports, protocols, counters and
  timestamps of the inspected device's traffic: as sensitive as the capture's
  metadata. They are stored in `/var/lib/luca-observatory` (mode 0750) and
  next to the capture in the session's `assets/` directory, and deleted after
  `retention_days` or beyond `retention_sessions`.
- **No public raw telemetry.** The administration API serves summaries and
  evidence bundles only to authenticated users. Bundles contain the
  snapshot, the summary and a manifest with SHA-256 digests; the pcap is
  referenced by digest, not included. The public web demo serves only the
  synthetic example.
- **No kernel changes.** The observatory loads verified BPF programs through
  the standard `bpf()` interface. It does not change kernel security
  settings, sysctls, lockdown or LSM policy, and does not need a custom
  kernel.

## Testing

```bash
# Unit tests (any OS; synthetic fixtures, no kernel involved)
python3 -m unittest discover -s observatory/tests -p "test_*.py"

# Kernel smoke test (Linux, root): builds a three-namespace topology,
# attaches, generates traffic, checks counters against veth statistics and
# that nothing is left attached afterwards
make -C observatory && sudo make -C observatory test           # ATTACH=tc to force clsact

# Installed service (Linux, root, after install-observatory.sh)
sudo python3 observatory/tests/service_e2e.py --peer-ns <ns> --target <address>
```

Tests that need Linux, root or systemd skip and say so; a skip is not a pass.

## Experiments

[`experiments/preregistration.json`](experiments/preregistration.json) fixes
the questions, procedures and thresholds of experiments A (coverage), B
(overhead), C (correlation), D (anomaly evidence on labelled scenarios) and
E (failure and recovery) before any measurement. Run them with:

```bash
make -C observatory
sudo python3 observatory/experiments/run_experiments.py --build-dir observatory/build
```

The runner writes `experiments/results/<run-id>.json`: verdict per criterion
(`pass`, `fail` or `not_evaluable` when a prerequisite such as Zeek,
`editcap` or systemd is missing), measured values, configuration, kernel and
feature manifest, collector commit and binary digest, timing, telemetry loss,
evidence files with digests and limitations. E1, E2 and E7 run the collector
and service as transient systemd units with the same user and capability
settings as the installed unit. The CI workflow uploads each run as an
artifact. Results are not committed to the repository.

## Kernel source reference

Kernel behaviour (the `kfree_skb` tracepoint prototype, `enum skb_drop_reason`,
TCX and `__sk_buff` semantics) was checked against the Linux 7.3 source tree,
used read-only as a reference. No kernel source is copied into Luca; the
programs include only UAPI headers and use CO-RE against the running
kernel's BTF.

## Licensing

The BPF programs and the collector are dual-licensed GPL-2.0-only OR
BSD-2-Clause (the BPF objects declare `Dual BSD/GPL` so that they may use
GPL-only helpers). The Python code is under Luca's Apache-2.0 license.
libbpf, when built from source, is LGPL-2.1 OR BSD-2-Clause and is linked
statically into the collector.
