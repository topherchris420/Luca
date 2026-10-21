# Luca

[![observatory CI](https://github.com/topherchris420/Luca/actions/workflows/observatory.yml/badge.svg)](https://github.com/topherchris420/Luca/actions/workflows/observatory.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE.txt)
[![Platform: Debian-family Linux](https://img.shields.io/badge/platform-Debian--family%20Linux-lightgrey.svg)](#quick-start)

**Agentless network inspection for one Wi-Fi device at a time. Luca runs a dedicated access point, records the device's traffic, analyzes it with Zeek and Suricata against indicators of compromise and behavioral heuristics, and produces a severity-graded report.**

![Luca traffic-analysis architecture](assets/luca-architecture.svg)

Connect a phone, tablet, laptop or IoT device to the Wi-Fi network Luca creates, use it for a while, and get a readable report. Nothing is installed on the device under inspection; the report is built only from what the device sent over the network. Luca is a derivative of [TinyCheck](https://github.com/KasperskyLab/TinyCheck), Kaspersky's open-source network inspection tool, and keeps its Apache 2.0 license.

> Luca is for authorized inspection and research. A match or heuristic alert is evidence to investigate, **not proof that a device is compromised**. Inspect only devices and networks you own or are authorized to assess.

## Contents

- [Why Luca](#why-luca)
- [How it works](#how-it-works)
- [What Luca flags](#what-luca-flags)
- [Quick start](#quick-start)
- [Running a capture](#running-a-capture)
- [Administration and threat intelligence](#administration-and-threat-intelligence)
- [Configuration](#configuration)
- [Kernel observatory (optional)](#kernel-observatory-optional)
- [Public demo](#public-demo)
- [Services, ports and paths](#services-ports-and-paths)
- [Updating and uninstalling](#updating-and-uninstalling)
- [Development](#development)
- [Limitations and operational security](#limitations-and-operational-security)
- [License and acknowledgements](#license-and-acknowledgements)

## Why Luca

- **Agentless.** The device joins a Wi-Fi network; Luca never touches its storage, apps or memory.
- **Two engines, one list of findings.** Zeek extracts connection, DNS, HTTP, TLS and file metadata; Suricata evaluates signature rules. Luca correlates both with indicators, heuristics and allowlists.
- **Evidence, not verdicts.** Every finding has a severity (High, Moderate, Low), an alert ID, the host involved and a plain-language explanation. The optional kernel observatory goes further and labels each statement OBSERVED, CORRELATED, INFERRED or UNAVAILABLE.
- **Self-contained appliance.** Indicators live in a local SQLite database seeded from the bundled set; remote feeds and MISP are optional. Kiosk mode, an on-screen keyboard and USB export make Luca usable on a small touchscreen box with no other computer.
- **Reports people can read.** The interface and the PDF report ship in ten languages.

## How it works

1. **Connect.** Luca starts a WPA2 access point on the capture interface (`network.in`) with a random name and password, shown as a QR code. One device joins, receives an address from a two-lease DHCP range and reaches the internet through NAT on the upstream interface (`network.out`). An nftables rule keeps the device away from Luca's own web interfaces.
2. **Capture.** TShark records TCP and UDP traffic on the access-point interface into `capture.pcap`, inside a session directory named by an eight-character token. The device's name, IP and MAC address are read from its DHCP lease.
3. **Analyze.** Zeek (with certificate validation) and Suricata run in parallel against the saved capture. Suricata uses the rules stored in the indicator database plus contextual rules generated for the session, which fire if the Wi-Fi name or the device name travels in clear text.
4. **Correlate.** Connections are resolved back to domain names from the session's DNS answers, allowlisted hosts are set aside, and the rest is checked against indicators and heuristics. Optional active lookups query name servers and WHOIS records.
5. **Report.** Findings are grouped by severity and written as JSON next to the connection lists, and WeasyPrint renders a PDF report. The session can be exported as a ZIP to a USB drive or through the browser.

```text
Wi-Fi device ──▶ Luca access point ──▶ TShark ──▶ capture.pcap
                        │                              │
                        │ optional eBPF          ┌─────┴─────┐
                        ▼                        ▼           ▼
                kernel observatory             Zeek       Suricata
              (flow and drop counts)        (metadata)  (signatures)
                        │                        │           │
                        └──────────▶ indicators + heuristics + allowlists
                                                 │
                                                 ▼
                                  alerts.json · conns.json · report.pdf
```

## What Luca flags

Every finding carries an ID. The texts live in [`analysis/locales/`](analysis/locales/), the logic in [`analysis/classes/`](analysis/classes/). Allowlisted addresses, ranges and domains are set aside before the connection checks run and are listed separately in the report.

| Family | IDs | Trigger | Severity |
| --- | --- | --- | --- |
| Indicator matches | IOC-01 to IOC-10 | Destination address, network range, domain name (seen in DNS answers, HTTP `Host` headers or TLS server names), free-DNS domain, suspect TLD or certificate SHA-1 present in the indicator database | High for indicators tagged malicious; Moderate for trackers, ranges and free DNS; Low for suspect TLDs |
| Protocol heuristics | PROTO-01 to PROTO-05 | Unexpected protocols, destination ports at or above `analysis.max_ports`, plain HTTP, HTTP on a non-standard port, destinations never resolved by DNS during the session | Low to Moderate |
| TLS heuristics | SSL-01 to SSL-04 | TLS on a port outside `analysis.ssl_default_ports`, certificates from the issuers in `analysis.free_issuers`, self-signed chains, an indicator-listed name inside a certificate | Moderate; High for SSL-04 |
| Active lookups | ACT-01, ACT-02 | Domain served by a flagged name server; domain registered less than a year ago. Needs `analysis.active` and sends DNS and WHOIS queries from the Luca host | Moderate |
| Suricata signatures | SNORT-01 | Any rule from the indicator database or the per-session contextual rules | High |
| Advice | ADV-01 | One host accumulates `analysis.max_alerts` or more findings | Moderate |
| Kernel observatory | KNO-01 to KNO-05 | ICMP or non-TCP/UDP traffic the capture cannot see, packets from outside the access point's prefix, signs of forwarding or of a second network stack behind the device | Low to Moderate, each labelled OBSERVED or INFERRED |

**Severity in one line:** High means an explicit indicator or signature matched; Moderate means a contextual signal worth checking; Low means a weak signal that matters only alongside others.

Indicators are typed and tagged. Types: `ip4addr`, `ip6addr`, `cidr`, `domain`, `freedns`, `ns`, `tld`, `sha1cert` and `snort` (Snort-compatible rules evaluated by Suricata). Tags: `apt`, `stalkerware`, `suspect`, `malicious`, `tracker`, `spyware`, `cybercrime`; a domain tagged `tracker` produces a Moderate finding, any other tag a High one. Each indicator also carries a TLP level (`white`, `green`, `amber`, `red`).

## Quick start

### Requirements

- A **dedicated machine** running a Debian-family Linux. The installer recognizes Debian, Ubuntu and Raspberry Pi OS. Kiosk mode and the desktop launcher were written for an appliance such as a Raspberry Pi with a touchscreen, but any box with the right interfaces works.
- Two network interfaces: a Wi-Fi adapter whose driver supports **AP mode** (listed under supported interface modes in `iw phy`) for the monitored device, and a separate upstream interface (Ethernet or a second Wi-Fi adapter) for internet access.
- Root access and an internet connection during installation.

### Install

```bash
git clone https://github.com/topherchris420/Luca.git
cd Luca
sudo bash install.sh
```

The installer is interactive. It asks which interfaces to use, the report language, the administration credentials, and whether to enable kiosk mode, in-app updates and the kernel observatory. It then:

- copies the repository to `/usr/share/luca` and records the commit in `VERSION`;
- installs hostapd, dnsmasq, dhcpcd, TShark, Zeek, Suricata, sqlite3, Node.js and the Python requirements, adding third-party apt sources for Zeek, Suricata and Node.js;
- appends a DHCP scope to `/etc/dnsmasq.conf` and a static address for the access-point interface to `/etc/dhcpcd.conf`, and may disable `systemd-resolved` in favour of dnsmasq;
- changes the hostname to `luca` and maps `luca.local` in `/etc/hosts`;
- builds both Vue applications, creates the SQLite database, generates a self-signed certificate for the administration interface, installs and enables the `luca-*` systemd units, seeds the indicator database from the bundled files, and offers to reboot.

Read [`install.sh`](install.sh) before running it. These are host-wide changes, which is why a dedicated machine is required.

### First use

| Interface | Address | Purpose |
| --- | --- | --- |
| Capture UI | `http://luca.local` (port 80) | Set up the upstream connection, run a capture, review findings, export |
| Administration | `https://luca.local` (port 443, self-signed certificate) | Configuration, indicators, allowlists, MISP, database backup, kernel observatory |

The administration login and password are the ones chosen during installation. `luca.local` resolves on the host itself; from another machine use the host's IP address and expect a certificate warning. Read [Limitations and operational security](#limitations-and-operational-security) before exposing either interface beyond the machine.

## Running a capture

1. **Home.** Luca checks internet access on the upstream interface. With `frontend.choose_net` enabled you can pick and join a Wi-Fi network for the uplink from the UI; otherwise Luca uses whatever the interface already has.
2. **Generate the access point.** Luca writes a hostapd configuration (WPA2-PSK, 2.4 GHz, channel chosen away from the uplink's), starts it and displays the SSID, the password and a QR code. Connect the device.
3. **Capture.** Watch the live packet chart, use the device normally (open the apps you want to examine), then stop. Luca records capture statistics with `capinfos` and the device identity from its DHCP lease.
4. **Analyze.** Zeek and Suricata run in parallel. The report view lists findings by severity with the connections that triggered them, the uncategorized connections and the allowlisted ones.
5. **Save.** Export the session as `Luca_<date>.zip` to a USB drive (detected automatically) or, with `frontend.download_links` enabled, download it in the browser. Exporting removes the session directory from the host.

### What a session contains

```text
/tmp/<TOKEN>/                 # TOKEN: eight hexadecimal characters
├── capture.pcap
├── report.pdf                # written by the analysis
└── assets/
    ├── device.json           # name, IP and MAC address from the DHCP lease
    ├── capinfos.json         # duration, packet count, sizes
    ├── conn.log, dns.log, ssl.log, http.log, files.log …   # Zeek logs
    ├── alerts.json           # findings grouped as high / moderate / low
    ├── conns.json            # connections that were not allowlisted, with resolutions
    ├── whitelist.json        # connections that were allowlisted
    └── observatory*.json     # only when the kernel observatory ran
```

The PDF holds the device name and MAC address, the capture's duration, packet count and SHA-1, a severity banner, the findings, the three connection tables and, when present, the kernel observatory evidence.

### Analyzing an existing capture

On an installed system, the analysis also runs without the UI against any directory that holds a `capture.pcap`:

```bash
python3 /usr/share/luca/analysis/analysis.py /path/to/capture-directory
```

This runs Zeek and Suricata, writes `assets/*.json` and `report.pdf` into that directory, and uses the installed configuration and indicator database. Without the session's device information, the contextual Suricata rules and the device section of the report are skipped.

## Administration and threat intelligence

The administration interface at `https://luca.local` uses HTTP Basic authentication; the installer stores the login and the SHA-256 digest of the password in `config.yaml`. The single-page app then obtains a 24-hour JWT for its API calls. From there you can:

- **Configure Luca:** toggle and edit `config.yaml` keys (interfaces, UI options, analysis thresholds, remote access).
- **Manage indicators:** add one indicator at a time (the type is detected automatically for addresses, ranges, domains and certificate hashes), search, export as JSON, delete.
- **Manage allowlists:** the same for known-good addresses, ranges and domains.
- **Connect MISP instances:** URL, API key and certificate verification; the watcher pulls attributes from each instance.
- **Back up or restore the database:** export and import the SQLite file.
- **Inspect the kernel observatory:** status, host capabilities and per-session summaries, when installed.

### Where indicators come from

The `luca-watchers` service runs at boot. It loads [`assets/iocs.json`](assets/iocs.json) and [`assets/whitelist.json`](assets/whitelist.json) first, then any HTTPS feeds listed under `watchers.iocs` and `watchers.whitelists`, then every MISP instance in the database, retrying failed sources every minute until all have loaded. Feeds use the same JSON shape as the bundled files: `{"iocs": [{"type", "tag", "tlp", "value"}], "to_delete": [...]}` for indicators and `{"elements": [{"type", "element"}], "to_delete": [...]}` for allowlists. No remote feed is configured by default. Detection is only as good as the indicators behind it: evaluate a source before trusting it.

## Configuration

[`config.yaml`](config.yaml) is copied to `/usr/share/luca/config.yaml` at install, where the installer replaces the placeholders (`iface_in`, `userlogin`, `kioskmode` and so on). Edit it there or through the administration interface, then restart the affected service.

| Key | Default | Role |
| --- | --- | --- |
| `network.in`, `network.out` | set by the installer | Access-point interface and upstream interface |
| `network.ssids`, `network.tokenized_ssids` | four names, `true` | Pool of access-point names; append a random four-character suffix |
| `network.internet_check` | `https://8.8.8.8` | URL fetched to test the uplink |
| `analysis.iocs`, `analysis.heuristics`, `analysis.whitelist` | `true` | Enable indicator matching, heuristics and allowlist filtering |
| `analysis.active` | `true` | Enable name-server and WHOIS lookups (ACT-01, ACT-02), which contact external services |
| `analysis.max_alerts`, `analysis.max_ports` | `3`, `1024` | Threshold for ADV-01; port threshold for PROTO-02 |
| `analysis.http_default_port`, `analysis.ssl_default_ports`, `analysis.free_issuers` | `80`, seven ports, three issuers | What counts as standard HTTP, standard TLS and a free certificate issuer |
| `frontend.http_port`, `frontend.remote_access` | `80`, `true` | Capture UI port; listen on all interfaces instead of localhost only |
| `frontend.kiosk_mode`, `frontend.hide_mouse`, `frontend.quit_option` | set by the installer | Fullscreen Chromium at boot, hidden cursor, quit button |
| `frontend.virtual_keyboard`, `frontend.sparklines` | `true` | On-screen keyboard; live packet chart |
| `frontend.download_links`, `frontend.shutdown_option`, `frontend.reboot_option` | `false` | Browser download of sessions; power buttons in the UI |
| `frontend.choose_net`, `frontend.update` | `false`, set by the installer | Uplink Wi-Fi selection in the UI; in-app update |
| `frontend.user_lang` | set by the installer | UI and report language. The installer offers `en`, `fr`, `cat`, `es`, `ru`, `pt`, `de` and `it`; `cn` and `sk` also ship |
| `backend.login`, `backend.password`, `backend.remote_access` | set by the installer, `true` | Administration credentials (the password is stored as a SHA-256 hex digest); listen on all interfaces |
| `watchers.iocs`, `watchers.whitelists` | `[]` | HTTPS feed URLs loaded by the watcher |
| `observatory.*` | disabled | Kernel observatory settings, documented in [`observatory/README.md`](observatory/README.md#settings-configyaml) |

## Kernel observatory (optional)

On Linux hosts the installer can add an opt-in **kernel observatory**: eBPF programs attached to the access-point interface count the device's traffic per flow, including protocols outside the `tcp or udp` capture filter, and record kernel drop reasons. A separate hardened service (`luca-observatory`, its own user, three capabilities, a Unix socket and no network listener) runs them, so the Flask applications gain no privileges. After a capture, the analysis correlates the kernel's counts with the pcap and the Zeek logs: a capture is reported complete only when the kernel's counts confirm it, every statement is labelled OBSERVED, CORRELATED, INFERRED or UNAVAILABLE, and traffic is never attributed to an application. The results appear as KNO-xx findings, in the PDF, and under **Kernel Observatory** in the administration interface.

It stays disabled unless you choose it at install time or run `observatory/scripts/install-observatory.sh` later, and no eBPF dependency is installed otherwise. Requirements (kernel 5.10 or newer, BTF for named drop reasons), security and privacy notes, tests and the preregistered experiments are in [`observatory/README.md`](observatory/README.md). Kernel validation so far covers CI virtual machines with veth topologies, not Wi-Fi hardware.

## Public demo

[`web-demo/`](web-demo/) is a read-only Vercel deployment: a static device-owner dashboard and a three-endpoint Flask API serving a **synthetic** report and the labelled offline observatory example. It captures nothing, controls no Wi-Fi and exposes none of Luca's capture, administration or intelligence components; it exists to show what a report looks like. Deployment steps are in [`web-demo/README.md`](web-demo/README.md).

## Services, ports and paths

| systemd unit | Program | Listens on |
| --- | --- | --- |
| `luca-frontend` | `server/frontend/main.py`: capture UI and API, no authentication | HTTP, port `frontend.http_port` (80) |
| `luca-backend` | `server/backend/main.py`: administration UI and API | HTTPS, port 443, self-signed certificate |
| `luca-watchers` | `server/backend/watchers.py`: loads indicators, allowlists and MISP data, then exits | nothing |
| `luca-kiosk` | `kiosk.sh`: fullscreen Chromium on the local display when kiosk mode is on | nothing |
| `luca-observatory` (optional) | eBPF collector service | Unix socket `/run/luca-observatory/control.sock` |

| Path | Content |
| --- | --- |
| `/usr/share/luca/` | Installed copy: `config.yaml`, `luca.sqlite3`, `VERSION`, the applications and scripts |
| `/usr/share/luca/server/backend/cert.pem`, `key.pem` | Administration TLS certificate and key, valid ten years |
| `/tmp/<TOKEN>/` | Capture sessions; removed when exported or cleaned up by the UI |
| `/tmp/hostapd.conf`, `/tmp/rules.rules` | Generated access-point and Suricata configuration |
| `/var/lib/luca-observatory/` | Kernel observatory snapshots, if installed |
| `192.168.100.1/24` | Access-point network; the device receives `.2` or `.3` |

## Updating and uninstalling

```bash
sudo bash /usr/share/luca/update.sh      # update in place
sudo bash /usr/share/luca/uninstall.sh   # remove Luca, optionally its packages, and reboot
```

`update.sh` clones the repository (override the source with `LUCA_SOURCE_REPO=<git url>`), rebuilds the Vue applications and, where installed, the observatory collector, then replaces `analysis/`, `app/`, `server/`, `assets/` and `observatory/` while keeping `config.yaml`, the database and the TLS certificate. If cloning or building fails, the installed version is left untouched. Instances installed under the upstream TinyCheck paths and service names are not migrated; install Luca fresh.

With `frontend.update` enabled the capture UI offers an **Update** page as well. Its version check compares `VERSION` with the newest tag on GitHub, and reports that no public releases are available while the repository has no tags.

`uninstall.sh` removes `/usr/share/luca`, the `luca-*` units, the dnsmasq and dhcpcd additions and the desktop launcher, asks whether to remove the packages it installed, asks for a new hostname, and reboots.

## Development

| Directory | Contents |
| --- | --- |
| [`analysis/`](analysis/) | Coordinator (`analysis.py`), Zeek, Suricata and observatory engines, PDF report, alert texts per language |
| [`server/frontend/`](server/frontend/) | Flask capture API: network, capture, device, analysis, save, misc and update blueprints |
| [`server/backend/`](server/backend/) | Flask administration API: ioc, whitelist, config, misp and observatory blueprints; `watchers.py` |
| [`app/frontend/`](app/frontend/), [`app/backend/`](app/backend/) | Vue 2 single-page applications for the capture and administration UIs |
| [`assets/`](assets/) | Bundled indicators and allowlist, SQLite schema, Python requirements, architecture diagram |
| [`observatory/`](observatory/) | Kernel observatory: BPF programs, C collector, Python service and correlation, tests, experiments |
| [`web-demo/`](web-demo/) | Synthetic public demo for Vercel |
| [`.github/workflows/`](.github/workflows/) | Continuous integration |

Running the UIs with hot reload against a local Flask application:

```bash
cd app/frontend && npm install && npm run serve   # http://localhost:4202
cd app/backend  && npm install && npm run serve   # http://localhost:4201
```

Each dev server proxies `/api` to the Flask port named in its `vue.config.js`; point it at wherever the matching Flask application listens. `npm run build` writes the `dist/` directory that Flask serves in production, and `npm run lint` runs ESLint. The capture pipeline itself needs an installed host: it drives hostapd, dnsmasq, nftables, TShark, Zeek and Suricata.

Tests that run anywhere:

```bash
# Kernel observatory unit tests: synthetic fixtures, no kernel involved
python3 -m unittest discover -s observatory/tests -p "test_*.py"

# Shell syntax of the installer and helper scripts
for f in install.sh update.sh uninstall.sh observatory/scripts/*.sh; do bash -n "$f"; done
```

The [`observatory` workflow](.github/workflows/observatory.yml) runs on every push and pull request: unit tests on Python 3.9 and 3.12, the demo API, shell syntax, eBPF smoke tests on Ubuntu 24.04 (x86-64 and arm64, TCX and clsact attachment), Debian bookworm containers with the system and a vendored libbpf, the installed systemd service end to end, and the preregistered experiments, whose results are uploaded as artifacts. There is no automated coverage of the capture pipeline or the Vue applications; changes there need a manual run on an installed host.

Contributions are welcome through issues and pull requests. Keep capture-side and administration-side changes verifiable on a real installation, keep the observatory's tests green, and never commit experiment results or captured data.

## Limitations and operational security

- **Traffic visibility is not endpoint visibility.** Luca sees network evidence only; it does not inspect installed apps, local files or memory.
- **Encryption limits inspection.** Domain names, certificate metadata and connection patterns remain visible; encrypted payloads are not decrypted.
- **Heuristics are probabilistic.** Benign services trigger alerts, and malicious traffic can evade the available rules and indicators. The capture filter keeps TCP and UDP only.
- **The capture UI has no login.** With `frontend.remote_access: true` (the default) it listens on every interface. The inspected device is blocked from it by an nftables rule, but anything else on the upstream network can start captures, read reports and, where the options are enabled, download sessions or reboot the host. Set it to `false` or keep the host on an isolated network.
- **Active lookups talk to third parties.** With `analysis.active` enabled, Luca sends DNS name-server queries and WHOIS lookups for every destination it saw, revealing those hosts to resolvers and registries. Disable it for sensitive cases.
- **Captures contain sensitive data.** PCAPs, exported ZIPs, reports and the administration interface identify the device and everything it talked to. Restrict access to them. Sessions live under `/tmp`, which is usually cleared at reboot, so export what you need first.
- **The access point is 2.4 GHz only** (`hw_mode=g`), with the regulatory domain hard-coded to `GB` in [`server/frontend/app/assets/hostapd.conf`](server/frontend/app/assets/hostapd.conf). Adjust the country code for your location.
- **The stack is legacy.** Flask 1.1, SQLAlchemy 1.4, Vue 2 with Vue CLI 4 and Node.js 14 from NodeSource are pinned in [`assets/requirements.txt`](assets/requirements.txt) and the `package.json` files. Review and harden them, the self-signed certificate and both `remote_access` settings before using Luca outside a controlled environment.
- **Inspect only devices and networks you own or are authorized to assess.**

## License and acknowledgements

Luca is released under the [Apache License 2.0](LICENSE.txt). It is a derivative of [TinyCheck](https://github.com/KasperskyLab/TinyCheck) by Kaspersky, also Apache 2.0: Luca renames the runtime (`/usr/share/luca`, `luca-*` services, `luca.local`), seeds the indicator database from a bundled set, and adds the kernel observatory and the public demo. The BPF programs and the collector in [`observatory/`](observatory/) are dual-licensed GPL-2.0-only OR BSD-2-Clause.

Luca stands on [Zeek](https://zeek.org/), [Suricata](https://suricata.io/), [TShark](https://www.wireshark.org/), [hostapd](https://w1.fi/hostapd/), [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html), [WeasyPrint](https://weasyprint.org/), Flask and Vue. Third-party licenses and attributions are listed in [`NOTICE.txt`](NOTICE.txt).
