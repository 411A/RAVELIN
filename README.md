# RAVELIN

<p align="center">
  <img src="https://github.com/user-attachments/assets/79098cb5-af7a-4343-9469-53d6d220410a" width="29%" alt="RAVELIN Logo by Ali Abdi">
</p>

**RAVELIN** *(French “[ravelin](https://en.wikipedia.org/wiki/Ravelin)”, an outer defensive fortification)*: **R**ust-powered **A**daptive **V**igilance & **E**nforcement — **L**ayered **I**ntelligent **I**nterceptor **N**ode

RAVELIN is a real-time Linux VPS protection TUI/backbone. It reads Suricata `eve.json`, tracks short per-IP behavior windows, visualizes suspicious traffic, and manages `ipset` blocks with bounded memory use.

It uses request and response metadata, including HTTP status codes, so isolated failures are not treated the same as bursty, repetitive, or IDS-confirmed attack behavior.

## What It Does

- Processes Suricata alerts and HTTP request/response metadata from `/var/log/suricata/eve.json`.
- Keeps bounded in-memory state: short UI logs, short suspect detail history, compact dedupe hashes, and compact HTTP behavior windows.
- Scores IDS alerts, HTTP error bursts, high-volume success bursts, and predictable request cadence.
- Avoids blocking local, private, already-blocked, and trusted IPs.
- Auto-blocks only after learning mode and only when score, event count, and high-confidence requirements are met.

## Safety Model

RAVELIN treats Suricata as the packet sensor and the Rust engine as the decision layer. Successful sparse traffic, webhook retries, and occasional errors are tracked but not immediately punished. Automated blocking requires repeated evidence and high-confidence signals, reducing the risk of blocking legitimate services such as Cloudflare, Telegram, or other upstream providers.

## Install

Latest Linux x86_64 release:

```shell
curl -fsSL https://raw.githubusercontent.com/411A/RAVELIN/main/install-latest.sh | sudo sh
```

Build from source:

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
sudo apt update
sudo apt install -y build-essential libsqlite3-dev suricata ipset iproute2
cargo build --release
```

## Run

```shell
# TUI only; protection backbone is managed separately.
./target/release/ravelin

# Backbone only; stop with systemctl/SIGTERM, not the TUI.
sudo ./target/release/ravelin daemon

# TUI and backbone in one foreground root process.
sudo ./target/release/ravelin standalone
```

Useful environment variable:

```shell
export RAVELIN_TRUSTED_IPS="203.0.113.10,198.51.100.20"
```

## TUI Controls

| Key / Command | Action |
| --- | --- |
| `q`, `Esc` | Exit TUI gracefully |
| `Tab` | Switch suspects/blocked panes |
| `j`, `k` | Move selection |
| `Enter` | Block selected suspect or unblock selected IP |
| `i` | Inspect selected suspect |
| `/text` | Filter suspects |
| `:block <ip>` | Manually block IP |
| `:unblock <ip>` | Unblock IP |
| `:whitelist <ip>` | Trust IP for current run |
| `:clearlogs` | Clear TUI log pane |

## Notes

- RAVELIN writes `ravelin.db` locally and restores persisted blocks on startup.
- The installer self-check configures `ipset`, `iptables`, and Suricata log rotation.
- If your services sit behind Cloudflare or another proxy, configure Suricata/reverse-proxy logging so the real client IP is visible before enabling automated blocking.
