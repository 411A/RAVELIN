**RAVELIN** *(French “[ravelin](https://en.wikipedia.org/wiki/Ravelin)”, an outer defensive fortification)*: **R**ust-powered **A**daptive **V**igilance & **E**nforcement — **L**ayered **I**ntelligent **I**nterceptor **N**ode

A real-time, terminal-based intrusion prevention system (IPS) that monitors system logs, visualizes threats, and actively manages network blocks using `ipset`.

## Prerequisites

Ravelin relies on system-level tools for log generation and firewall management.

```shell
# 1. Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 2. Install Dependencies (Debian/Ubuntu)
# libsqlite3-dev: Database
# suricata: IDS/Log generation
# ipset: Blocking mechanism
# tmux: Background session management
sudo apt update && sudo apt install -y build-essential libsqlite3-dev suricata ipset tmux
```

## Build

```shell
cargo build --release
```

## Deployment

Ravelin must run with `sudo` permissions to modify firewall rules and read system logs. Use `tmux` to keep the process running in the background.

```shell
# Create session, rename it, and run the binary
tmux new -s ravelin
sudo ./target/release/ravelin
```

## Controls

| Key | Action |
| :--- | :--- |
| **TAB** | Switch between Suspects and Blocked lists |
| **j / k** | Navigate Up/Down |
| **h / l** | Scroll Details Left/Right |
| **Enter** | Block Suspect / Unblock IP |
| **i** | Inspect detailed history for selected IP |
| **/** | Search/Filter Suspects |
| **:** | Command Mode (e.g., `:clearlogs`, `:whitelist <ip>`) |
| **q** | Quit |

---

### ⚙️ Code Configuration Guide

Based on the `main.rs` provided, here are the specific sections you may need to modify to fit your specific server environment or operational needs.

#### 1. Operational Configuration

These constants control the behavior of the application.

```rust
const DB_URL: &str = "sqlite://ravelin.db?mode=rwc";
const LEARNING_PERIOD_HOURS: i64 = 12; // Time before auto-blocking/strict mode begins
const LOG_CAP: usize = 100;            // Max lines in the "Live Feed" window
const HISTORY_CAP: usize = 500;        // Max raw log lines stored per IP (for Inspect mode)
```

#### 2. Log Paths

In `fn harvest_logs`, check that these paths match your Linux distribution:
*   **Suricata:** Defaults to `/var/log/suricata/eve.json`.
*   **SSH:** Defaults to checking `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS).
*   **Docker:** Automatically grabs logs from running containers.

#### 3. Log Parsing Regex
If you use a non-standard SSH port, a different web server (Nginx vs Apache), or a specific log format, you may need to tweak these Regex patterns:

```rust
// Matches standard SSH login success
static ref RE_SSH_SUCCESS: Regex = ...
// Matches SSH failures (Brute force attempts)
static ref RE_SSH_FAIL: Regex = ...
// Matches HTTP 400/500 errors (Web scanning/fuzzing)
static ref RE_HTTP_ERROR: Regex = ...
```

#### 4. Blocking Logic

The `block_ip` function uses `ipset` and `iptables`.
*   If your system uses `nftables` natively or `ufw` (Uncomplicated Firewall), you may need to change the `Command::new("sudo")` arguments to use those tools instead of `ipset`.

#### 5. Whitelisting

To prevent locking yourself out, you can manually whitelist your IP in the UI command mode:

```text
:whitelist 192.168.1.50
```
