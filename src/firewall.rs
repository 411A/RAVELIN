use anyhow::{Context, Result, bail};
use std::{
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
    process::Command,
};

use crate::constants::{INSTALLER_SCRIPT, IPSET_NAME, SETUP_PATH};

pub fn system_self_check() -> Result<()> {
    let has_ipset = command_exists("ipset")?;
    let has_suricata = command_exists("suricata")?;

    if !has_ipset || !has_suricata {
        println!(
            "Dependencies missing or updates needed. Running embedded installer script with elevated privileges..."
        );
    } else {
        println!("Verifying Ravelin firewall rules...");
    }

    let script = INSTALLER_SCRIPT.replace('\r', "");
    fs::write(SETUP_PATH, script)
        .with_context(|| format!("failed to write setup script at {SETUP_PATH}"))?;
    fs::set_permissions(SETUP_PATH, Permissions::from_mode(0o755))
        .with_context(|| format!("failed to chmod setup script at {SETUP_PATH}"))?;

    run_checked(
        privileged_command("bash", &[SETUP_PATH]),
        "Ravelin dependency and firewall setup",
    )
}

pub fn block_ipset(ip: &str) -> Result<()> {
    ensure_ipset()?;
    run_checked(
        privileged_command("ipset", &["add", IPSET_NAME, ip, "-exist"]),
        &format!("adding {ip} to ipset {IPSET_NAME}"),
    )
}

pub fn unblock_ipset(ip: &str) -> Result<()> {
    run_checked(
        privileged_command("ipset", &["del", IPSET_NAME, ip, "-exist"]),
        &format!("removing {ip} from ipset {IPSET_NAME}"),
    )
}

pub fn restore_blocked_ips<'a>(ips: impl IntoIterator<Item = &'a str>) -> Result<()> {
    ensure_ipset()?;
    for ip in ips {
        run_checked(
            privileged_command("ipset", &["add", IPSET_NAME, ip, "-exist"]),
            &format!("restoring {ip} into ipset {IPSET_NAME}"),
        )?;
    }

    Ok(())
}

fn ensure_ipset() -> Result<()> {
    run_checked(
        privileged_command(
            "ipset",
            &["create", IPSET_NAME, "hash:ip", "timeout", "0", "-exist"],
        ),
        &format!("creating ipset {IPSET_NAME}"),
    )
}

fn command_exists(binary: &str) -> Result<bool> {
    let output = Command::new("which")
        .arg(binary)
        .output()
        .with_context(|| format!("failed to check whether {binary} exists"))?;

    Ok(output.status.success())
}

fn privileged_command(program: &str, args: &[&str]) -> Command {
    let mut command = if running_as_root() {
        Command::new(program)
    } else {
        let mut sudo = Command::new("sudo");
        sudo.arg("-n").arg(program);
        sudo
    };

    command.args(args);
    command
}

fn running_as_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .is_some_and(|uid| uid.trim() == "0")
}

fn run_checked(mut command: Command, description: &str) -> Result<()> {
    let output = command
        .output()
        .with_context(|| format!("failed to start {description}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };

    bail!(
        "{description} failed with status {}: {details}",
        output.status
    );
}
