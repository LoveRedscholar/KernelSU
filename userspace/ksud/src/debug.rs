use anyhow::{Context, Result, bail, ensure};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

use crate::ksucalls;
use log::warn;

const KERNEL_PARAM_PATH: &str = "/sys/module/kernelsu";

fn read_u32(path: &PathBuf) -> Result<u32> {
    let content = std::fs::read_to_string(path)?;
    let content = content.trim();
    let content = content.parse::<u32>()?;
    Ok(content)
}

fn set_kernel_param(uid: u32) -> Result<()> {
    let kernel_param_path = Path::new(KERNEL_PARAM_PATH).join("parameters");

    let ksu_debug_manager_uid = kernel_param_path.join("ksu_debug_manager_uid");
    let before_uid = read_u32(&ksu_debug_manager_uid)?;
    std::fs::write(&ksu_debug_manager_uid, uid.to_string())?;
    let after_uid = read_u32(&ksu_debug_manager_uid)?;

    warn!("set manager uid: {} -> {}", before_uid, after_uid);

    Ok(())
}

fn get_pkg_uid(pkg: &str) -> Result<u32> {
    // stat /data/data/<pkg>
    let uid = rustix::fs::stat(format!("/data/data/{pkg}"))
        .with_context(|| format!("stat /data/data/{pkg}"))?
        .st_uid;
    Ok(uid)
}

pub fn set_manager(pkg: &str) -> Result<()> {
    ensure!(
        Path::new(KERNEL_PARAM_PATH).exists(),
        "CONFIG_KSU_DEBUG is not enabled"
    );

    let uid = get_pkg_uid(pkg)?;
    warn!("[DEBUG-SU] pkg={} uid={} is trying to become Debug Manager", pkg, uid);

    set_kernel_param(uid)?;
    warn!("[DEBUG-SU] Debug Manager UID set successfully for pkg={} uid={}", pkg, uid);

    let _ = Command::new("am").args(["force-stop", pkg]).status();
    warn!("[DEBUG-SU] force-stopped pkg={} to refresh UID setting", pkg);

    Ok(())
}

/// Get mark status for a process
pub fn mark_get(pid: i32) -> Result<()> {
    let result = ksucalls::mark_get(pid)?;
    if pid == 0 {
        bail!("Please specify a pid to get its mark status");
    }
    warn!(
        "Process {} mark status: {}",
        pid,
        if result != 0 { "marked" } else { "unmarked" }
    );
    Ok(())
}

/// Mark a process
pub fn mark_set(pid: i32) -> Result<()> {
    ksucalls::mark_set(pid)?;
    if pid == 0 {
        warn!("All processes marked successfully");
    } else {
        warn!("Process {} marked successfully", pid);
    }
    Ok(())
}

/// Unmark a process
pub fn mark_unset(pid: i32) -> Result<()> {
    ksucalls::mark_unset(pid)?;
    if pid == 0 {
        warn!("All processes unmarked successfully");
    } else {
        warn!("Process {} unmarked successfully", pid);
    }
    Ok(())
}

/// Refresh mark for all running processes
pub fn mark_refresh() -> Result<()> {
    ksucalls::mark_refresh()?;
    warn!("Refreshed mark for all running processes");
    Ok(())
}