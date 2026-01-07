#![deny(clippy::all, clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::cast_possible_wrap
)]

use android_logger::Config;
use log::{info, LevelFilter};
use anyhow::Result;

mod apk_sign;
mod assets;
mod boot_patch;
#[cfg(target_os = "android")]
mod cli;
#[cfg(not(target_os = "android"))]
mod cli_non_android;
#[cfg(target_os = "android")]
mod debug;
mod defs;
#[cfg(target_os = "android")]
mod feature;
#[cfg(target_os = "android")]
mod init_event;
#[cfg(target_os = "android")]
mod ksucalls;
#[cfg(target_os = "android")]
mod metamodule;
#[cfg(target_os = "android")]
mod module;
#[cfg(target_os = "android")]
mod module_config;
#[cfg(target_os = "android")]
mod profile;
#[cfg(target_os = "android")]
mod restorecon;
#[cfg(target_os = "android")]
mod sepolicy;
#[cfg(target_os = "android")]
mod su;
#[cfg(target_os = "android")]
mod utils;

fn main() -> Result<()> {
    #[cfg(target_os = "android")]
    {
        // 初始化日志系统，设置 logcat 的 tag 和最高日志级别
        android_logger::init_once(
            Config::default()
                .with_tag("KernelSUNB")   // 在 logcat 中显示的 tag
                .with_max_level(LevelFilter::Info), // 替换为正确的方法
        );

        // 打印一条测试日志，确认 Rust 日志能进入 logcat
        info!("Rust logger initialized successfully, hello from KernelSUNB!");

        cli::run()
    }
    #[cfg(not(target_os = "android"))]
    {
        cli_non_android::run()
    }
}
