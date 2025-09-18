// Copyright (c) 2026 Virtual Cable S.L.U.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
//    * Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above copyright notice,
//      this list of conditions and the following disclaimer in the documentation
//      and/or other materials provided with the distribution.
//    * Neither the name of Virtual Cable S.L.U. nor the names of its contributors
//      may be used to endorse or promote products derived from this software
//      without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
/*!
Author: Adolfo Gómez, dkmaster at dkmon dot com
*/
use std::{fs, fs::OpenOptions, io, path::PathBuf, sync::OnceLock};
use tracing_subscriber::{
    EnvFilter, Layer, filter::filter_fn, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};

// Reexport to avoid using crate names for tracing
pub use tracing::{debug, error, info, trace, warn};

static LOGGER_INIT: OnceLock<()> = OnceLock::new();
pub static LOG_FLOW_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
pub static FLOW_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
pub static LAST_STEP: std::sync::OnceLock<std::sync::RwLock<std::time::Instant>> =
    std::sync::OnceLock::new();

struct RotatingWriter {
    path: PathBuf,
    max_size: u64,    // Max size in bytes before rotation
    max_files: usize, // Number of rotations to keep
}

impl RotatingWriter {
    fn rotate_if_needed(&self) -> io::Result<()> {
        if let Ok(meta) = fs::metadata(&self.path)
            && meta.len() >= self.max_size
        {
            // Remove last if needed
            if self.max_files > 1 {
                let last = self.path.with_extension(format!("log.{}", self.max_files));
                let _ = fs::remove_file(&last);
                // Rename in reverse order
                for i in (1..self.max_files).rev() {
                    let src = self.path.with_extension(format!("log.{}", i));
                    let dst = self.path.with_extension(format!("log.{}", i + 1));
                    let _ = fs::rename(&src, &dst);
                }
                // Rename current to .log.1
                let rotated = self.path.with_extension("log.1");
                let _ = fs::rename(&self.path, rotated);
            } else {
                // if max_files is 1, just remove current
                let _ = fs::remove_file(&self.path);
            }
        }
        Ok(())
    }
}

impl<'a> fmt::MakeWriter<'a> for RotatingWriter {
    type Writer = fs::File;

    fn make_writer(&'a self) -> Self::Writer {
        // Rotate if needed
        let _ = self.rotate_if_needed();
        // Always open in append mode, creating it if it doesn't exist
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .unwrap_or_else(|e| panic!("Failed to open log file {:?}: {}", self.path, e))
    }
}

pub fn setup_logging(level: &str) {
    let level = std::env::var("UDSCP_LOG_LEVEL").unwrap_or_else(|_| level.to_string());
    let log_path = std::env::var("UDSCP_LOG_PATH")
        .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into());

    LOGGER_INIT.get_or_init(|| {
        let main_layer = fmt::layer()
            .with_writer(RotatingWriter {
                path: std::path::Path::new(&log_path).join("uds-cred-prov.log"),
                max_size: 16 * 1024 * 1024, // 16 MB
                max_files: 2,
            })
            .with_ansi(false)
            .with_target(true)
            .with_level(true)
            .with_filter(EnvFilter::new(format!("{},flow=off", level)));

        LOG_FLOW_ENABLED.store(
            std::env::var("UDSCP_ENABLE_FLOW_LOG").unwrap_or_default() == "1",
            std::sync::atomic::Ordering::Relaxed,
        );

        let use_flow_log = LOG_FLOW_ENABLED.load(std::sync::atomic::Ordering::Relaxed);
        if use_flow_log {
            let flow_layer = fmt::layer()
                .with_writer(RotatingWriter {
                    path: std::path::Path::new(&log_path).join("uds-cred-prov-flow.log"),
                    max_size: 16 * 1024 * 1024, // 10 MB
                    max_files: 2,
                })
                .with_ansi(false)
                .with_target(true)
                .with_level(true)
                .with_filter(filter_fn(|meta| meta.target() == "flow"));

            tracing_subscriber::registry()
                .with(main_layer)
                .with(flow_layer)
                .try_init()
                .ok();
        } else {
            tracing_subscriber::registry()
                .with(main_layer)
                .try_init()
                .ok();
        }

        info!("Logging initialized with level: {}", level);
    });
}
pub fn reset_flow_counter() {
    FLOW_COUNTER.store(0, std::sync::atomic::Ordering::Relaxed);
    LAST_STEP
        .set(std::sync::RwLock::new(std::time::Instant::now()))
        .ok();
}

#[macro_export]
macro_rules! debug_flow {
    ($($arg:tt)*) => {{
        if $crate::utils::log::LOG_FLOW_ENABLED.load(std::sync::atomic::Ordering::Relaxed)
            {
                let count = $crate::utils::log::FLOW_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let last_guard = $crate::utils::log::LAST_STEP.get_or_init(|| std::sync::RwLock::new(std::time::Instant::now()));
                if count == 1 {
                    tracing::info!(target: "flow", "----------------------------------------");
                }
                let s = format!($($arg)*);
                tracing::info!(target: "flow", "[#{count:5}][{:>5} ms] {}", last_guard.read().unwrap().elapsed().as_millis(), s);
                *last_guard.write().unwrap() = std::time::Instant::now();
            }
    }};
}

#[macro_export]
macro_rules! debug_dev {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            let s = format!($($arg)*);
            tracing::info!(target: "dev", "{}", s);
        }
    };
}
