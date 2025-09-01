use std::{fs::OpenOptions, sync::OnceLock};
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use widestring::U16CString;
use windows::Win32::System::Diagnostics::Debug::OutputDebugStringW;
use windows::core::PCWSTR;

// Reexport to avoid using crate names for tracing
pub use tracing::{debug, error, info, trace, warn};

static LOGGER_INIT: OnceLock<()> = OnceLock::new();
pub static LOG_FLOW_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
pub static FLOW_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
pub static LAST_STEP: std::sync::OnceLock<std::sync::RwLock<std::time::Instant>> =
    std::sync::OnceLock::new();

pub fn output_debug_string(s: &str) {
    {
        let wide = U16CString::from_str(s).unwrap_or_default();
        unsafe { OutputDebugStringW(PCWSTR(wide.as_ptr())) };
    }
}

pub fn setup_logging(level: &str) {
    // if UDSCP_LOG_LEVEL is on env, use it intead of level
    let level = std::env::var("UDSCP_LOG_LEVEL").unwrap_or_else(|_| level.to_string());
    let log_path = std::env::var("UDSCP_LOG_PATH").unwrap_or_else(|_| {
        std::env::temp_dir().to_string_lossy().into()
    });

    // Bridge log crate logs to tracing
    LOGGER_INIT.get_or_init(|| {
        // Main log file
        let main_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(std::path::Path::new(&log_path).join("uds-cred-prov.log"))
            .expect("Failed to open main log file");

        let main_layer = fmt::layer()
            .with_writer(main_file)
            .with_ansi(false)
            .with_target(true)
            .with_level(true)
            .with_filter(EnvFilter::new(format!("{},flow=off", level)));

        // Secondary log file only in debug
        LOG_FLOW_ENABLED.store(
            std::env::var("UDSCP_ENABLE_FLOW_LOG").unwrap_or_default() == "1",
            std::sync::atomic::Ordering::Relaxed,
        );
        let use_flow_log = LOG_FLOW_ENABLED.load(std::sync::atomic::Ordering::Relaxed);
        if use_flow_log {
            let flow_layer = fmt::layer()
                .with_writer(
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(std::path::Path::new(&log_path).join("uds-cred-prov-flow.log"))
                        .expect("Failed to open flow log file"),
                )
                .with_ansi(false)
                .with_target(true)
                .with_level(true)
                .with_filter(EnvFilter::new("flow=debug"));

            // Register
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
                tracing::info!(target: "flow", "[#{count:5}][{:>5} ms] {}", last_guard.read().unwrap().elapsed().as_millis(), format_args!($($arg)*));
                *last_guard.write().unwrap() = std::time::Instant::now();
            }
    }};
}

#[macro_export]
macro_rules! debug_dev {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            tracing::info!($($arg)*);
            let s = format!($($arg)*);
            $crate::utils::log::output_debug_string(&s);
        }
    };
}
