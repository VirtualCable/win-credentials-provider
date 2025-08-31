use std::{fs::OpenOptions, sync::OnceLock};
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

// Reexport to avoid using crate names for tracing
pub use tracing::{debug, error, info, trace, warn};

static LOGGER_INIT: OnceLock<()> = OnceLock::new();

pub fn setup_logging(level: &str) {
    // Bridge log crate logs to tracing
    LOGGER_INIT.get_or_init(|| {
        // Main log file
        let main_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(std::env::temp_dir().join("uds-cred-prov.log"))
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
                        .open(std::env::temp_dir().join("uds-cred-prov-flow.log"))
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
    });
}

pub static LOG_FLOW_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
pub static FLOW_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
pub static LAST_STEP: std::sync::OnceLock<std::sync::RwLock<std::time::Instant>> =
    std::sync::OnceLock::new();

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
        }
    };
}
