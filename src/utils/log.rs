use std::{
    fs::OpenOptions,
    sync::{OnceLock},
};
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
            .with_filter(EnvFilter::new(level));

        // Secondary log file only in debug
        #[cfg(debug_assertions)]
        let flow_layer = fmt::layer()
            .with_writer(OpenOptions::new()
                .create(true)
                .append(true)
                .open(std::env::temp_dir().join("uds-cred-prov-flow.log"))
                .expect("Failed to open flow log file"))
            .with_ansi(false)
            .with_target(true)
            .with_level(true)
            .with_filter(EnvFilter::new("flow=debug"));        

        // Registro final
        #[cfg(debug_assertions)]
        tracing_subscriber::registry()
            .with(main_layer)
            .with(flow_layer)
        .try_init()
        .ok();

        #[cfg(not(debug_assertions))]
        tracing_subscriber::registry()
            .with(main_layer)
            .try_init()
            .ok();
    });
}

#[cfg(debug_assertions)]
pub static FLOW_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[macro_export]
macro_rules! debug_flow {
    ($($arg:tt)*) => {{
        #[cfg(debug_assertions)]
        {
            let count = $crate::utils::log::FLOW_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if count == 1 {
                tracing::info!(target: "flow", "----------------------------------------");
            }
            tracing::info!(target: "flow", "[#{count:5}] {}", format_args!($($arg)*));
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
