pub fn setup_logging(level: &str) {
    // log file, located on home directory of current user
    let log_file = std::env::temp_dir().join("uds-cred-prov.log");
    // Note that on tests, log_file will be overridden to stderr
    // but in production, it will be created in the temp directory
    // We need the allow(unused_variables) to avoid warnings about the log_file variable
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
        .expect("Failed to open log file");
    // On testing, just output to stderr, overriding the log file
    #[allow(unused_variables)]
    let target = env_logger::Target::Pipe(Box::new(log_file));
    #[cfg(test)]
    let target = env_logger::Target::Stderr;

    let level = if let Ok(debug_level) = std::env::var("UDSCP_DEBUG") {
        log::info!("RUST_LOG is set, using its value instead of the provided level");
        debug_level
    } else {
        level.to_string()
    };

    // If already initialized, do not fail
    if env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&level))
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
        .format_module_path(false)
        .format_target(true)
        .format_level(true)
        .target(target)
        .try_init()
        .is_err()
    {
        log::warn!("Logger already initialized, skipping setup.");
    } else {
        log::info!("Logger initialized with level: {}", level)
    }
}
