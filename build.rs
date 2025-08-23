use chrono::Datelike;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use winres::WindowsResource;

fn main() {
    println!("cargo:rerun-if-changed=protobuf/auth.proto");
    println!("cargo:rerun-if-changed=img/uds.bmp");

    let out_dir = PathBuf::from("src/messages");
    std::fs::create_dir_all(&out_dir).unwrap();

    prost_build::Config::new()
        .btree_map(&["."])
        .out_dir(out_dir)
        .compile_protos(&["protobuf/auth.proto"], &["protobuf"])
        .unwrap();
    let current_year = chrono::Utc::now().year();
    let base_date = chrono::NaiveDate::from_ymd_opt(1972, 7, 1).unwrap();
    let today = chrono::Utc::now().date_naive();
    let build_days = (today - base_date).num_days();

    // Path to the VERSION file
    let version_path = Path::new("../../../../openuds/VERSION");

    // Read the base version
    let base_version = fs::read_to_string(version_path).unwrap_or_else(|_| "0.0.0".to_string());

    // Build the full version string
    let full_version = format!("{}.{}", base_version.trim(), build_days);

    // Inject environment variable for use with env!("LAUNCHER_VERSION")
    println!("cargo:rustc-env=LAUNCHER_VERSION={}", full_version);
    let version_parts: Vec<u64> = full_version
        .split('.')
        .map(|s| s.parse().unwrap_or(0))
        .collect();
    // Ensure version has 4 parts or raise an error

    if version_parts.len() < 4 {
        panic!("Version string must have 4 parts: {}", full_version);
    }
    let (major, minor, patch, build) = (
        version_parts[0],
        version_parts[1],
        version_parts[2],
        version_parts[3],
    );

    let version: u64 = (major << 48) | (minor << 32) | (patch << 16) | build;
    // Set executable metadata with winres

    let mut res = WindowsResource::new();
    res.set_icon("img/uds.ico");

    res.set_version_info(winres::VersionInfo::FILEVERSION, version);
    res.set_version_info(winres::VersionInfo::PRODUCTVERSION, version);

    res.set_language(0x0409);

    res.set("FileVersion", &full_version);
    res.set("ProductVersion", &full_version);
    res.set("ProductName", "UDS RDS Launcher");
    res.set("FileDescription", "UDS RDS Server Launcher helper");
    res.set(
        "LegalCopyright",
        format!("Copyright © 2012-{current_year} Virtual Cable S.L.U.").as_str(),
    );
    res.set("CompanyName", "Virtual Cable S.L.U.");

    res.append_rc_content(r##"101      BITMAP      DISCARDABLE "img/uds.bmp""##);

    // Compile resources
    res.compile().unwrap();
}
