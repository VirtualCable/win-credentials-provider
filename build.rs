// Copyright (c) 2025 Virtual Cable S.L.U.
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
use chrono::Datelike;
use std::path::PathBuf;
use winres::WindowsResource;

fn main() {
    println!("cargo:rerun-if-changed=protobuf/auth.proto");
    println!("cargo:rerun-if-changed=img/uds.bmp");

    let out_dir = PathBuf::from("src/messages");
    std::fs::create_dir_all(&out_dir).unwrap();

    prost_build::Config::new()
        .btree_map(["."])
        .out_dir(out_dir)
        .compile_protos(&["protobuf/auth.proto"], &["protobuf"])
        .unwrap();
    let current_year = chrono::Utc::now().year();
    let base_date = chrono::NaiveDate::from_ymd_opt(1972, 7, 1).unwrap();
    let today = chrono::Utc::now().date_naive();
    let build_days = (today - base_date).num_days();

    let (major, minor, patch, build) = (
        env!("CARGO_PKG_VERSION_MAJOR").parse::<u64>().unwrap(),
        env!("CARGO_PKG_VERSION_MINOR").parse::<u64>().unwrap(),
        env!("CARGO_PKG_VERSION_PATCH").parse::<u64>().unwrap(),
        build_days as u64,
    );

    let version: u64 = (major << 48) | (minor << 32) | (patch << 16) | build;
    // Set executable metadata with winres

    let mut res = WindowsResource::new();
    res.set_icon("img/uds.ico");

    res.set_version_info(winres::VersionInfo::FILEVERSION, version);
    res.set_version_info(winres::VersionInfo::PRODUCTVERSION, version);

    res.set_language(0x0409);

    res.set("FileVersion", &format!("{major}.{minor}.{patch}.{build}"));
    res.set("ProductVersion", &format!("{major}.{minor}.{patch}.{build}"));
    res.set("ProductName", "UDS Credential Provider");
    res.set("FileDescription", "UDS SSO System");
    res.set(
        "LegalCopyright",
        format!("Copyright © 2012-{current_year} Virtual Cable S.L.U.").as_str(),
    );
    res.set("CompanyName", "Virtual Cable S.L.U.");

    res.append_rc_content(r##"101      BITMAP      DISCARDABLE "img/uds.bmp""##);

    // Compile resources
    res.compile().unwrap();
}
