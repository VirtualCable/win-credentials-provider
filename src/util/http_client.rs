use anyhow::{Context, Result};
use std::{collections::HashMap, os::raw::c_void};
use windows::{
    Win32::{Foundation::*, Networking::WinHttp::*},
    core::*,
};

pub struct HttpResponse {
    pub status_code: u32,
    pub body: String,
    pub headers: HashMap<String, String>, // Headers
}

pub struct HttpRequestClient {
    pub verify_ssl: bool,
    pub proxy: Option<String>,             // Proxy
    pub proxy_bypass_list: Option<String>, // Bypass list
}

#[derive(Debug)]
pub struct WinHttpHandle {
    ptr: *mut std::ffi::c_void,
}

impl WinHttpHandle {
    pub fn from_ptr(ptr: *mut std::ffi::c_void) -> Result<Self> {
        // If null, raise an error
        if ptr.is_null() {
            // Get windows last error
            let last_error = unsafe { GetLastError().0 };
            return Err(anyhow::anyhow!(
                "Null pointer passed to WinHttpHandle: {last_error}"
            ));
        }
        Ok(Self { ptr })
    }

    pub fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.ptr
    }
}

/// Helper Function to Convert Any Type to a Byte Slice
fn as_u8_slice<T>(val: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>()) }
}

impl Drop for WinHttpHandle {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                // Simply ignore close handle errors. Maybe log them in a future?
                WinHttpCloseHandle(self.ptr)
                    .ok()
                    .context("WinHttpCloseHandle failed")
                    .unwrap_or_default();
            }
            self.ptr = std::ptr::null_mut();
        }
    }
}
// Request client

impl HttpRequestClient {
    pub fn new() -> Self {
        Self {
            verify_ssl: true,
            proxy: None,
            proxy_bypass_list: None,
        }
    }

    pub fn with_ignore_ssl(mut self) -> Self {
        self.verify_ssl = false;
        self
    }

    
    #[allow(dead_code)]
    pub fn with_proxy<S: Into<String>>(mut self, proxy: S) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    #[allow(dead_code)]
    pub fn with_proxy_bypass_list<S: Into<String>>(mut self, bypass: S) -> Self {
        self.proxy_bypass_list = Some(bypass.into());
        self
    }

    pub fn parse_url(url: &str) -> Result<(bool, String, String, u16)> {
        let (use_ssl, rest) = if url.starts_with("http://") {
            (false, &url[7..])
        } else if url.starts_with("https://") {
            (true, &url[8..])
        } else {
            anyhow::bail!("Invalid URL: {url}");
        };

        let mut parts = rest.splitn(2, '/');
        let host_port = parts.next().unwrap_or("");
        let mut host_port_split = host_port.splitn(2, ':');
        let server = host_port_split.next().unwrap_or("").to_string();
        let port_str = host_port_split.next().unwrap_or("");
        let port = if port_str.is_empty() {
            if use_ssl { 443 } else { 80 }
        } else {
            port_str
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid port number in URL: {url}"))?
        };
        let path = format!("/{}", parts.next().unwrap_or(""));

        Ok((use_ssl, server, path, port))
    }

    pub fn get(&self, url: &str, headers: HashMap<String, String>) -> Result<HttpResponse> {
        let (use_ssl, server, path, port) = Self::parse_url(url)?;
        self.do_request("GET", use_ssl, &server, &path, port, headers, None)
    }

    pub fn do_request(
        &self,
        method: &str,
        use_ssl: bool,
        server: &str,
        path: &str,
        port: u16,
        headers: HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse> {
        // Ensures that the pointers live long enough by asssigning vars
        let mut _proxy_wide: Option<widestring::U16CString> = None;
        let mut _bypass_wide: Option<widestring::U16CString> = None;

        let (access_type, proxy_pcwstr, bypass_pcwstr) = if let Some(proxy) = &self.proxy {
            _proxy_wide = Some(widestring::U16CString::from_str(proxy)?);

            if let Some(bypass) = &self.proxy_bypass_list {
                _bypass_wide = Some(widestring::U16CString::from_str(bypass)?);
            }

            (
                WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                _proxy_wide.as_ref().map_or(PCWSTR::null(), |p| PCWSTR::from_raw(p.as_ptr())),
                _bypass_wide.as_ref().map_or(PCWSTR::null(), |b| PCWSTR::from_raw(b.as_ptr())),
            )
        } else {
            (WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, PCWSTR::null(), PCWSTR::null())
        };

        // Ahora sí, proxy_wide y bypass_wide viven hasta aquí
        let hsession = WinHttpHandle::from_ptr(unsafe {
            WinHttpOpen(
                w!("RustClientHttpWin/1.0"),
                access_type,
                proxy_pcwstr,
                bypass_pcwstr,
                0,
            )
        })?;
        let wide_server = widestring::U16CString::from_str(server)
            .context("Failed to convert server name to wide string")?;

        let hconnect = WinHttpHandle::from_ptr(unsafe {
            WinHttpConnect(
                hsession.as_ptr(),
                PCWSTR::from_raw(wide_server.as_ptr()),
                port,
                0,
            )
        })?;

        let flags = if use_ssl {
            WINHTTP_FLAG_SECURE
        } else {
            WINHTTP_OPEN_REQUEST_FLAGS::default()
        };

        // accepted types are all *const windows_sys::core::PCWSTR
        let accept_types: [PCWSTR; 2] = [windows::core::w!("*/*"), PCWSTR::null()];

        // Ensures the pointer is valid assigning a valid lifetime
        let verb_cstr = widestring::U16CString::from_str(method)?;
        let verb_wide = PCWSTR::from_raw(verb_cstr.as_ptr());

        let path_cstr = widestring::U16CString::from_str(path)
            .context("Failed to convert path to wide string")?;
        let path_wide = PCWSTR::from_raw(path_cstr.as_ptr());

        let hrequest = WinHttpHandle::from_ptr(unsafe {
            WinHttpOpenRequest(
                hconnect.as_ptr(),
                verb_wide,
                path_wide,
                None,
                None,
                accept_types.as_ptr(),
                flags,
            )
        })?;

        // Add headers
        if !headers.is_empty() {
            let mut headers_str = String::new();
            for (k, v) in headers {
                headers_str.push_str(&format!("{k}: {v}\r\n"));
            }
            let wide_headers = widestring::U16String::from_str(&headers_str);

            unsafe {
                WinHttpAddRequestHeaders(
                    hrequest.as_ptr(),
                    wide_headers.as_slice(),
                    WINHTTP_ADDREQ_FLAG_ADD,
                )
            }
            .ok()
            .context("WinHttpAddRequestHeaders failed")?;
        }

        // Configurar SSL si hace falta
        if use_ssl {
            let opts = if !self.verify_ssl {
                SECURITY_FLAG_IGNORE_UNKNOWN_CA
                    | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
                    | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                    | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
            } else {
                SECURITY_FLAG_SECURE
            };
            unsafe {
                WinHttpSetOption(
                    Some(hrequest.as_ptr()),
                    WINHTTP_OPTION_SECURITY_FLAGS,
                    Some(as_u8_slice(&opts)),
                )
            }
            .ok()
            .context("WinHttpSetOption failed")?;
        }
        let (lpoptional, lpoptional_len) = match body {
            Some(data) => (Some(data.as_ptr() as *const c_void), data.len() as u32),
            None => (None, 0),
        };

        // Enviar
        unsafe {
            WinHttpSendRequest(
                hrequest.as_ptr(),
                None,
                lpoptional,
                lpoptional_len,
                lpoptional_len,
                0,
            )
        }
        .ok()
        .context("WinHttpSendRequest failed")?;

        unsafe { WinHttpReceiveResponse(hrequest.as_ptr(), std::ptr::null_mut()) }
            .ok()
            .context("WinHttpReceiveResponse failed")?;

        // Código de estado
        let mut status_code: u32 = 0;
        let mut size = std::mem::size_of::<u32>() as u32;
        unsafe {
            WinHttpQueryHeaders(
                hrequest.as_ptr(),
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                PWSTR::null(),
                Some(&mut status_code as *mut u32 as *mut std::ffi::c_void),
                &mut size,
                std::ptr::null_mut(),
            )
        }
        .ok()
        .context("WinHttpQueryHeaders STATUS_CODE failed")?;

        // Read body
        let mut body_str = String::new();
        loop {
            let mut avail: u32 = 0;
            unsafe { WinHttpQueryDataAvailable(hrequest.as_ptr(), &mut avail) }
                .ok()
                .context("WinHttpQueryDataAvailable failed")?;

            if avail == 0 {
                break;
            }

            let mut buf = vec![0u8; avail as usize];
            let mut read: u32 = 0;
            unsafe { WinHttpReadData(hrequest.as_ptr(), buf.as_mut_ptr() as _, avail, &mut read) }
                .ok()
                .context("WinHttpReadData failed")?;

            body_str.push_str(&String::from_utf8_lossy(&buf[..read as usize]));
        }

        // Read headers
        let mut headers_size: u32 = 0;

        // First, the size to create the buffer
        let headers_info = unsafe {
            WinHttpQueryHeaders(
                hrequest.as_ptr(),
                WINHTTP_QUERY_RAW_HEADERS_CRLF,
                PCWSTR::null(),
                None,
                &mut headers_size,
                std::ptr::null_mut(),
            )
        };

        let headers_map = {
            if let Err(err) = headers_info {
                let mut headers_str = String::new();
                if (err.code().0 & 0xFFFF) as u32 == ERROR_INSUFFICIENT_BUFFER.0 {
                    let mut buf: Vec<u16> = vec![0; (headers_size / 2) as usize + 1];
                    unsafe {
                        WinHttpQueryHeaders(
                            hrequest.as_ptr(),
                            WINHTTP_QUERY_RAW_HEADERS_CRLF,
                            PCWSTR::null(),
                            Some(buf.as_mut_ptr() as _),
                            &mut headers_size,
                            std::ptr::null_mut(),
                        )
                    }
                    .ok()
                    .context("WinHttpQueryHeaders RAW failed")?;
                    headers_str = String::from_utf16_lossy(&buf);
                }

                // Generate the hashmap from headers
                headers_str
                    .lines()
                    .filter_map(|line| {
                        let mut parts = line.splitn(2, ": ");
                        Some((parts.next()?.to_string(), parts.next()?.to_string()))
                    })
                    .collect()
            } else {
                HashMap::new()
            }
        };

        Ok(HttpResponse {
            status_code,
            body: body_str,
            headers: headers_map,
        })
    }
}
