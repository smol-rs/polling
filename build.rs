use std::env;

fn main() {
    let cfg = match autocfg::AutoCfg::new() {
        Ok(cfg) => cfg,
        Err(e) => {
            println!(
                "cargo:warning=polling: failed to detect compiler features: {}",
                e
            );
            return;
        }
    };

    // We use "no_*" instead of "has_*" here. For non-Cargo
    // build tools that don't run build.rs, the negative
    // allows us to treat the current Rust version as the
    // latest stable version, for when version information
    // isn't available.
    if !cfg.probe_rustc_version(1, 63) {
        autocfg::emit("polling_no_io_safety");
    }

    if !cfg.probe_rustc_version(1, 53) {
        autocfg::emit("polling_no_unsupported_error_kind");
    }

    // Probe for the target_os.
    let target_os = TargetOs::new();

    // kqueue is supported for most BSD-derives OSes.
    let bsdlike = &[
        "macos",
        "ios",
        "tvos",
        "watchos",
        "freebsd",
        "netbsd",
        "dragonfly",
        "openbsd"
    ];

    // We fall back to poll() on these platforms.
    let poll_fallback = &[
        "vxworks",
        "fuchsia",
        "horizon"
    ];

    // If we're forced to use the polling fallback, use that and return.
    if has_cfg("polling_test_poll_backend") {
        return;
    }

    // epoll is supported on Linux and Android
    if target_os.is("linux") || target_os.is("android") {
        autocfg::emit("polling_epoll");
    }

    // Event ports are supported on illumos and Solaris
    else if target_os.is("illumos") || target_os.is("solaris") {
        autocfg::emit("polling_event_port");
    } 

    // kqueue is supported on most BSD-derives OSes.
    else if bsdlike.iter().any(|os| target_os.is(os)) {
        autocfg::emit("polling_kqueue");
    }

    // If we're not on a supported platform, fall back to poll().
    else if poll_fallback.iter().any(|os| target_os.is(os)) || has_cfg("unix") {
        autocfg::emit("polling_poll");
    }

    // Otherwise, check for windows.
    else if target_os.is("windows") {
        autocfg::emit("polling_iocp");
    }
}

/// Tell whether the `cfg` directive is set.
fn has_cfg(name: &str) -> bool {
    let env_check = format!("CARGO_FEATURE_{}", cfg_name(name));
    env::var_os(env_check).is_some()
}

struct TargetOs(String);

impl TargetOs {
    fn new() -> Self {
        let target_os = env::var_os("CARGO_CFG_TARGET_OS")
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "".to_string());
        Self(target_os)
    }

    fn is(&self, os: &str) -> bool {
        self.0.split(',').any(|s| s == os)
    }
}

fn cfg_name(name: &str) -> String {
    name.to_uppercase().replace('-', "_").replace('"', "")
}
