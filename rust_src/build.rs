use std::env;
use std::process::Command;

fn parse_rustc_minor(version_text: &str) -> Option<u32> {
    let version = version_text.split_whitespace().nth(1)?;
    let mut parts = version.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    if major == 1 {
        return Some(minor);
    }
    None
}

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rustc-check-cfg=cfg(legacy_rustc_private_api)");
    let rustc = env::var("RUSTC").unwrap_or_else(|_| String::from("rustc"));
    let output = Command::new(rustc).arg("--version").output();
    let version_text = match output {
        Ok(result) => String::from_utf8_lossy(&result.stdout).to_string(),
        Err(_) => return,
    };
    if let Some(minor) = parse_rustc_minor(&version_text) {
        if minor < 56 {
            println!("cargo:rustc-cfg=legacy_rustc_private_api");
        }
    }
}
