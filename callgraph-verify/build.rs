// Emit GIT_SHA env var at build time so the CLI usage banner can show which
// commit the binary was built from. When there's no .git dir (e.g. `cargo
// install` from a tarball) we silently set GIT_SHA="" — main.rs interprets
// that as "no-git".
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Re-run whenever HEAD moves (cheap; the crate isn't rebuilt otherwise).
    println!("cargo:rerun-if-changed=.git/HEAD");

    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    println!("cargo:rustc-env=GIT_SHA={sha}");
}