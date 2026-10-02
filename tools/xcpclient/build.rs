// Added to upstream (VsCANape issue 214): the commit xcpclient is built from, for `--version`.
//
// The VS Code extension ships xcpclient prebuilt and refuses one named in a setting that does not
// report the version it was packaged with, so the version has to say which sources it is: the
// crate's version, then the commit of the repository the crate is tracked in, with `-dirty` when
// the crate's files differ from that commit. A copy of the crate that no repository tracks -- the
// test scripts build one under source/mc-instrument/build -- says `unknown` rather than borrowing
// the commit of whatever repository it was copied into.

use std::path::{Path, PathBuf};
use std::process::Command;

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git").arg("-C").arg(dir).args(args).output().ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Builds again when the commit can have changed: HEAD moved, the branch it names moved, or the
/// index changed (a commit, an add).
fn rerun_on_git(dir: &Path) {
    let mut paths = vec!["HEAD".to_string(), "index".to_string(), "packed-refs".to_string()];
    if let Some(reference) = git(dir, &["symbolic-ref", "-q", "HEAD"]) {
        paths.push(reference);
    }
    for path in paths {
        if let Some(found) = git(dir, &["rev-parse", "--git-path", &path]) {
            let found = PathBuf::from(found);
            println!("cargo:rerun-if-changed={}", if found.is_absolute() { found } else { dir.join(found) }.display());
        }
    }
}

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=src");

    let tracked = git(&dir, &["ls-files", "--error-unmatch", "Cargo.toml"]).is_some();
    let commit = match tracked.then(|| git(&dir, &["rev-parse", "--short=12", "HEAD"])).flatten() {
        Some(head) => {
            rerun_on_git(&dir);
            let dirty = git(&dir, &["status", "--porcelain", "--", "."]).is_some_and(|status| !status.is_empty());
            if dirty { format!("{head}-dirty") } else { head }
        }
        None => "unknown".to_string(),
    };
    println!("cargo:rustc-env=XCPCLIENT_COMMIT={commit}");
}
