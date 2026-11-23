//! `cargo xtask deb`: Keep Hub's Linux package (Revision 4 D), a `.deb` for Ubuntu and Debian.
//! Until keep-launcher runs on Ubuntu it is installed from the release page; the launcher
//! adopts the same package later.
//!
//! ```text
//! cargo xtask deb                       build, then make dist/keep-hub_<version>_<arch>.deb
//! cargo xtask deb --skip-build --bin <folder>
//!                                       make it from a program built already
//! ```
//!
//! The package holds the program, the systemd unit, the sysusers file, the licences and the
//! maintainer scripts from `installer/linux/`. `postinst` runs `keep-hub install-service`
//! (the user, the sealing key, the certificate page's port, the service started); `prerm`
//! runs `keep-hub remove-service`. `dpkg -r` keeps `/var/lib/keep-hub`; `dpkg -P` deletes it
//! and asks nothing, as Debian's rules say. Made with `dpkg-deb --root-owner-group`, so
//! every file is root's whoever builds it.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::installer::{sha256_file, version};

/// The Debian version of a semver version: a pre-release sorts before its release with `~`
/// (`0.2.0-alpha.1` is `0.2.0~alpha.1`); build metadata is left out.
pub fn debian_version(v: &str) -> Result<String, String> {
    let v = v.split_once('+').map_or(v, |(a, _)| a);
    let ok = |s: &str| {
        !s.is_empty()
            && s.starts_with(|c: char| c.is_ascii_digit())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
    };
    if !ok(v) {
        return Err(format!("{v} isn't a version the package can carry"));
    }
    Ok(v.replacen('-', "~", 1))
}

/// Debian's name for the architecture this program was built for.
pub fn debian_arch(rust_arch: &str) -> Result<&'static str, String> {
    match rust_arch {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        other => Err(format!("no Debian architecture is set for {other}")),
    }
}

pub fn deb_name(version: &str, arch: &str) -> String {
    format!("keep-hub_{version}_{arch}.deb")
}

/// Who the package names as its maintainer: `KH_DEB_MAINTAINER` ("Name <address>"), or
/// the publisher's (owner decision 2026-11-22).
pub fn maintainer(var: Option<String>) -> String {
    var.filter(|m| m.contains('<') && m.ends_with('>'))
        .unwrap_or_else(|| "MoneyKeep Project <maintainer@getmoneykeep.org>".into())
}

/// The package's `control` file.
pub fn control(version: &str, arch: &str, installed_kib: u64, maintainer: &str) -> String {
    format!(
        "Package: keep-hub
Version: {version}
Architecture: {arch}
Maintainer: {maintainer}
Installed-Size: {installed_kib}
Depends: systemd
Recommends: nftables
Section: net
Priority: optional
Homepage: https://getmoneykeep.org/
Description: Keep Hub, phone access for the Keep apps
 The one program on the household's hub computer that phones connect to.
 It holds the secure name and certificate, the household's members and
 phones, and who may use which app, and passes each request to its app.
 It holds no app's books.
"
    )
}

/// Every file in the package: (path inside it, source, mode).
pub fn layout(root: &Path, bin: &Path) -> Vec<(String, PathBuf, u32)> {
    let linux = root.join("installer").join("linux");
    vec![
        ("usr/bin/keep-hub".into(), bin.join("keep-hub"), 0o755),
        (
            "usr/lib/systemd/system/keep-hub.service".into(),
            linux.join("keep-hub.service"),
            0o644,
        ),
        (
            "usr/lib/sysusers.d/keep-hub.conf".into(),
            linux.join("keep-hub.sysusers"),
            0o644,
        ),
        ("DEBIAN/postinst".into(), linux.join("postinst"), 0o755),
        ("DEBIAN/prerm".into(), linux.join("prerm"), 0o755),
        ("DEBIAN/postrm".into(), linux.join("postrm"), 0o755),
        (
            "usr/share/doc/keep-hub/LICENSE-MIT".into(),
            root.join("LICENSE-MIT"),
            0o644,
        ),
        (
            "usr/share/doc/keep-hub/LICENSE-APACHE".into(),
            root.join("LICENSE-APACHE"),
            0o644,
        ),
        (
            "usr/share/doc/keep-hub/NOTICE".into(),
            root.join("NOTICE"),
            0o644,
        ),
    ]
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("cannot set the mode of {}: {e}", p.display()))
}

#[cfg(not(unix))]
fn set_mode(_p: &Path, _mode: u32) -> Result<(), String> {
    Err("the .deb is made on Linux".into())
}

/// Put the package's files in `tree`; their size in KiB (for `Installed-Size`).
pub fn stage(root: &Path, bin: &Path, tree: &Path, version: &str) -> Result<u64, String> {
    if tree.exists() {
        std::fs::remove_dir_all(tree)
            .map_err(|e| format!("cannot clear {}: {e}", tree.display()))?;
    }
    let mut bytes = 0u64;
    for (inside, from, mode) in layout(root, bin) {
        let to = tree.join(&inside);
        if let Some(dir) = to.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            set_mode(dir, 0o755)?;
        }
        std::fs::copy(&from, &to)
            .map_err(|e| format!("cannot copy {} to {}: {e}", from.display(), to.display()))?;
        set_mode(&to, mode)?;
        if !inside.starts_with("DEBIAN/") {
            bytes += std::fs::metadata(&to).map(|m| m.len()).unwrap_or(0);
        }
    }
    let doc = tree.join("usr/share/doc/keep-hub");
    let (_, n) = crate::licences::write(root, &doc, version)?;
    println!("==> {} lists {n} crates", crate::licences::FILE);
    bytes += std::fs::metadata(doc.join(crate::licences::FILE))
        .map(|m| m.len())
        .unwrap_or(0);
    Ok(bytes.div_ceil(1024))
}

/// `cargo xtask deb [--skip-build] [--bin <folder>]`.
pub fn deb(root: &Path, args: &[String]) -> Result<(), String> {
    let mut skip_build = false;
    let mut bin = root.join("target").join("release");
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--skip-build" => skip_build = true,
            "--bin" => bin = PathBuf::from(it.next().ok_or("--bin needs a folder")?),
            other => return Err(format!("deb: unknown option {other}")),
        }
    }
    if !cfg!(target_os = "linux") {
        return Err("cargo xtask deb makes the Linux package on Linux.".into());
    }
    let version = debian_version(&version(root)?)?;
    let arch = debian_arch(std::env::consts::ARCH)?;
    if !skip_build {
        println!("==> cargo build --release -p keep-hub");
        let ok = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["build", "--release", "--locked", "-p", "keep-hub"])
            .current_dir(root)
            .status()
            .map_err(|e| e.to_string())?
            .success();
        if !ok {
            return Err("cargo build failed".into());
        }
    }
    let tree = root
        .join("target")
        .join("deb")
        .join(format!("keep-hub_{version}_{arch}"));
    let kib = stage(root, &bin, &tree, &version)?;
    let who = maintainer(std::env::var("KH_DEB_MAINTAINER").ok());
    std::fs::write(
        tree.join("DEBIAN/control"),
        control(&version, arch, kib, &who),
    )
    .map_err(|e| format!("cannot write the control file: {e}"))?;
    set_mode(&tree.join("DEBIAN/control"), 0o644)?;
    let dist = root.join("dist");
    std::fs::create_dir_all(&dist).map_err(|e| format!("cannot create dist: {e}"))?;
    let out = dist.join(deb_name(&version, arch));
    println!("==> dpkg-deb --build {}", out.display());
    let ok = Command::new("dpkg-deb")
        .args(["--root-owner-group", "-Zxz", "--build"])
        .arg(&tree)
        .arg(&out)
        .status()
        .map_err(|e| format!("cannot run dpkg-deb (install dpkg): {e}"))?
        .success();
    if !ok || !out.is_file() {
        return Err("dpkg-deb failed".into());
    }
    let sum = sha256_file(&out)?;
    let name = deb_name(&version, arch);
    std::fs::write(
        dist.join(format!("{name}.sha256")),
        format!("{sum}  {name}\n"),
    )
    .map_err(|e| format!("cannot write the checksum: {e}"))?;
    println!("==> {} ({sum})", out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn versions_and_architectures_read_as_debian_writes_them() {
        assert_eq!(debian_version("0.1.0").unwrap(), "0.1.0");
        assert_eq!(debian_version("0.2.0-alpha.1").unwrap(), "0.2.0~alpha.1");
        assert_eq!(debian_version("1.0.0-rc.2+abc").unwrap(), "1.0.0~rc.2");
        assert!(debian_version("v1").is_err());
        assert!(debian_version("1.0 0").is_err());
        assert_eq!(debian_arch("x86_64").unwrap(), "amd64");
        assert_eq!(debian_arch("aarch64").unwrap(), "arm64");
        assert!(debian_arch("riscv64").is_err());
        assert_eq!(deb_name("0.1.0", "amd64"), "keep-hub_0.1.0_amd64.deb");
    }

    #[test]
    fn the_control_file_names_the_package_and_its_needs() {
        let c = control("0.1.0", "amd64", 6000, &maintainer(None));
        assert!(c.starts_with("Package: keep-hub\nVersion: 0.1.0\nArchitecture: amd64\n"));
        assert!(c.contains("Depends: systemd"));
        assert!(c.contains("Installed-Size: 6000\n"));
        assert!(c.contains("Maintainer: MoneyKeep Project <"));
        assert_eq!(
            maintainer(Some("A Person <a@example.org>".into())),
            "A Person <a@example.org>"
        );
        assert!(maintainer(Some("no address".into())).starts_with("MoneyKeep Project"));
        // a description's later lines start with a space
        let after = c.split("Description:").nth(1).unwrap();
        assert!(after.lines().skip(1).all(|l| l.starts_with(' ')));
    }

    #[test]
    fn the_package_holds_the_unit_the_user_and_the_scripts() {
        let root = crate::workspace_root();
        let files = layout(&root, Path::new("/nowhere"));
        for (inside, from, _) in &files {
            if !inside.starts_with("usr/bin/") {
                assert!(from.is_file(), "{} is missing", from.display());
            }
        }
        let modes: Vec<(&str, u32)> = files.iter().map(|(i, _, m)| (i.as_str(), *m)).collect();
        assert!(modes.contains(&("DEBIAN/postinst", 0o755)));
        assert!(modes.contains(&("usr/lib/systemd/system/keep-hub.service", 0o644)));
        let read = |f: &str| std::fs::read_to_string(root.join("installer/linux").join(f)).unwrap();
        assert!(read("postinst").contains("keep-hub install-service"));
        assert!(read("prerm").contains("keep-hub remove-service"));
        let postrm = read("postrm");
        assert!(postrm.contains("purge)"));
        assert!(postrm.contains("rm -rf /var/lib/keep-hub"));
        // only purge touches the data folder
        let before_purge = postrm.split("purge)").next().unwrap();
        assert!(!before_purge.contains("/var/lib/keep-hub"));
        for s in ["postinst", "prerm", "postrm"] {
            assert!(read(s).starts_with("#!/bin/sh\n"), "{s}");
            assert!(read(s).contains("set -e"), "{s}");
        }
    }
}
