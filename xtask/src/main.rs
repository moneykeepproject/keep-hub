//! Keep Hub developer tasks (following ShareKeep's xtask).
//!
//! ```text
//! cargo xtask ci          fmt check, clippy -D warnings, tests, then the repository rules
//! cargo xtask workflows   only release.yml may name the project's own Mac (self-hosted)
//! cargo xtask guards      no panics in shipped code; sources keep LF line endings
//! cargo xtask installer   the Windows setup (installer.rs)
//! cargo xtask deb         the Linux package (deb.rs)
//! ```

mod deb;
mod installer;
mod licences;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let task = std::env::args().nth(1).unwrap_or_default();
    let root = workspace_root();
    let result = match task.as_str() {
        "ci" => ci(&root),
        "workflows" => report(check_workflows(&root)),
        "guards" => report(check_guards(&root)),
        "deb" => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            deb::deb(&root, &rest)
        }
        "installer" => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            installer::installer(&root, &rest)
        }
        _ => {
            eprintln!("usage: cargo xtask <ci|workflows|guards|installer|deb>");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask {task}: {e}");
            ExitCode::FAILURE
        }
    }
}

pub fn workspace_root() -> PathBuf {
    // At run time, not build time: a shared target folder may hold an xtask built from
    // another checkout.
    let manifest =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").into());
    Path::new(&manifest)
        .parent()
        .expect("xtask sits in the workspace")
        .to_path_buf()
}

fn report(problems: Vec<String>) -> Result<(), String> {
    if problems.is_empty() {
        return Ok(());
    }
    for p in &problems {
        eprintln!("  {p}");
    }
    Err(format!("{} problem(s)", problems.len()))
}

fn ci(root: &Path) -> Result<(), String> {
    let steps: [&[&str]; 3] = [
        &["fmt", "--all", "--", "--check"],
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        &["test", "--workspace", "--locked"],
    ];
    for args in steps {
        println!("== cargo {}", args.join(" "));
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let ok = Command::new(&cargo)
            .args(args)
            .current_dir(root)
            .status()
            .map_err(|e| e.to_string())?
            .success();
        if !ok {
            return Err(format!("cargo {} failed", args[0]));
        }
    }
    println!("== workflows");
    report(check_workflows(root))?;
    println!("== guards");
    report(check_guards(root))
}

/// Only `release.yml` may run on the project's own Mac (a self-hosted runner), as in the
/// other Keep apps: a pull request must never reach it.
fn check_workflows(root: &Path) -> Vec<String> {
    let dir = root.join(".github/workflows");
    let mut problems = Vec::new();
    for path in files(&dir, &["yml", "yaml"]) {
        let Ok(text) = fs::read_to_string(&path) else {
            problems.push(format!("{}: can't be read", path.display()));
            continue;
        };
        let text = text.replace("\r\n", "\n");
        problems.extend(workflow_problems(&file_name(&path), &text));
    }
    problems
}

/// Keys repeated in the same mapping (GitHub refuses such a workflow; another reader keeps
/// the last copy). A small indentation reader: enough for workflow files, which use block
/// style, `- ` list items and `|` / `>` text blocks.
fn repeated_keys(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut stack: Vec<(usize, Vec<String>)> = Vec::new();
    let mut block: Option<usize> = None;
    for (i, raw) in text.lines().enumerate() {
        let trimmed = raw.trim_start();
        let mut indent = raw.len() - trimmed.len();
        if let Some(b) = block {
            if trimmed.is_empty() || indent > b {
                continue;
            }
            block = None;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("---") {
            continue;
        }
        let mut content = trimmed;
        if let Some(rest) = content.strip_prefix("- ") {
            // a list item opens a new mapping
            indent += 2;
            while stack.last().is_some_and(|(n, _)| *n >= indent) {
                stack.pop();
            }
            stack.push((indent, Vec::new()));
            content = rest.trim_start();
        } else if content == "-" {
            continue;
        }
        while stack.last().is_some_and(|(n, _)| *n > indent) {
            stack.pop();
        }
        let Some((key, value)) = content.split_once(':') else {
            continue;
        };
        if !(value.is_empty() || value.starts_with(' '))
            || key.contains(['{', '[', ' ']) && !key.starts_with(['"', '\''])
        {
            continue;
        }
        let key = key.trim_matches(['"', '\'']).to_string();
        match stack.last_mut() {
            Some((n, keys)) if *n == indent => {
                if keys.contains(&key) {
                    found.push((i + 1, key));
                } else {
                    keys.push(key);
                }
            }
            _ => stack.push((indent, vec![key])),
        }
        let v = value.split(" #").next().unwrap_or("").trim();
        if v.starts_with('|') || v.starts_with('>') {
            block = Some(indent);
        }
    }
    found
}

fn workflow_problems(name: &str, text: &str) -> Vec<String> {
    let mut problems: Vec<String> = repeated_keys(text)
        .into_iter()
        .map(|(line, key)| format!("{name}:{line}: \"{key}\" appears twice in the same place"))
        .collect();
    let names_mac = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .any(|l| l.contains("self-hosted"));
    if names_mac && name != "release.yml" {
        problems.push(format!("{name}: only release.yml may use self-hosted"));
    }
    if names_mac && name == "release.yml" {
        let code: String = text
            .lines()
            .map(|l| l.split('#').next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        if code.contains("pull_request") {
            problems.push(format!(
                "{name}: a workflow that uses self-hosted can't run on pull requests"
            ));
        }
    }
    problems
}

/// The repository rules of AGENTS.md that a program can check:
///
/// - **No panics in shipped code.** The sources under `crates/*/src` may not call `unwrap`,
///   `expect` or a panicking macro outside their test modules.
/// - **Line endings.** Sources keep LF, whatever the checkout's system.
fn check_guards(root: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    for path in files(&root.join("crates"), &["rs"]) {
        let shipped = path
            .components()
            .any(|c| c.as_os_str() == std::ffi::OsStr::new("src"));
        if !shipped {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            problems.push(format!("{}: can't be read", path.display()));
            continue;
        };
        problems.extend(panic_problems(&path.display().to_string(), &text));
    }
    for path in files(
        root,
        &[
            "rs", "toml", "lock", "md", "yml", "yaml", "json", "sh", "command", "ps1", "nsi",
            "plist", "py", "html", "js", "wat",
        ],
    )
    .into_iter()
    // the Linux package's files: shell scripts without an extension, the unit, sysusers
    .chain(
        fs::read_dir(root.join("installer").join("linux"))
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file()),
    ) {
        match fs::read(&path) {
            Ok(bytes) if bytes.contains(&b'\r') => {
                problems.push(format!("{}: has CRLF line endings", path.display()))
            }
            Ok(_) => {}
            Err(_) => problems.push(format!("{}: can't be read", path.display())),
        }
    }
    problems
}

/// What a line of shipped code may not contain.
const PANICS: &[&str] = &[
    ".unwrap()",
    ".expect(",
    "panic!(",
    "unreachable!(",
    "todo!(",
    "unimplemented!(",
];

/// The panicking calls in a source file, up to its test module (`#[cfg(test)]`, which
/// every file keeps last).
fn panic_problems(name: &str, text: &str) -> Vec<String> {
    text.lines()
        .enumerate()
        .take_while(|(_, l)| l.trim() != "#[cfg(test)]")
        .filter_map(|(i, l)| {
            let code = l.split("//").next().unwrap_or("");
            PANICS
                .iter()
                .find(|p| code.contains(**p))
                .map(|p| format!("{name}:{}: no panics in shipped code ({p})", i + 1))
        })
        .collect()
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn files(dir: &Path, exts: &[&str]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            let name = file_name(&p);
            if name != "target" && name != ".git" && name != "dist" {
                out.extend(files(&p, exts));
            }
        } else if p.extension().is_some_and(|x| exts.iter().any(|e| x == *e)) {
            out.push(p);
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_repository_follows_its_rules() {
        let root = workspace_root();
        assert_eq!(check_workflows(&root), Vec::<String>::new());
        assert_eq!(check_guards(&root), Vec::<String>::new());
    }

    #[test]
    fn a_key_twice_in_one_place_is_refused() {
        let joined = "on:\n  push:\npermissions:\n  contents: write\njobs:\n  a:\n    steps:\n      - name: x\n        run: |\n          jobs:\n          a: 1\n      - name: y\npermissions:\n  contents: read\njobs:\n  b:\n";
        let found = repeated_keys(joined);
        assert_eq!(
            found.iter().map(|(_, k)| k.as_str()).collect::<Vec<_>>(),
            ["permissions", "jobs"]
        );
        // the same key in different places, list items and text blocks are fine
        let fine = "jobs:\n  a:\n    name: a\n    steps:\n      - name: x\n      - name: y\n  b:\n    name: b\n";
        assert!(repeated_keys(fine).is_empty());
    }

    #[test]
    fn self_hosted_outside_release_is_refused() {
        let ci = "jobs:\n  a:\n    runs-on: [self-hosted, macOS]\n";
        assert_eq!(workflow_problems("ci.yml", ci).len(), 1);
        let commented = "jobs:\n  a:\n    runs-on: ubuntu-latest # not self-hosted\n";
        assert!(workflow_problems("ci.yml", commented).is_empty());
        let release_pr = "on:\n  pull_request:\njobs:\n  a:\n    runs-on: [self-hosted]\n";
        assert_eq!(workflow_problems("release.yml", release_pr).len(), 1);
    }

    #[test]
    fn panics_in_shipped_code_are_refused() {
        let bad = "fn f(x: Option<u8>) -> u8 {\n    x.unwrap()\n}\n";
        assert_eq!(panic_problems("a.rs", bad).len(), 1);
        let also =
            "fn f() {\n    todo!()\n}\nfn g(x: Option<u8>) -> u8 {\n    x.expect(\"set\")\n}\n";
        assert_eq!(panic_problems("a.rs", also).len(), 2);
        // comments, the fallible cousins and test modules are fine
        let fine = "// never .unwrap() here\nfn f(x: Option<u8>) -> u8 {\n    x.unwrap_or(0)\n}\n#[cfg(test)]\nmod tests {\n    fn t() {\n        None::<u8>.unwrap();\n    }\n}\n";
        assert!(panic_problems("a.rs", fine).is_empty());
    }

    #[test]
    fn crlf_sources_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.md"), "one\r\ntwo\r\n").unwrap();
        fs::write(dir.path().join("b.md"), "one\ntwo\n").unwrap();
        let found = check_guards(dir.path());
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("a.md"));
    }
}
