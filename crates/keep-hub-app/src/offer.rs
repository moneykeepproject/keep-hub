//! Turning on phones in an app (the spec, "How the hub gets onto the computer"): is there a
//! hub on this computer, and what does the app offer?
//!
//! - No hub: the app asks whether this computer should be the household's hub. On yes it opens
//!   keep-launcher at the hub's entry, where the person installs it; without keep-launcher it
//!   shows the hub's download page. An app never installs the hub itself.
//! - A hub installed and stopped counts as found: the app offers to start it, and installs
//!   nothing.
//! - A running hub: the app registers ([`crate::ensure_registered`]) and goes on to the phone
//!   setup, without asking the person to restart the app.
//!
//! How keep-launcher is opened at an entry is keep-launcher's to define (its catalog entry for
//! a component that is a service): the app supplies it as a [`Launcher`].

use std::path::Path;

use crate::client::{find, Found, HubClient, HubError, HubStatus};

/// The hub's entry in keep-launcher's catalog (its release package's name).
pub const LAUNCHER_ENTRY: &str = "keep-hub";

/// Where the hub can be downloaded when keep-launcher isn't installed (its releases, the same
/// files keep-launcher installs).
pub const DOWNLOAD_PAGE: &str = "https://github.com/moneykeepproject/keep-hub/releases";

/// What the app offers when the person turns on phones.
#[derive(Debug)]
pub enum Offer {
    /// No hub on this computer: ask whether this computer should be the household's hub; on
    /// yes, [`make_this_the_hub`].
    MakeThisTheHub,
    /// Installed and stopped: offer to start it ([`start_command`]). When it runs, the same
    /// client works.
    StartHub(HubClient),
    /// Installed, but this app can't use it: why, in words for the person.
    CantUse(HubError),
    /// Running and not set up: ask for the first administrator and the household PIN
    /// ([`HubClient::set_up`]), then go on.
    SetUp(HubClient),
    /// Running: register and go on.
    Ready(HubClient, HubStatus),
}

/// What to offer, for the hub whose data folder is `data` ([`crate::default_data_folder`]).
pub fn offer(data: &Path) -> Offer {
    match find(data) {
        Found::NotInstalled => Offer::MakeThisTheHub,
        Found::NoAccess(e) => Offer::CantUse(e),
        Found::Stopped(hub) => Offer::StartHub(hub),
        Found::NotSetUp(hub) => Offer::SetUp(hub),
        Found::Running(hub, status) => Offer::Ready(hub, status),
    }
}

/// keep-launcher on this computer, as the app opens it.
pub trait Launcher {
    /// Whether keep-launcher is installed.
    fn installed(&self) -> bool;
    /// Open it at the hub's entry ([`LAUNCHER_ENTRY`]), where the person installs the hub.
    fn open_hub_entry(&self) -> Result<(), String>;
}

/// What happened after the person said yes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// keep-launcher is open at the hub's entry. When the hub runs, [`offer`] says `Ready`.
    LauncherOpened,
    /// keep-launcher isn't installed: show this link to the hub's download page.
    DownloadPage(&'static str),
}

/// The person said this computer should be the household's hub.
pub fn make_this_the_hub(launcher: &dyn Launcher) -> Result<Next, HubError> {
    if !launcher.installed() {
        return Ok(Next::DownloadPage(DOWNLOAD_PAGE));
    }
    launcher.open_hub_entry().map_err(|e| {
        HubError::here(
            "launcher_not_opened",
            format!("keep-launcher couldn't be opened ({e}). Open it, and install Keep Hub there."),
        )
    })?;
    Ok(Next::LauncherOpened)
}

/// The command that starts a stopped hub. The app runs it with the system's permission prompt
/// (starting a service is for administrators). None where the hub isn't a system service.
pub fn start_command() -> Option<Vec<String>> {
    if cfg!(windows) {
        Some(vec!["sc.exe".into(), "start".into(), "KeepHub".into()])
    } else if cfg!(target_os = "macos") {
        Some(vec![
            "/bin/launchctl".into(),
            "kickstart".into(),
            "system/org.moneykeep.keep-hub".into(),
        ])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct FakeLauncher {
        installed: bool,
        fails: bool,
        opened: Cell<u32>,
    }

    impl Launcher for FakeLauncher {
        fn installed(&self) -> bool {
            self.installed
        }
        fn open_hub_entry(&self) -> Result<(), String> {
            self.opened.set(self.opened.get() + 1);
            if self.fails {
                Err("no".into())
            } else {
                Ok(())
            }
        }
    }

    fn launcher(installed: bool, fails: bool) -> FakeLauncher {
        FakeLauncher {
            installed,
            fails,
            opened: Cell::new(0),
        }
    }

    #[test]
    fn yes_opens_the_launcher_or_the_download_page() {
        let l = launcher(true, false);
        assert_eq!(make_this_the_hub(&l).unwrap(), Next::LauncherOpened);
        assert_eq!(l.opened.get(), 1);
        let l = launcher(false, false);
        assert_eq!(
            make_this_the_hub(&l).unwrap(),
            Next::DownloadPage(DOWNLOAD_PAGE)
        );
        assert_eq!(l.opened.get(), 0);
        let l = launcher(true, true);
        assert_eq!(
            make_this_the_hub(&l).unwrap_err().code,
            "launcher_not_opened"
        );
    }

    #[test]
    fn no_folder_offers_to_make_this_computer_the_hub() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(offer(dir.path()), Offer::MakeThisTheHub));
    }

    #[test]
    fn starting_names_the_hubs_service() {
        let found = start_command();
        assert_eq!(found.is_some(), cfg!(windows) || cfg!(target_os = "macos"));
        if let Some(c) = found {
            assert!(c
                .iter()
                .any(|a| a.contains("KeepHub") || a.contains("keep-hub")));
        }
    }
}
