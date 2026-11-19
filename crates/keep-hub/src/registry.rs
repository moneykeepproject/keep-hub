//! `hub.sqlite`: the apps, members, grants, devices and guest invites, and the household
//! PIN's hash. Started as a copy of ShareKeep's hub, `registry.rs` (devices and the PIN's
//! hash), then changed for apps and grants.
//!
//! A device's token is never stored: only its SHA-256 (the token is 32 random bytes, so a
//! plain hash is enough to make the stored value useless to a thief). The same goes for a
//! guest invite. Revoking a device keeps its row (for the device list) and refuses its token
//! from then on. The schema has migrations, so any newer hub opens an older registry without
//! re-pairing, and a registry from a newer hub is refused.

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::util::StoreResult;

pub const REGISTRY_FILE: &str = "hub.sqlite";

/// The key of the household PIN's hash in the `kv` table.
pub const PIN_KEY: &str = "pin";

pub const MIGRATIONS: &[&str] = &[
    // 0 → 1
    "CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
     CREATE TABLE apps (
         id            TEXT PRIMARY KEY,
         title         TEXT NOT NULL,
         version       TEXT NOT NULL,
         protocol      INTEGER NOT NULL,
         public_port   INTEGER NOT NULL UNIQUE,
         loopback_port INTEGER NOT NULL UNIQUE,
         money         INTEGER NOT NULL,
         guests        INTEGER NOT NULL,
         registered    INTEGER NOT NULL
     );
     CREATE TABLE members (
         id          INTEGER PRIMARY KEY,
         name        TEXT NOT NULL,
         guest_app   TEXT,
         guest_scope TEXT,
         created     INTEGER NOT NULL
     );
     CREATE TABLE grants (
         member  INTEGER NOT NULL,
         app     TEXT NOT NULL,
         created INTEGER NOT NULL,
         PRIMARY KEY (member, app)
     );
     CREATE TABLE devices (
         id         INTEGER PRIMARY KEY,
         token_hash BLOB NOT NULL UNIQUE,
         member     INTEGER NOT NULL,
         app        TEXT NOT NULL,
         name       TEXT NOT NULL,
         created    INTEGER NOT NULL,
         last_seen  INTEGER,
         revoked    INTEGER
     );
     CREATE TABLE invites (
         id        INTEGER PRIMARY KEY,
         code_hash BLOB NOT NULL UNIQUE,
         app       TEXT NOT NULL,
         scope     TEXT NOT NULL,
         created   INTEGER NOT NULL,
         expires   INTEGER NOT NULL
     );",
];

/// A registered app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct App {
    pub id: String,
    pub title: String,
    pub version: String,
    pub protocol: u32,
    pub public_port: u16,
    pub loopback_port: u16,
    pub money: bool,
    pub guests: bool,
    pub registered: i64,
}

/// A person in the household, or a guest of one app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub id: u32,
    pub name: String,
    /// For a guest: the app the invite was for.
    pub guest_app: Option<String>,
    /// For a guest: what the invite was for (the app's own text).
    pub guest_scope: Option<String>,
    pub created: i64,
}

/// A member may use an app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub member: u32,
    pub app: String,
    pub created: i64,
}

/// One app on one phone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: u32,
    pub member: u32,
    pub app: String,
    pub name: String,
    pub created: i64,
    pub last_seen: Option<i64>,
    pub revoked: Option<i64>,
}

/// A guest invite that hasn't been used (its code is not kept, only a hash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub id: u32,
    pub app: String,
    pub scope: String,
    pub created: i64,
    pub expires: i64,
}

#[derive(Debug)]
pub struct Registry {
    conn: Connection,
}

fn sql(e: rusqlite::Error) -> String {
    format!("the hub's records can't be used: {e}")
}

/// The stored form of a device token or an invite code.
pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn app_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<App> {
    Ok(App {
        id: r.get(0)?,
        title: r.get(1)?,
        version: r.get(2)?,
        protocol: r.get(3)?,
        public_port: r.get(4)?,
        loopback_port: r.get(5)?,
        money: r.get(6)?,
        guests: r.get(7)?,
        registered: r.get(8)?,
    })
}

const APP: &str =
    "id, title, version, protocol, public_port, loopback_port, money, guests, registered";

fn member_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Member> {
    Ok(Member {
        id: r.get(0)?,
        name: r.get(1)?,
        guest_app: r.get(2)?,
        guest_scope: r.get(3)?,
        created: r.get(4)?,
    })
}

const MEMBER: &str = "id, name, guest_app, guest_scope, created";

fn device_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        id: r.get(0)?,
        member: r.get(1)?,
        app: r.get(2)?,
        name: r.get(3)?,
        created: r.get(4)?,
        last_seen: r.get(5)?,
        revoked: r.get(6)?,
    })
}

const DEVICE: &str = "id, member, app, name, created, last_seen, revoked";

fn invite_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Invite> {
    Ok(Invite {
        id: r.get(0)?,
        app: r.get(1)?,
        scope: r.get(2)?,
        created: r.get(3)?,
        expires: r.get(4)?,
    })
}

const INVITE: &str = "id, app, scope, created, expires";

impl Registry {
    pub fn open(dir: &Path) -> StoreResult<Registry> {
        Self::open_with(dir, MIGRATIONS)
    }

    /// The registered apps, read without changing anything (no migrations, no writing): for
    /// the uninstaller, which asks again when apps still use the hub. Works while the hub runs.
    pub fn read_apps(dir: &Path) -> StoreResult<Vec<App>> {
        let path = dir.join(REGISTRY_FILE);
        if !path.is_file() {
            return Ok(Vec::new());
        }
        let conn = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(sql)?;
        let mut stmt = conn
            .prepare(&format!("SELECT {APP} FROM apps ORDER BY public_port"))
            .map_err(sql)?;
        let rows = stmt.query_map([], app_row).map_err(sql)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sql)
    }

    /// Open with a given list of migrations (a later hub has a longer list).
    pub fn open_with(dir: &Path, migrations: &[&str]) -> StoreResult<Registry> {
        let mut conn = Connection::open(dir.join(REGISTRY_FILE)).map_err(sql)?;
        conn.pragma_update(None, "journal_mode", "DELETE")
            .map_err(sql)?;
        Self::migrate(&mut conn, migrations)?;
        Ok(Registry { conn })
    }

    pub fn in_memory() -> StoreResult<Registry> {
        let mut conn = Connection::open_in_memory().map_err(sql)?;
        Self::migrate(&mut conn, MIGRATIONS)?;
        Ok(Registry { conn })
    }

    fn migrate(conn: &mut Connection, migrations: &[&str]) -> StoreResult<()> {
        let v: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(sql)?;
        let to = migrations.len() as i64;
        if v > to {
            return Err(format!(
                "The hub's records were made by a newer Keep Hub (version {v}); update Keep Hub."
            ));
        }
        let tx = conn.transaction().map_err(sql)?;
        for m in migrations.iter().skip(v as usize) {
            tx.execute_batch(m).map_err(sql)?;
        }
        tx.pragma_update(None, "user_version", to).map_err(sql)?;
        tx.commit().map_err(sql)
    }

    pub fn get(&self, key: &str) -> StoreResult<Option<String>> {
        self.conn
            .query_row("SELECT value FROM kv WHERE key = ?1", [key], |r| r.get(0))
            .optional()
            .map_err(sql)
    }

    pub fn set(&self, key: &str, value: &str) -> StoreResult<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)",
                [key, value],
            )
            .map(|_| ())
            .map_err(sql)
    }

    // ----- apps ---------------------------------------------------------------------------------

    pub fn apps(&self) -> StoreResult<Vec<App>> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {APP} FROM apps ORDER BY public_port"))
            .map_err(sql)?;
        let rows = stmt.query_map([], app_row).map_err(sql)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sql)
    }

    pub fn app(&self, id: &str) -> StoreResult<Option<App>> {
        self.conn
            .query_row(
                &format!("SELECT {APP} FROM apps WHERE id = ?1"),
                [id],
                app_row,
            )
            .optional()
            .map_err(sql)
    }

    /// Record an app, or replace what is recorded for its id.
    pub fn put_app(&self, a: &App) -> StoreResult<()> {
        self.conn
            .execute(
                "INSERT INTO apps (id, title, version, protocol, public_port, loopback_port, money, guests, registered)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT (id) DO UPDATE SET title = ?2, version = ?3, protocol = ?4,
                     public_port = ?5, loopback_port = ?6, money = ?7, guests = ?8, registered = ?9",
                rusqlite::params![
                    a.id,
                    a.title,
                    a.version,
                    a.protocol,
                    a.public_port,
                    a.loopback_port,
                    a.money,
                    a.guests,
                    a.registered
                ],
            )
            .map(|_| ())
            .map_err(sql)
    }

    /// Forget an app: its devices are revoked, its grants and unused invites removed.
    /// `false` when there is no such app.
    pub fn remove_app(&mut self, id: &str, now: i64) -> StoreResult<bool> {
        let tx = self.conn.transaction().map_err(sql)?;
        tx.execute(
            "UPDATE devices SET revoked = ?2 WHERE app = ?1 AND revoked IS NULL",
            rusqlite::params![id, now],
        )
        .map_err(sql)?;
        tx.execute("DELETE FROM grants WHERE app = ?1", [id])
            .map_err(sql)?;
        tx.execute("DELETE FROM invites WHERE app = ?1", [id])
            .map_err(sql)?;
        let n = tx
            .execute("DELETE FROM apps WHERE id = ?1", [id])
            .map_err(sql)?;
        tx.commit().map_err(sql)?;
        Ok(n > 0)
    }

    // ----- members ------------------------------------------------------------------------------

    pub fn add_member(&self, name: &str, now: i64) -> StoreResult<u32> {
        self.conn
            .execute(
                "INSERT INTO members (name, created) VALUES (?1, ?2)",
                rusqlite::params![name, now],
            )
            .map_err(sql)?;
        Ok(self.conn.last_insert_rowid() as u32)
    }

    /// `false` when there is no such member.
    pub fn rename_member(&self, id: u32, name: &str) -> StoreResult<bool> {
        let n = self
            .conn
            .execute(
                "UPDATE members SET name = ?2 WHERE id = ?1",
                rusqlite::params![id, name],
            )
            .map_err(sql)?;
        Ok(n > 0)
    }

    pub fn member(&self, id: u32) -> StoreResult<Option<Member>> {
        self.conn
            .query_row(
                &format!("SELECT {MEMBER} FROM members WHERE id = ?1"),
                [id],
                member_row,
            )
            .optional()
            .map_err(sql)
    }

    pub fn members(&self) -> StoreResult<Vec<Member>> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {MEMBER} FROM members ORDER BY id"))
            .map_err(sql)?;
        let rows = stmt.query_map([], member_row).map_err(sql)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sql)
    }

    // ----- grants -------------------------------------------------------------------------------

    /// Let a member use an app (no change when they already may).
    pub fn give_grant(&self, member: u32, app: &str, now: i64) -> StoreResult<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO grants (member, app, created) VALUES (?1, ?2, ?3)",
                rusqlite::params![member, app, now],
            )
            .map(|_| ())
            .map_err(sql)
    }

    /// `false` when there was no such grant.
    pub fn remove_grant(&self, member: u32, app: &str) -> StoreResult<bool> {
        let n = self
            .conn
            .execute(
                "DELETE FROM grants WHERE member = ?1 AND app = ?2",
                rusqlite::params![member, app],
            )
            .map_err(sql)?;
        Ok(n > 0)
    }

    pub fn has_grant(&self, member: u32, app: &str) -> StoreResult<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM grants WHERE member = ?1 AND app = ?2",
                rusqlite::params![member, app],
                |_| Ok(()),
            )
            .optional()
            .map(|r| r.is_some())
            .map_err(sql)
    }

    pub fn grants(&self) -> StoreResult<Vec<Grant>> {
        let mut stmt = self
            .conn
            .prepare("SELECT member, app, created FROM grants ORDER BY member, app")
            .map_err(sql)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Grant {
                    member: r.get(0)?,
                    app: r.get(1)?,
                    created: r.get(2)?,
                })
            })
            .map_err(sql)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sql)
    }

    // ----- devices ------------------------------------------------------------------------------

    /// Record a newly paired device; returns its id.
    pub fn add_device(
        &self,
        token: &str,
        member: u32,
        app: &str,
        name: &str,
        now: i64,
    ) -> StoreResult<u32> {
        self.conn
            .execute(
                "INSERT INTO devices (token_hash, member, app, name, created) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![token_hash(token), member, app, name, now],
            )
            .map_err(sql)?;
        Ok(self.conn.last_insert_rowid() as u32)
    }

    /// The device holding `token`, unless it was revoked.
    pub fn device_by_token(&self, token: &str) -> StoreResult<Option<Device>> {
        self.conn
            .query_row(
                &format!("SELECT {DEVICE} FROM devices WHERE token_hash = ?1 AND revoked IS NULL"),
                [token_hash(token)],
                device_row,
            )
            .optional()
            .map_err(sql)
    }

    pub fn touch(&self, id: u32, now: i64) -> StoreResult<()> {
        self.conn
            .execute(
                "UPDATE devices SET last_seen = ?2 WHERE id = ?1",
                rusqlite::params![id, now],
            )
            .map(|_| ())
            .map_err(sql)
    }

    pub fn devices(&self) -> StoreResult<Vec<Device>> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {DEVICE} FROM devices ORDER BY id"))
            .map_err(sql)?;
        let rows = stmt.query_map([], device_row).map_err(sql)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sql)
    }

    /// Refuse the device's token from now on. `false` when there is no such device.
    pub fn revoke_device(&self, id: u32, now: i64) -> StoreResult<bool> {
        let n = self
            .conn
            .execute(
                "UPDATE devices SET revoked = ?2 WHERE id = ?1 AND revoked IS NULL",
                rusqlite::params![id, now],
            )
            .map_err(sql)?;
        Ok(n > 0)
    }

    // ----- guest invites ------------------------------------------------------------------------

    /// Record a guest invite by the hash of its code; returns its id.
    pub fn add_invite(
        &self,
        code: &str,
        app: &str,
        scope: &str,
        now: i64,
        expires: i64,
    ) -> StoreResult<u32> {
        self.conn
            .execute(
                "INSERT INTO invites (code_hash, app, scope, created, expires) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![token_hash(code), app, scope, now, expires],
            )
            .map_err(sql)?;
        Ok(self.conn.last_insert_rowid() as u32)
    }

    pub fn invite_by_code(&self, code: &str) -> StoreResult<Option<Invite>> {
        self.conn
            .query_row(
                &format!("SELECT {INVITE} FROM invites WHERE code_hash = ?1"),
                [token_hash(code)],
                invite_row,
            )
            .optional()
            .map_err(sql)
    }

    /// `false` when there is no such invite.
    pub fn remove_invite(&self, id: u32) -> StoreResult<bool> {
        let n = self
            .conn
            .execute("DELETE FROM invites WHERE id = ?1", [id])
            .map_err(sql)?;
        Ok(n > 0)
    }

    pub fn invites(&self) -> StoreResult<Vec<Invite>> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {INVITE} FROM invites ORDER BY id"))
            .map_err(sql)?;
        let rows = stmt.query_map([], invite_row).map_err(sql)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sql)
    }

    /// Use a guest invite, in one step: the invite is removed, a guest member is made with
    /// a grant for the invite's app, and their device is recorded. Returns the member's and
    /// the device's ids; `None` when the invite is gone (someone else used it first).
    pub fn pair_guest(
        &mut self,
        invite: &Invite,
        name: &str,
        token: &str,
        now: i64,
    ) -> StoreResult<Option<(u32, u32)>> {
        let tx = self.conn.transaction().map_err(sql)?;
        let used = tx
            .execute("DELETE FROM invites WHERE id = ?1", [invite.id])
            .map_err(sql)?;
        if used == 0 {
            return Ok(None);
        }
        tx.execute(
            "INSERT INTO members (name, guest_app, guest_scope, created) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![name, invite.app, invite.scope, now],
        )
        .map_err(sql)?;
        let member = tx.last_insert_rowid() as u32;
        tx.execute(
            "INSERT INTO grants (member, app, created) VALUES (?1, ?2, ?3)",
            rusqlite::params![member, invite.app, now],
        )
        .map_err(sql)?;
        tx.execute(
            "INSERT INTO devices (token_hash, member, app, name, created) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![token_hash(token), member, invite.app, name, now],
        )
        .map_err(sql)?;
        let device = tx.last_insert_rowid() as u32;
        tx.commit().map_err(sql)?;
        Ok(Some((member, device)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(id: &str, port: u16) -> App {
        App {
            id: id.into(),
            title: id.to_uppercase(),
            version: "1.0.0".into(),
            protocol: 1,
            public_port: port,
            loopback_port: port + 1000,
            money: false,
            guests: true,
            registered: 5,
        }
    }

    #[test]
    fn devices_are_found_by_token_until_revoked() {
        let r = Registry::in_memory().unwrap();
        let sam = r.add_member("Sam", 1).unwrap();
        let id = r
            .add_device("tok-1", sam, "alpha", "Sam's phone", 10)
            .unwrap();
        assert_eq!(r.device_by_token("tok-1").unwrap().unwrap().member, sam);
        assert!(r.device_by_token("tok-2").unwrap().is_none());
        r.touch(id, 20).unwrap();
        assert_eq!(r.devices().unwrap()[0].last_seen, Some(20));
        assert!(r.revoke_device(id, 30).unwrap());
        assert!(r.device_by_token("tok-1").unwrap().is_none());
        assert!(!r.revoke_device(id, 31).unwrap());
        assert_eq!(r.devices().unwrap()[0].revoked, Some(30));
    }

    #[test]
    fn grants_are_per_member_and_app() {
        let r = Registry::in_memory().unwrap();
        let sam = r.add_member("Sam", 1).unwrap();
        let ana = r.add_member("Ana", 1).unwrap();
        r.give_grant(sam, "alpha", 2).unwrap();
        r.give_grant(sam, "alpha", 3).unwrap(); // again: no change
        assert!(r.has_grant(sam, "alpha").unwrap());
        assert!(!r.has_grant(sam, "beta").unwrap());
        assert!(!r.has_grant(ana, "alpha").unwrap());
        assert_eq!(r.grants().unwrap().len(), 1);
        assert_eq!(r.grants().unwrap()[0].created, 2);
        assert!(r.remove_grant(sam, "alpha").unwrap());
        assert!(!r.remove_grant(sam, "alpha").unwrap());
        assert!(r.rename_member(ana, "Ana M").unwrap());
        assert!(!r.rename_member(99, "Nobody").unwrap());
        assert_eq!(r.member(ana).unwrap().unwrap().name, "Ana M");
    }

    #[test]
    fn two_apps_cannot_hold_one_port() {
        let r = Registry::in_memory().unwrap();
        r.put_app(&app("alpha", 16443)).unwrap();
        assert!(r.put_app(&app("beta", 16443)).is_err());
        r.put_app(&app("beta", 16444)).unwrap();
        // the same app again replaces its record
        let mut a = app("alpha", 16443);
        a.version = "1.1.0".into();
        r.put_app(&a).unwrap();
        assert_eq!(r.app("alpha").unwrap().unwrap().version, "1.1.0");
        assert_eq!(r.apps().unwrap().len(), 2);
    }

    #[test]
    fn removing_an_app_revokes_its_devices_only() {
        let mut r = Registry::in_memory().unwrap();
        r.put_app(&app("alpha", 16443)).unwrap();
        r.put_app(&app("beta", 16444)).unwrap();
        let sam = r.add_member("Sam", 1).unwrap();
        r.give_grant(sam, "alpha", 1).unwrap();
        r.give_grant(sam, "beta", 1).unwrap();
        r.add_device("a", sam, "alpha", "phone", 1).unwrap();
        r.add_device("b", sam, "beta", "phone", 1).unwrap();
        r.add_invite("CODE0001", "alpha", "trip-1", 1, 100).unwrap();
        assert!(r.remove_app("alpha", 9).unwrap());
        assert!(!r.remove_app("alpha", 9).unwrap());
        assert!(r.device_by_token("a").unwrap().is_none());
        assert!(r.device_by_token("b").unwrap().is_some());
        assert!(!r.has_grant(sam, "alpha").unwrap());
        assert!(r.has_grant(sam, "beta").unwrap());
        assert!(r.invites().unwrap().is_empty());
    }

    #[test]
    fn a_guest_invite_works_once() {
        let mut r = Registry::in_memory().unwrap();
        r.add_invite("CODE0001", "alpha", "trip-1", 1, 100).unwrap();
        assert!(r.invite_by_code("CODE0002").unwrap().is_none());
        let inv = r.invite_by_code("CODE0001").unwrap().unwrap();
        let (member, device) = r.pair_guest(&inv, "Kim", "tok", 5).unwrap().unwrap();
        let m = r.member(member).unwrap().unwrap();
        assert_eq!(m.guest_app.as_deref(), Some("alpha"));
        assert_eq!(m.guest_scope.as_deref(), Some("trip-1"));
        assert!(r.has_grant(member, "alpha").unwrap());
        assert_eq!(r.device_by_token("tok").unwrap().unwrap().id, device);
        assert!(r.pair_guest(&inv, "Lee", "tok2", 6).unwrap().is_none());
        assert_eq!(r.members().unwrap().len(), 1);
    }

    #[test]
    fn the_registry_survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        {
            let r = Registry::open(dir.path()).unwrap();
            let m = r.add_member("Sam", 1).unwrap();
            r.add_device("tok", m, "alpha", "desk", 1).unwrap();
            r.set(PIN_KEY, "hash").unwrap();
        }
        let r = Registry::open(dir.path()).unwrap();
        assert!(r.device_by_token("tok").unwrap().is_some());
        assert_eq!(r.get(PIN_KEY).unwrap().as_deref(), Some("hash"));
    }

    /// Acceptance test 21.
    #[test]
    fn a_later_hub_opens_this_registry_and_a_newer_registry_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        {
            let r = Registry::open(dir.path()).unwrap();
            let m = r.add_member("Sam", 1).unwrap();
            r.give_grant(m, "alpha", 1).unwrap();
            r.add_device("tok", m, "alpha", "phone", 1).unwrap();
        }
        // a later hub: one more migration
        let mut later: Vec<&str> = MIGRATIONS.to_vec();
        later.push("ALTER TABLE members ADD COLUMN note TEXT;");
        {
            let r = Registry::open_with(dir.path(), &later).unwrap();
            assert!(r.device_by_token("tok").unwrap().is_some());
            assert!(r.has_grant(1, "alpha").unwrap());
            // and opening it again changes nothing
            drop(r);
            Registry::open_with(dir.path(), &later).unwrap();
        }
        // this hub now meets a registry marked newer than it knows
        let e = Registry::open(dir.path()).unwrap_err();
        assert!(e.contains("newer Keep Hub"), "{e}");
        assert!(e.contains("update Keep Hub"), "{e}");
    }
}
