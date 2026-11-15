//! The repository over a fake transport serving a TUF repository of synthetic keys.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use oncl_pki::http::HttpTransport;
use oncl_update::tuf::store::{FileStore, Store};
use oncl_update::tuf::testing::Repo;
use oncl_update::{Channel, Index, UpdateError};
use time::{Duration as TimeDuration, OffsetDateTime};

use super::Repository;
use crate::update::tests::FakeTransport;

/// Where the fake repository is "published".
pub(crate) const BASE: &str = "https://example.org/tuf/v1";

/// The URL of `path` of the repository.
pub(crate) fn url(path: &str) -> String {
    format!("{BASE}/{path}")
}

/// The URL of the timestamp.
pub(crate) fn timestamp_url() -> String {
    url("metadata/timestamp.json")
}

/// The URL whose requests count the downloads of the index: every refresh asks first for the
/// next root, whatever else fails after it.
pub(crate) fn refresh_url() -> String {
    url("metadata/2.root.json")
}

/// A TUF repository of synthetic keys, and the way it is put on a [`FakeTransport`].
pub(crate) struct Server {
    pub(crate) repo: Mutex<Repo>,
}

impl Server {
    pub(crate) fn new() -> Server {
        Server {
            repo: Mutex::new(Repo::new()),
        }
    }

    /// The root the clients are built with.
    pub(crate) fn anchor(&self) -> Vec<u8> {
        self.repo().anchor().to_vec()
    }

    pub(crate) fn repo(&self) -> std::sync::MutexGuard<'_, Repo> {
        self.repo.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Publishes `body` as the index of `channel` and serves every file of the repository.
    pub(crate) fn publish(&self, transport: &FakeTransport, channel: Channel, body: &[u8]) {
        self.repo().publish(channel, body);
        self.serve(transport);
    }

    /// Serves every file of the repository; the next root is not there.
    pub(crate) fn serve(&self, transport: &FakeTransport) {
        for (path, bytes) in self.repo().files() {
            transport.serve(&url(path), bytes);
        }
        transport.reply(&url("metadata/2.root.json"), 404, b"");
    }
}

/// An empty index of `channel`.
pub(crate) fn index(channel: Channel, seq: u64) -> Vec<u8> {
    let generated = OffsetDateTime::now_utc() - TimeDuration::hours(1);
    serde_json::to_vec_pretty(&Index {
        schema: 1,
        channel,
        seq,
        generated,
        expires: generated + TimeDuration::days(14),
        core: Vec::new(),
        extension: None,
        plugins: Vec::new(),
    })
    .unwrap()
}

const TIMEOUT: Duration = Duration::from_secs(20);

fn repository(
    server: &Server,
    dir: &std::path::Path,
    transport: &Arc<FakeTransport>,
) -> Repository {
    Repository::with_anchor(
        &server.anchor(),
        dir,
        BASE,
        Arc::clone(transport) as Arc<dyn HttpTransport>,
    )
    .unwrap()
}

fn refused(e: &UpdateError) -> bool {
    matches!(e, UpdateError::Tuf(_)) && !e.retry_soon()
}

#[test]
fn the_index_is_read_through_tuf_and_held_to_its_channel_and_seq() {
    let (server, transport, dir) = (
        Server::new(),
        Arc::new(FakeTransport::default()),
        tempfile::tempdir().unwrap(),
    );
    let body = index(Channel::Stable, 7);
    server.publish(&transport, Channel::Stable, &body);
    let r = repository(&server, dir.path(), &transport);

    let got = r.index(Channel::Stable, Some(7), TIMEOUT).unwrap();
    assert_eq!((got.index.seq, got.bytes.as_slice()), (7, body.as_slice()));
    // It holds until the first of the root's and the targets' expiry: 30 days.
    let left = got.valid_until - OffsetDateTime::now_utc();
    assert!(
        left > TimeDuration::days(29) && left <= TimeDuration::days(30),
        "{left}"
    );
    // Every request is HTTPS only, within the size of the file it is for.
    assert!(
        transport
            .asked()
            .iter()
            .all(|(_, _, https_only)| *https_only)
    );

    // An index whose `seq` went back, or of another channel, is refused though the
    // repository vouches for it.
    let e = r.index(Channel::Stable, Some(8), TIMEOUT).unwrap_err();
    assert!(
        matches!(e, UpdateError::Rollback { seq: 7, last: 8 }),
        "{e}"
    );
    assert!(!e.retry_soon());
    server.publish(&transport, Channel::Beta, &index(Channel::Stable, 9));
    let e = r.index(Channel::Beta, None, TIMEOUT).unwrap_err();
    assert!(matches!(e, UpdateError::WrongChannel { .. }), "{e}");
    // The age of the index (generated long ago, expires in the past) is not what ends it.
    let old = {
        let generated = OffsetDateTime::now_utc() - TimeDuration::days(90);
        let mut v: serde_json::Value = serde_json::from_slice(&index(Channel::Stable, 10)).unwrap();
        v["generated"] = serde_json::json!(
            generated
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        );
        v["expires"] = v["generated"].clone();
        serde_json::to_vec(&v).unwrap()
    };
    server.publish(&transport, Channel::Stable, &old);
    assert_eq!(
        r.index(Channel::Stable, Some(10), TIMEOUT)
            .unwrap()
            .index
            .seq,
        10
    );
}

#[test]
fn a_rolled_back_timestamp_is_refused_by_every_handle_on_the_state() {
    let (server, transport, dir) = (
        Server::new(),
        Arc::new(FakeTransport::default()),
        tempfile::tempdir().unwrap(),
    );
    server.publish(&transport, Channel::Stable, &index(Channel::Stable, 1));
    let old_timestamp = server
        .repo()
        .get("metadata/timestamp.json")
        .unwrap()
        .to_vec();
    server.publish(&transport, Channel::Stable, &index(Channel::Stable, 2));

    // One handle (the updater's) takes the newer; another (the plugin catalog's, as a
    // second process would be) on the same directory, shown the older one, refuses it.
    let updater = repository(&server, dir.path(), &transport);
    assert_eq!(
        updater
            .index(Channel::Stable, None, TIMEOUT)
            .unwrap()
            .index
            .seq,
        2
    );
    transport.serve(&timestamp_url(), &old_timestamp);
    let catalog = repository(&server, dir.path(), &transport);
    let e = catalog.index(Channel::Stable, None, TIMEOUT).unwrap_err();
    assert!(refused(&e), "{e}");
    assert!(e.to_string().contains("was trusted before"), "{e}");
    // The same one, on a directory that has seen nothing, takes it: only the state refuses.
    let fresh = tempfile::tempdir().unwrap();
    assert_eq!(
        repository(&server, fresh.path(), &transport)
            .index(Channel::Stable, None, TIMEOUT)
            .unwrap()
            .index
            .seq,
        1
    );
}

#[test]
fn what_each_handle_saves_the_other_keeps() {
    let (server, transport, dir) = (
        Server::new(),
        Arc::new(FakeTransport::default()),
        tempfile::tempdir().unwrap(),
    );
    server.publish(&transport, Channel::Stable, &index(Channel::Stable, 1));
    let (a, b) = (
        repository(&server, dir.path(), &transport),
        repository(&server, dir.path(), &transport),
    );
    a.index(Channel::Stable, None, TIMEOUT).unwrap();
    let second = index(Channel::Stable, 2);
    server.publish(&transport, Channel::Stable, &second);
    b.index(Channel::Stable, None, TIMEOUT).unwrap();
    // `a` saves nothing newer than it knew (the repository is as `b` left it), and it does
    // not undo what `b` saved: the versions on disk are the highest of both.
    a.index(Channel::Stable, None, TIMEOUT).unwrap();
    let saved = FileStore::in_data_dir(dir.path()).load().unwrap();
    let timestamp = saved.timestamp.unwrap();
    assert_eq!(timestamp.version, 1_000_001);
    assert_eq!(saved.targets, Some(2));
    // Both see the index that is current, kept offline.
    for handle in [&a, &b] {
        handle
            .verify_kept(Channel::Stable, &second, OffsetDateTime::now_utc())
            .unwrap();
    }
}

#[test]
fn an_expired_timestamp_a_tampered_index_and_a_wrong_key_are_refused() {
    let transport = Arc::new(FakeTransport::default());
    let dir = tempfile::tempdir().unwrap();
    let server = Server::new();
    // Signed 8 days ago: the timestamp's 7 days are over.
    server.repo().signed_at = OffsetDateTime::now_utc() - TimeDuration::days(8);
    server.publish(&transport, Channel::Stable, &index(Channel::Stable, 1));
    let r = repository(&server, dir.path(), &transport);
    let e = r.index(Channel::Stable, None, TIMEOUT).unwrap_err();
    assert!(refused(&e) && e.to_string().contains("expired"), "{e}");

    // The index file served is not the one the targets list.
    let server = Server::new();
    server.publish(&transport, Channel::Stable, &index(Channel::Stable, 1));
    let path = server.repo().index_file_path(Channel::Stable);
    let mut body = server.repo().get(&path).unwrap().to_vec();
    body[10] ^= 1;
    transport.serve(&url(&path), &body);
    let dir = tempfile::tempdir().unwrap();
    let e = repository(&server, dir.path(), &transport)
        .index(Channel::Stable, None, TIMEOUT)
        .unwrap_err();
    assert!(
        refused(&e) && e.to_string().contains("does not match"),
        "{e}"
    );

    // A repository of other keys than the root built in.
    let hostile = Server::new();
    *hostile.repo() = Repo::with_seed(41);
    hostile.publish(&transport, Channel::Stable, &index(Channel::Stable, 1));
    let dir = tempfile::tempdir().unwrap();
    let e = repository(&server, dir.path(), &transport)
        .index(Channel::Stable, None, TIMEOUT)
        .unwrap_err();
    assert!(refused(&e) && e.to_string().contains("signatures"), "{e}");
}

#[test]
fn a_repository_that_is_not_there_is_not_published_and_one_that_cannot_be_read_is_retried() {
    let (server, transport, dir) = (
        Server::new(),
        Arc::new(FakeTransport::default()),
        tempfile::tempdir().unwrap(),
    );
    let r = repository(&server, dir.path(), &transport);
    // Nothing answers: retry soon.
    let e = r.index(Channel::Stable, None, TIMEOUT).unwrap_err();
    assert!(e.retry_soon(), "{e}");
    // 404 for the timestamp: not published.
    transport.reply(&timestamp_url(), 404, b"");
    transport.reply(&url("metadata/2.root.json"), 404, b"");
    assert!(matches!(
        r.index(Channel::Stable, None, TIMEOUT),
        Err(UpdateError::NotPublished(Channel::Stable))
    ));
    // Published, but the channel has no entry in the targets: not published either.
    server.publish(&transport, Channel::Beta, &index(Channel::Beta, 1));
    assert!(matches!(
        r.index(Channel::Stable, None, TIMEOUT),
        Err(UpdateError::NotPublished(Channel::Stable))
    ));
    r.index(Channel::Beta, None, TIMEOUT).unwrap();
    // A server error: retry soon; no time left: the same.
    transport.reply(&timestamp_url(), 503, b"");
    let e = r.index(Channel::Beta, None, TIMEOUT).unwrap_err();
    assert!(e.retry_soon() && e.to_string().contains("HTTP 503"), "{e}");
    let e = r.index(Channel::Beta, None, Duration::ZERO).unwrap_err();
    assert!(
        e.retry_soon() && e.to_string().contains("no time left"),
        "{e}"
    );
}

#[test]
fn a_kept_index_is_checked_offline_against_the_saved_targets() {
    let (server, transport, dir) = (
        Server::new(),
        Arc::new(FakeTransport::default()),
        tempfile::tempdir().unwrap(),
    );
    let body = index(Channel::Stable, 3);
    server.publish(&transport, Channel::Stable, &body);
    let r = repository(&server, dir.path(), &transport);
    let now = OffsetDateTime::now_utc();
    // Before any refresh nothing is vouched for.
    assert!(r.verify_kept(Channel::Stable, &body, now).is_err());
    r.index(Channel::Stable, None, TIMEOUT).unwrap();
    let asked = transport.asked().len();

    let until = r.verify_kept(Channel::Stable, &body, now).unwrap();
    assert!(until > now + TimeDuration::days(29));
    assert!(
        r.verify_kept(Channel::Stable, &index(Channel::Stable, 4), now)
            .is_err()
    );
    assert!(r.verify_kept(Channel::Beta, &body, now).is_err());
    assert!(
        r.verify_kept(Channel::Stable, &body, now + TimeDuration::days(31))
            .is_err()
    );
    assert_eq!(transport.asked().len(), asked, "no request was made");
}

#[test]
fn without_the_trust_root_built_in_there_is_no_repository() {
    let dir = tempfile::tempdir().unwrap();
    let transport: Arc<dyn HttpTransport> = Arc::new(FakeTransport::default());
    let opened = Repository::open(dir.path(), BASE, transport);
    assert_eq!(opened.is_none(), oncl_update::embedded_root().is_none());
    // A base that is not HTTPS is no repository either.
    let transport: Arc<dyn HttpTransport> = Arc::new(FakeTransport::default());
    let server = Server::new();
    assert!(
        Repository::with_anchor(
            &server.anchor(),
            dir.path(),
            "http://example.org/tuf",
            transport
        )
        .is_err()
    );
}
