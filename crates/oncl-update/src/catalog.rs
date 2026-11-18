//! The plugin catalog of a channel: the owner's index plus the releases of third-party
//! publishers (`docs/design/publishers.md`, «Каталог»).
//!
//! A [`Catalog`] is built from the owner's [`Index`], `publishers.json` read into a
//! [`PublisherPolicy`] and the delegated roles of the publishers. The owner's word wins:
//!
//! 1. a version the owner revoked in `publishers.json` is revoked whatever the publisher's
//!    role says;
//! 2. a publisher's release with an id of the owner's index is left out;
//! 3. a publisher's release serving a module or standing for a bundle of a release of the
//!    owner's index is left out, unless the publisher replaces that port (`supersedes`);
//! 4. a publisher's release outside its prefix, modules or bundles is left out.
//!
//! Each publisher is [`PublisherState::Active`], [`PublisherState::Retired`] (it publishes no
//! more: no new versions, installed ones stay unless revoked),
//! [`PublisherState::Unavailable`] (its role, `publishers.json` or the delegations did not
//! hold up, its `state` is unknown to this version, or `publishers.json` does not name it:
//! its plugins are not updated and stay installed, except versions the owner revoked in
//! `publishers.json`) or [`PublisherState::Revoked`] (the verified `publishers.json` says
//! so). An error or a missing entry never revokes a publisher.
//!
//! A catalog of the owner's index alone ([`Catalog::owner`]) behaves as the index did:
//! every publisher is unavailable and only the index's releases are offered.

mod names;
mod policy;
mod release;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use semver::Version;
use tracing::warn;

pub use names::{BundleName, IdPrefix, ModuleName, PROJECT_PREFIX, PluginId};
pub use policy::{
    ActivePublisher, CatalogError, Publisher, PublisherDisplay, PublisherPolicy, RevokedVersion,
    Standing,
};
pub use release::{
    CapabilitiesError, DeclaredCapabilities, EntryRejected, EntryRejection, MAX_URL,
    PublisherRelease, PublisherTarget,
};

use crate::index::Index;
use crate::plugins::{PluginRelease, offerable};
use crate::tuf::{Delegated, PublisherName, RoleName, Target, TargetPath};

/// What the catalog knows of a publisher.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PublisherState {
    /// Its role was verified; its releases are in the catalog.
    Active,
    /// It publishes no more: none of its releases is offered, its installed plugins stay
    /// unless the owner revoked their versions in `publishers.json`.
    Retired,
    /// Its role, `publishers.json` or the delegations did not hold up, its `state` is
    /// unknown to this version, or `publishers.json` does not name it: its installed plugins
    /// stay as they are until they do.
    Unavailable,
    /// The verified `publishers.json` names it revoked: its plugins are turned off.
    Revoked,
}

/// The plugin catalog of a channel: the owner's index and the publishers' releases.
#[derive(Debug)]
pub struct Catalog {
    index: Index,
    /// `None`: `publishers.json` is unknown (a catalog of the owner's index alone) or was not
    /// used; every publisher is unavailable.
    policy: Option<PublisherPolicy>,
    /// The state of every publisher of `policy`.
    states: BTreeMap<PublisherName, PublisherState>,
    /// The releases of the active publishers offered on the index's channel.
    releases: Vec<PluginRelease>,
    rejected: Vec<EntryRejected>,
}

/// The publishers' side of a [`Catalog`] being built ([`Catalog::builder`]).
#[derive(Debug)]
#[must_use = "a builder does nothing until built"]
pub struct CatalogBuilder<'r> {
    index: Index,
    policy: Result<PublisherPolicy, CatalogError>,
    builtin_modules: BTreeSet<String>,
    /// The delegated roles, in order, each name once: its targets if it was verified.
    roles: Vec<(PublisherName, Option<&'r BTreeMap<TargetPath, Target>>)>,
}

impl Catalog {
    /// The catalog of the owner's index alone, as before publishers: every publisher is
    /// unavailable.
    pub fn owner(index: Index) -> Catalog {
        Catalog {
            index,
            policy: None,
            states: BTreeMap::new(),
            releases: Vec::new(),
            rejected: Vec::new(),
        }
    }

    /// Starts a catalog of `index` and `publishers.json` read as `policy`; an `Err` makes
    /// every publisher unavailable.
    pub fn builder<'r>(
        index: Index,
        policy: Result<PublisherPolicy, CatalogError>,
    ) -> CatalogBuilder<'r> {
        CatalogBuilder {
            index,
            policy,
            builtin_modules: BTreeSet::new(),
            roles: Vec::new(),
        }
    }

    /// The owner's index.
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// `publishers.json`, if it is used.
    pub fn policy(&self) -> Option<&PublisherPolicy> {
        self.policy.as_ref()
    }

    /// Every release: the owner's index's, then the active publishers' offered on its
    /// channel. A port another publisher replaces is among them ([`Catalog::replacement`]).
    pub fn releases(&self) -> impl Iterator<Item = &PluginRelease> {
        self.index.plugins.iter().chain(&self.releases)
    }

    /// The publishers' targets left out, and why.
    pub fn rejected(&self) -> &[EntryRejected] {
        &self.rejected
    }

    /// The state of `publisher`; unavailable if `publishers.json` is not used or does not
    /// name it.
    pub fn publisher_state(&self, publisher: &PublisherName) -> PublisherState {
        self.states
            .get(publisher)
            .copied()
            .unwrap_or(PublisherState::Unavailable)
    }

    /// The publisher of the plugin `id`, by the prefixes of `publishers.json` (revoked
    /// publishers included); `None` for a plugin of the owner's index, or while
    /// `publishers.json` is not used.
    pub fn publisher_of(&self, id: &str) -> Option<&PublisherName> {
        if self.index.plugins.iter().any(|r| r.id == id) {
            return None;
        }
        Some(self.policy.as_ref()?.covering(id)?.name())
    }

    /// Whether `version` of `id` is revoked: by its release in the catalog, or by the owner
    /// in `publishers.json` (build metadata aside), listed or not. The owner's revocation
    /// holds while the publisher is active, retired or unavailable; it needs
    /// `publishers.json`.
    pub fn is_revoked(&self, id: &str, version: &Version) -> bool {
        self.releases()
            .any(|r| r.id == id && r.version == *version && r.revoked)
            || self.publisher_of(id).is_some_and(|publisher| {
                self.publisher_state(publisher) != PublisherState::Revoked
                    && self
                        .policy
                        .as_ref()
                        .and_then(|policy| policy.publisher(publisher))
                        .and_then(Publisher::rules)
                        .is_some_and(|active| active.revokes(id, version))
            })
    }

    /// The release replacing the port `port`, if an active publisher replaces it
    /// (`supersedes`) and offers this installation a version of its plugin: the newest one
    /// compatible with `core`, not revoked, not `bad`, rolled out to `install_id`, serving
    /// every module and standing for every bundle of the port's releases in the owner's
    /// index. Until then the port stays as it is.
    pub fn replacement(
        &self,
        port: &str,
        core: &Version,
        install_id: &[u8; 16],
        bad: &BTreeMap<String, BTreeSet<Version>>,
    ) -> Option<&PluginRelease> {
        let (publisher, plugin) = self.policy.as_ref()?.superseding(port)?;
        if self.publisher_state(publisher.name()) != PublisherState::Active {
            return None;
        }
        let ports = || self.index.plugins.iter().filter(|r| r.id == port);
        let covers = |r: &PluginRelease| {
            ports().all(|p| {
                p.modules.iter().all(|m| r.modules.contains(m))
                    && p.replaces.as_ref().is_none_or(|bundle| {
                        r.replaces
                            .as_ref()
                            .is_some_and(|own| own.symname == bundle.symname)
                    })
            })
        };
        self.releases
            .iter()
            .filter(|r| r.id == plugin.as_str() && offerable(r, core, install_id, bad) && covers(r))
            .max_by(|a, b| a.version.cmp(&b.version))
    }
}

impl<'r> CatalogBuilder<'r> {
    /// The modules the core serves itself: a `publishers.json` that gives one to a
    /// publisher is not used.
    pub fn builtin_modules(mut self, modules: impl IntoIterator<Item = String>) -> Self {
        self.builtin_modules.extend(modules);
        self
    }

    /// The verified role `role` and its targets.
    pub fn role(mut self, role: &RoleName, targets: &'r BTreeMap<TargetPath, Target>) -> Self {
        self.add(role, Some(targets));
        self
    }

    /// The role `role`, delegated but not verified: its publisher is unavailable.
    pub fn unavailable_role(mut self, role: &RoleName) -> Self {
        self.add(role, None);
        self
    }

    /// Every role of the delegated step ([`crate::tuf::TufClient::delegated`]).
    pub fn delegated(mut self, delegated: &'r Delegated) -> Self {
        for (name, role) in delegated.roles() {
            self.add(name, role.ok().map(|role| role.targets()));
        }
        self
    }

    fn add(&mut self, role: &RoleName, targets: Option<&'r BTreeMap<TargetPath, Target>>) {
        let publisher = role.publisher();
        if !self.roles.iter().any(|(name, _)| *name == publisher) {
            self.roles.push((publisher, targets));
        }
    }

    /// The catalog. A `publishers.json` that gives a publisher a built-in module, names a
    /// publisher active without a delegated role, or does not name (or names revoked) the
    /// publisher of a delegated role is not used: every publisher is unavailable. Active
    /// publishers' targets are offered; of a retired or unknown-state publisher's verified
    /// role only the versions it revoked are read, so they stay withdrawn. Each target left
    /// out of an active role is logged once.
    pub fn build(self) -> Catalog {
        let CatalogBuilder {
            index,
            policy,
            builtin_modules,
            roles,
        } = self;
        let policy = policy.and_then(|policy| {
            policy.check_builtin(&builtin_modules)?;
            check_delegations(&policy, &roles)?;
            Ok(policy)
        });
        let policy = match policy {
            Ok(policy) => policy,
            Err(error) => {
                warn!(error = ?error, "the publishers' catalog is unavailable");
                return Catalog::owner(index);
            }
        };
        let mut states = BTreeMap::new();
        let mut releases = Vec::new();
        let mut rejected = Vec::new();
        let owner = Owner::of(&index);
        for publisher in policy.publishers() {
            let name = publisher.name();
            let targets = roles
                .iter()
                .find(|(role, _)| role == name)
                .and_then(|(_, targets)| *targets);
            let (rules, state) = match publisher.standing() {
                Standing::Active(rules) => (rules, PublisherState::Active),
                Standing::Retired(rules) => (rules, PublisherState::Retired),
                Standing::Unknown { state, rules } => {
                    warn!(publisher = %name, state = ?state, "a publisher of an unknown state is unavailable");
                    (rules, PublisherState::Unavailable)
                }
                Standing::Revoked { .. } => {
                    states.insert(name.clone(), PublisherState::Revoked);
                    continue;
                }
            };
            let Some(targets) = targets else {
                let state = match state {
                    PublisherState::Active => PublisherState::Unavailable,
                    other => other,
                };
                states.insert(name.clone(), state);
                continue;
            };
            states.insert(name.clone(), state);
            if state != PublisherState::Active {
                // Nothing is offered; only the versions it revoked itself are kept, so an
                // installation that missed the withdrawal still withdraws them.
                releases.extend(
                    targets
                        .iter()
                        .filter_map(|(path, target)| {
                            admit(publisher, rules, &owner, path, target).ok()
                        })
                        .map(PublisherRelease::into_release)
                        .filter(|release| release.revoked),
                );
                continue;
            }
            for (path, target) in targets {
                match admit(publisher, rules, &owner, path, target) {
                    Ok(release) if release.offered_on(index.channel) => {
                        releases.push(release.into_release());
                    }
                    Ok(_) => {}
                    Err(reason) => {
                        warn!(publisher = %name, path = %path, reason = %reason, "a publisher's target is left out of the catalog");
                        rejected.push(EntryRejected {
                            path: path.clone(),
                            reason,
                        });
                    }
                }
            }
        }
        Catalog {
            index,
            policy: Some(policy),
            states,
            releases,
            rejected,
        }
    }
}

/// The active publishers are exactly those with a delegated role; a retired publisher or one
/// of an unknown state may keep its role or not, a revoked or unnamed one has none.
fn check_delegations(
    policy: &PublisherPolicy,
    roles: &[(PublisherName, Option<&BTreeMap<TargetPath, Target>>)],
) -> Result<(), CatalogError> {
    if let Some((name, _)) = roles.iter().find(|(name, _)| {
        policy
            .publisher(name)
            .is_none_or(|p| matches!(p.standing(), Standing::Revoked { .. }))
    }) {
        return Err(CatalogError::NotActive(name.clone()));
    }
    if let Some(publisher) = policy
        .publishers()
        .iter()
        .find(|p| p.active().is_some() && !roles.iter().any(|(name, _)| name == p.name()))
    {
        return Err(CatalogError::NotDelegated(publisher.name().clone()));
    }
    Ok(())
}

/// What the owner's index claims: ids, and the ids serving each module and bundle. Module
/// and bundle names are keyed in ASCII lowercase: the registries match them exactly, but a
/// name differing only in case is still too close to the owner's to give to a publisher.
struct Owner<'i> {
    ids: BTreeSet<&'i str>,
    modules: BTreeMap<String, BTreeSet<&'i str>>,
    bundles: BTreeMap<String, BTreeSet<&'i str>>,
}

impl<'i> Owner<'i> {
    fn of(index: &'i Index) -> Owner<'i> {
        let mut owner = Owner {
            ids: BTreeSet::new(),
            modules: BTreeMap::new(),
            bundles: BTreeMap::new(),
        };
        for release in &index.plugins {
            let id = release.id.as_str();
            owner.ids.insert(id);
            for module in &release.modules {
                owner
                    .modules
                    .entry(module.to_ascii_lowercase())
                    .or_default()
                    .insert(id);
            }
            if let Some(replaces) = &release.replaces {
                owner
                    .bundles
                    .entry(replaces.symname.to_ascii_lowercase())
                    .or_default()
                    .insert(id);
            }
        }
        owner
    }
}

/// `path` of `publisher`'s verified role, checked against its rules and the owner's index;
/// revoked if the owner revoked the version.
fn admit(
    publisher: &Publisher,
    active: &ActivePublisher,
    owner: &Owner<'_>,
    path: &TargetPath,
    target: &Target,
) -> Result<PublisherRelease, EntryRejection> {
    let mut release = PublisherRelease::parse(publisher.name(), path, target)?;
    let id = release.release().id.as_str();
    if !publisher.id_prefix().covers(id) {
        return Err(EntryRejection::IdOutsidePrefix);
    }
    let modules = &release.release().modules;
    if let Some(module) = modules
        .iter()
        .find(|m| !active.modules().contains(m.as_str()))
    {
        return Err(EntryRejection::ModuleNotAllowed(module.clone()));
    }
    let bundle = release.release().replaces.as_ref().map(|r| &r.symname);
    if let Some(symname) = bundle.filter(|s| !active.bundles().contains(s.as_str())) {
        return Err(EntryRejection::BundleNotAllowed(symname.clone()));
    }
    if owner.ids.contains(id) {
        return Err(EntryRejection::OwnerId);
    }
    // A port the publisher replaces with this very plugin may share its modules and bundle.
    let replaced = |ports: &BTreeSet<&str>| {
        ports.iter().all(|port| {
            active
                .supersedes()
                .get(*port)
                .is_some_and(|plugin| plugin.as_str() == id)
        })
    };
    if let Some(module) = modules.iter().find(|m| {
        owner
            .modules
            .get(&m.to_ascii_lowercase())
            .is_some_and(|p| !replaced(p))
    }) {
        return Err(EntryRejection::OwnerModule(module.clone()));
    }
    if let Some(symname) = bundle.filter(|s| {
        owner
            .bundles
            .get(&s.to_ascii_lowercase())
            .is_some_and(|p| !replaced(p))
    }) {
        return Err(EntryRejection::OwnerBundle(symname.clone()));
    }
    if active.revokes(id, &release.release().version) {
        release.revoke();
    }
    Ok(release)
}
