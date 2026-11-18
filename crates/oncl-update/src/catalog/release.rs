//! A publisher's release: a target `plugins/<publisher>/<id>/<version>.onclp` of its
//! delegated role, read into a [`PluginRelease`] from the target's `custom.oncl`. The rules
//! that need the publisher's entry of `publishers.json` or the owner's index are the
//! catalog's ([`super::Catalog`]); here only what the target says of itself is checked.

use std::sync::Arc;

use semver::Version;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::names::PluginId;
use crate::index::{Channel, Package, Sha256};
use crate::plugins::{PluginName, PluginRelease, PluginReplaces};
use crate::tuf::{PublisherName, Target, TargetPath};

/// The longest URL of a publisher's package or homepage, in bytes.
pub const MAX_URL: usize = 2048;

/// Whether `url` is a plain `https://` URL of at most [`MAX_URL`] bytes: a host, no user
/// info, query or fragment, no whitespace or control characters.
pub(crate) fn plain_https_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    url.len() <= MAX_URL
        && !authority.is_empty()
        && !authority.contains('@')
        && !url.contains(['?', '#'])
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// The `capabilities` of a publisher's release (`custom.oncl.capabilities`): the
/// `[capabilities]` table of the package's manifest as a JSON object, kept as signed. This
/// crate does not read the plugin format; the caller reads it into the plugin's
/// capabilities, and compares them with the package's manifest before installing it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredCapabilities(Map<String, Value>);

impl DeclaredCapabilities {
    /// The largest object, in bytes of compact JSON.
    pub const MAX_LEN: usize = 16 * 1024;

    /// The object as signed.
    pub fn as_object(&self) -> &Map<String, Value> {
        &self.0
    }

    /// The object as signed, owned.
    pub fn into_object(self) -> Map<String, Value> {
        self.0
    }
}

/// Why a `capabilities` value is not a [`DeclaredCapabilities`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CapabilitiesError {
    /// It is not a JSON object.
    #[error("capabilities are not a JSON object")]
    NotObject,
    /// It is larger than [`DeclaredCapabilities::MAX_LEN`].
    #[error("capabilities are {len} bytes, more than {max}")]
    TooLarge {
        /// Its length in compact JSON.
        len: usize,
        /// The limit.
        max: usize,
    },
}

impl TryFrom<Value> for DeclaredCapabilities {
    type Error = CapabilitiesError;

    fn try_from(value: Value) -> Result<DeclaredCapabilities, CapabilitiesError> {
        let Value::Object(object) = value else {
            return Err(CapabilitiesError::NotObject);
        };
        // Writing a `Value` to a `Vec` does not fail: its keys are strings.
        let len = serde_json::to_vec(&object).map_or(usize::MAX, |bytes| bytes.len());
        if len > DeclaredCapabilities::MAX_LEN {
            return Err(CapabilitiesError::TooLarge {
                len,
                max: DeclaredCapabilities::MAX_LEN,
            });
        }
        Ok(DeclaredCapabilities(object))
    }
}

/// Why a publisher's target is left out of the catalog. The other targets of its role are
/// unaffected.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EntryRejection {
    /// The path is not `plugins/<publisher>/<id>/<version>.onclp` of the role's publisher.
    #[error("the path is not plugins/<publisher>/<id>/<version>.onclp of its role")]
    Path,
    /// The target has no `custom.oncl`.
    #[error("the target has no custom.oncl")]
    NoEntry,
    /// `custom.oncl` has a `schema` this version does not read.
    #[error("custom.oncl schema {0} is not supported")]
    Schema(u64),
    /// `custom.oncl` is not of the expected shape.
    #[error("custom.oncl is malformed")]
    Malformed(#[source] Arc<serde_json::Error>),
    /// `id` or `version` differ from the path.
    #[error("id or version differ from the target path")]
    PathMismatch,
    /// `url` is not a plain `https://` URL of at most [`MAX_URL`] bytes: no user info,
    /// query or fragment.
    #[error("the package url is not a plain https:// url of at most 2048 bytes")]
    Url,
    /// `rollout` is over 100.
    #[error("rollout {0} is over 100")]
    Rollout(u8),
    /// No module, or more than [`PublisherRelease::MAX_MODULES`].
    #[error("{0} modules, not 1 to 32")]
    Modules(usize),
    /// A pre-release version on the `stable` channel.
    #[error("a pre-release on the stable channel")]
    StablePrerelease,
    /// `capabilities` are missing.
    #[error("capabilities are missing")]
    NoCapabilities,
    /// `capabilities` are not a [`DeclaredCapabilities`].
    #[error("invalid capabilities")]
    Capabilities(#[source] CapabilitiesError),
    /// `id` is not under the publisher's prefix.
    #[error("the id is outside the publisher's prefix")]
    IdOutsidePrefix,
    /// A module is not one the publisher was approved for.
    #[error("module {0} is not the publisher's")]
    ModuleNotAllowed(String),
    /// `replaces.symname` is not one the publisher was approved for.
    #[error("bundle {0} is not the publisher's")]
    BundleNotAllowed(String),
    /// The owner's index has a release of the same id: the owner's wins.
    #[error("the owner's index has the same id")]
    OwnerId,
    /// A release of the owner's index serves the module, and the publisher does not replace
    /// it: the owner's wins.
    #[error("the owner's index serves module {0}")]
    OwnerModule(String),
    /// A release of the owner's index stands for the bundle, and the publisher does not
    /// replace it: the owner's wins.
    #[error("the owner's index stands for bundle {0}")]
    OwnerBundle(String),
}

/// A publisher's target left out of the catalog, and why.
#[derive(Clone, Debug, thiserror::Error)]
#[error("publisher target {path} is left out")]
#[non_exhaustive]
pub struct EntryRejected {
    /// The target.
    pub path: TargetPath,
    /// Why.
    #[source]
    pub reason: EntryRejection,
}

/// A target path of a publisher's role: `plugins/<publisher>/<id>/<version>.onclp`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PublisherTarget {
    /// The publisher.
    pub publisher: PublisherName,
    /// The plugin.
    pub id: PluginId,
    /// Its version.
    pub version: Version,
}

impl PublisherTarget {
    /// `path` read as a publisher's target; `None` for any other form.
    pub fn parse(path: &TargetPath) -> Option<PublisherTarget> {
        let mut segments = path.as_str().split('/');
        let (Some("plugins"), Some(publisher), Some(id), Some(file), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return None;
        };
        Some(PublisherTarget {
            publisher: PublisherName::parse(publisher).ok()?,
            id: PluginId::parse(id).ok()?,
            version: Version::parse(file.strip_suffix(".onclp")?).ok()?,
        })
    }
}

/// `custom.oncl` as signed; members this version does not know are skipped.
#[derive(Deserialize)]
struct RawRelease {
    id: String,
    version: Version,
    url: String,
    channel: Channel,
    min_core: Version,
    modules: Vec<String>,
    #[serde(default)]
    replaces: Option<PluginReplaces>,
    name: PluginName,
    #[serde(default)]
    capabilities: Option<Value>,
    rollout: u8,
    #[serde(default)]
    revoked: bool,
}

/// A publisher's release as its role signs it: a [`PluginRelease`] with
/// [`PluginRelease::publisher`] and [`PluginRelease::capabilities`] set, and the channel it
/// is published to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublisherRelease {
    channel: Channel,
    release: PluginRelease,
}

impl PublisherRelease {
    /// The `custom.oncl` format version read.
    pub const SCHEMA: u64 = 1;
    /// The most modules one release serves.
    pub const MAX_MODULES: usize = 32;

    /// Reads the target `path` of `publisher`'s role: the path names the publisher, id and
    /// version; `custom.oncl` the rest; the target's length and sha256 are the package's.
    ///
    /// # Errors
    ///
    /// [`EntryRejection`] for a target that breaks a rule of its own.
    pub fn parse(
        publisher: &PublisherName,
        path: &TargetPath,
        target: &Target,
    ) -> Result<PublisherRelease, EntryRejection> {
        let place = PublisherTarget::parse(path)
            .filter(|place| place.publisher == *publisher)
            .ok_or(EntryRejection::Path)?;
        let entry = target
            .custom
            .as_ref()
            .and_then(|custom| custom.get("oncl"))
            .ok_or(EntryRejection::NoEntry)?;
        match entry.get("schema").and_then(Value::as_u64) {
            Some(PublisherRelease::SCHEMA) => {}
            Some(schema) => return Err(EntryRejection::Schema(schema)),
            None => {
                return Err(EntryRejection::Malformed(Arc::new(
                    <serde_json::Error as serde::de::Error>::missing_field("schema"),
                )));
            }
        }
        let raw =
            RawRelease::deserialize(entry).map_err(|e| EntryRejection::Malformed(Arc::new(e)))?;
        if raw.id != place.id.as_str() || raw.version != place.version {
            return Err(EntryRejection::PathMismatch);
        }
        if !plain_https_url(&raw.url) {
            return Err(EntryRejection::Url);
        }
        if raw.rollout > 100 {
            return Err(EntryRejection::Rollout(raw.rollout));
        }
        if !(1..=PublisherRelease::MAX_MODULES).contains(&raw.modules.len()) {
            return Err(EntryRejection::Modules(raw.modules.len()));
        }
        if raw.channel == Channel::Stable && !raw.version.pre.is_empty() {
            return Err(EntryRejection::StablePrerelease);
        }
        let capabilities =
            DeclaredCapabilities::try_from(raw.capabilities.ok_or(EntryRejection::NoCapabilities)?)
                .map_err(EntryRejection::Capabilities)?;
        Ok(PublisherRelease {
            channel: raw.channel,
            release: PluginRelease {
                id: raw.id,
                version: raw.version,
                package: Package {
                    url: raw.url,
                    sha256: Sha256(target.sha256.0),
                    size: target.length,
                },
                min_core: raw.min_core,
                modules: raw.modules,
                replaces: raw.replaces,
                name: raw.name,
                rollout: raw.rollout,
                revoked: raw.revoked,
                publisher: Some(publisher.clone()),
                capabilities: Some(capabilities),
            },
        })
    }

    /// The channel the publisher chose: `stable` is offered on both channels, `beta` only on
    /// `beta`.
    pub fn channel(&self) -> Channel {
        self.channel
    }

    /// Whether a client of `channel` is offered the release.
    pub fn offered_on(&self, channel: Channel) -> bool {
        match self.channel {
            Channel::Stable => true,
            Channel::Beta => channel == Channel::Beta,
        }
    }

    /// The release.
    pub fn release(&self) -> &PluginRelease {
        &self.release
    }

    /// The release, owned.
    pub fn into_release(self) -> PluginRelease {
        self.release
    }

    /// Marks the release revoked: the owner revoked its version.
    pub(crate) fn revoke(&mut self) {
        self.release.revoked = true;
    }
}
