//! A Welcome transfer over a slow gossip inbox.
//!
//! On a metered phone the gossip inbox is tens of seconds to minutes one
//! way, longer than a joiner's bounded fetch attempt. So a joiner keeps a
//! Welcome receive that it asked for over gossip across its attempts, and
//! the frames of an earlier request still count when they arrive later.

use std::time::Duration;

/// The lifetime of a gossip-carried Welcome frame, in either direction.
pub(super) const WELCOME_GOSSIP_LIFETIME: Duration = Duration::from_secs(300);

/// While a gossip-carried request is younger than this, a joiner does not
/// ask again, and an owner does not stream the Welcome again.
pub(super) const WELCOME_GOSSIP_REFRESH: Duration = Duration::from_secs(150);

/// How long a joiner keeps a gossip-carried receive across attempts.
pub(super) const RETAINED_WELCOME_TTL: Duration = Duration::from_secs(600);

/// The most retained receives (and completed Welcomes) a joiner holds.
pub(super) const MAX_RETAINED_WELCOMES: usize = 8;

/// The most bytes retained receives and completed Welcomes hold together.
pub(super) const MAX_RETAINED_WELCOME_BYTES: u64 = 8 * 1024 * 1024;
