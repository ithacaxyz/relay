//! Relay version.

/// The short version information for relay.
pub const RELAY_SHORT_VERSION: &str = env!("RELAY_SHORT_VERSION");

/// The long version information for relay.
pub const RELAY_LONG_VERSION: &str = concat!(
    env!("RELAY_LONG_VERSION_0"),
    "\n",
    env!("RELAY_LONG_VERSION_1"),
    "\n",
    env!("RELAY_LONG_VERSION_2"),
    "\n",
    env!("RELAY_LONG_VERSION_3"),
    "\n",
    env!("RELAY_LONG_VERSION_4")
);
