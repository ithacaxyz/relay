/// Indicates which transactions from a interop bundle should be queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InteropTxType {
    /// Source chain transactions
    Source,
    /// Destination chain transactions
    Destination,
}

impl InteropTxType {
    /// Returns true if this is the Source variant.
    pub fn is_source(&self) -> bool {
        matches!(self, Self::Source)
    }

    /// Returns true if this is the Destination variant.
    pub fn is_destination(&self) -> bool {
        matches!(self, Self::Destination)
    }
}
