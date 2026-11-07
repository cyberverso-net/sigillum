//! Times supplied by the caller (ADR-0026, decision 3).
//!
//! The library never reads a clock. The caller passes the signing time and
//! the validation time in the [`Context`](crate::Context): the current time
//! in normal use, fixed times in tests and in the corpus.

use crate::error::{Error, ErrorKind};

/// Represents a signing time or a validation time that the caller
/// supplies, in whole seconds since 1970-01-01T00:00:00Z.
///
/// It is not meant for the validity of certificates, whose `UTCTime` also
/// covers 1950 to 1969 (RFC 5280, section 4.1.2.5.1).
///
/// The count follows POSIX time, which does not count leap seconds.
/// Whole seconds are enough for the times sigillum writes. The
/// `signing-time` attribute of CAdES is a `UTCTime` or `GeneralizedTime`
/// that includes seconds (RFC 5652, section 11.3). The `iat` header
/// parameter of JAdES "shall not contain fractions of seconds" (ETSI TS
/// 119 182-1 V1.2.1, clause 5.1.11).
///
/// The range ends at 9999-12-31T23:59:59Z, the last second that a
/// `GeneralizedTime` with a four-digit year can state, written
/// `99991231235959Z` in RFC 5280, section 4.1.2.5. Times before 1970 are
/// not representable; no signing or validation time of sigillum needs
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime {
    seconds: u64,
}

impl UnixTime {
    /// The largest number of seconds accepted, that of
    /// 9999-12-31T23:59:59Z.
    pub const MAX_SECONDS: u64 = 253_402_300_799;

    /// Creates the time `seconds` after 1970-01-01T00:00:00Z.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] if `seconds` is above
    /// [`MAX_SECONDS`](Self::MAX_SECONDS).
    pub const fn from_seconds(seconds: u64) -> Result<Self, Error> {
        if seconds > Self::MAX_SECONDS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "the time is after 9999-12-31T23:59:59Z",
            ));
        }
        Ok(Self { seconds })
    }

    /// Returns the number of seconds since 1970-01-01T00:00:00Z.
    #[must_use]
    pub const fn seconds(self) -> u64 {
        self.seconds
    }
}
