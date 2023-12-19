use thiserror::Error;

#[derive(Clone, Error, Debug, PartialEq)]
pub enum Error {
    /// Base64 Decode
    #[error("Base64 decode: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// HKDF Length
    #[error("Invalid Length for HKDF: {0}")]
    HkdfLength(usize),

    /// HMAC Length
    #[error("Invalid Length for HMAC: {0}")]
    HmacLength(#[from] chacha20::cipher::InvalidLength),

    /// Invalid MAC
    #[error("Invalid MAC")]
    InvalidMac,

    /// Invalid padding
    #[error("Invalid Padding")]
    InvalidPadding,

    /// Message is empty
    #[error("Message is empty")]
    MessageIsEmpty,

    /// Message is too long (max len 65536 - 128)
    #[error("Message is too long")]
    MessageIsTooLong,

    /// Unsupported future version
    #[error("Encryption format is not yet supported")]
    UnsupportedFutureVersion,

    /// Unknown version
    #[error("Encryption format is unknown")]
    UnknownVersion,

    // UTF8 Decode
    #[error("UTF8 Decode: {0}")]
    Utf8Decode(#[from] std::string::FromUtf8Error),
}
