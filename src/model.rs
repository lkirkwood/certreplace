use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use regex::Regex;
use std::fmt::Display;
use std::path::PathBuf;

#[derive(Debug)]
pub enum CommonName {
    Literal(String),
    Pattern(Regex),
}

impl Display for CommonName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Literal(string) => write!(f, "{string}"),
            Self::Pattern(pattern) => write!(f, "{pattern}"),
        }
    }
}

impl CommonName {
    pub fn matches(&self, cn: &str) -> bool {
        match self {
            Self::Literal(string) => string == cn,
            Self::Pattern(pattern) => pattern.is_match(cn),
        }
    }
}

/// The action for the app to perform.
#[derive(Debug)]
pub enum Verb {
    /// Find certificates and their matching private keys.
    Find { name: CommonName },
    /// Replace certificates, and optionally their private keys.
    Replace {
        name: CommonName,
        cert: Cert,
        privkey: Option<PrivKey>,
    },
}

impl Display for Verb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Find { name: cn } => {
                write!(f, "Finding certificates and associated private keys with common name matching: {cn}")
            }
            Self::Replace {
                name: cn,
                cert: _,
                privkey,
            } => {
                if privkey.is_some() {
                    write!(f, "Replacing certificates and associated private keys with common name matching: {cn}")
                } else {
                    write!(
                        f,
                        "Replacing certificates only with common name matching: {cn}"
                    )
                }
            }
        }
    }
}

impl Verb {
    /// Returns the target common name.
    pub fn name(&self) -> &CommonName {
        match self {
            Self::Find { name } | Self::Replace { name, .. } => name,
        }
    }

    /// Returns whether to also consider private keys.
    pub fn privkeys(&self) -> bool {
        match self {
            Self::Find { .. } => true,
            Self::Replace {
                name: _,
                cert: _,
                privkey,
            } => privkey.is_some(),
        }
    }
}

// PKI Objects

/// An X509 certificate.
#[derive(Debug, Clone)]
pub struct Cert {
    pub content: X509,
    pub common_name: String,
    pub locator: PEMLocator,
}

/// An X509 certificate private key.
#[derive(Debug, Clone)]
pub struct PrivKey {
    /// Private key.
    pub key: PKey<Private>,
    /// Path to file with key in.
    pub locator: PEMLocator,
}

/// A X509 certificate or private key.
#[derive(Debug)]
pub enum PKIObject {
    Cert(Cert),
    PrivKey(PrivKey),
}

// File objects

/// A single part of a PEM file.
#[derive(Debug, PartialEq, Eq)]
pub struct PEMPart<'a> {
    pub label: String,
    /// Data contained in the part.
    pub data: &'a [u8],
    /// Index of the start of the bytes in the file.
    pub start: usize,
}

/// Kinds of `PEMParts` that can exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PEMKind {
    Cert,
    PrivKey,
}

/// Describes the location of a `PEMPart` on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PEMLocator {
    /// Kind of data in this `PEMPart`.
    pub kind: PEMKind,
    /// Path to the file containing the bytes.
    pub path: PathBuf,
    /// Index of the start of the bytes in the file.
    pub start: usize,
    /// Index of the end of the bytes in the file.
    pub end: usize,
}
