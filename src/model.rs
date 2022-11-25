use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::fmt::Display;
use std::path::PathBuf;

// Error

#[derive(Debug)]
pub struct ParseError {
    pub msg: String,
}
impl std::error::Error for ParseError {}
impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to parse certificate: {}", self.msg)
    }
}

// Model

#[derive(Debug)]
pub enum Verb {
    Find {
        cn: String,
    },
    Replace {
        cn: String,
        cert: Cert,
        privkey: Option<PrivKey>,
    },
}

impl Display for Verb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return match self {
            Self::Find { cn } => write!(f, "Finding certificates and associated private keys with common name matching: {}", cn),
            Self::Replace {
                cn,
                cert: _,
                privkey,
            } => match privkey.is_some() {
                true => write!(f, "Replacing certificates and associated private keys with common name matching: {}", cn),
                false => write!(f, "Replacing certificates only with common name matching: {}", cn),
            },
        };
    }
}

impl Verb {
    /// Returns the target common name.
    pub fn cn(&self) -> &str {
        match self {
            Self::Find { cn } => cn,
            Self::Replace {
                cn,
                cert: _,
                privkey: _,
            } => cn,
        }
    }

    /// Returns whether to also consider private keys.
    pub fn privkeys(&self) -> bool {
        match self {
            Self::Find { cn: _ } => true,
            Self::Replace {
                cn: _,
                cert: _,
                privkey,
            } => privkey.is_some(),
        }
    }
}

// PKI Objects

/// Models an X509 certificate.
#[derive(Debug, Clone)]
pub struct Cert {
    pub cert: X509,
    pub common_name: String,
    pub locator: PEMLocator,
}

/// Models an X509 certificate private key.
#[derive(Debug, Clone)]
pub struct PrivKey {
    /// Private key.
    pub key: PKey<Private>,
    /// Path to file with key in.
    pub locator: PEMLocator,
}

#[derive(Debug)]
pub enum PKIObject {
    Cert(Cert),
    PrivKey(PrivKey),
}

// File objects

/// Models a single part of a PEM file.
#[derive(Debug)]
pub struct PEMPart<'a> {
    /// Data contained in the part.
    pub data: &'a [u8],
    /// Index of the start of the bytes in the file.
    pub start: usize,
}

/// Kinds of PEMParts that can exist.
#[derive(Debug, Clone)]
pub enum PEMKind {
    Cert,
    PrivKey,
}

/// Models the location of a PEMPart on disk.
#[derive(Debug, Clone)]
pub struct PEMLocator {
    /// Kind of data in this PEMPart.
    pub kind: PEMKind,
    /// Path to the file containing the bytes.
    pub path: PathBuf,
    /// Index of the start of the bytes in the file.
    pub start: usize,
    /// Index of the end of the bytes in the file.
    pub end: usize,
}
