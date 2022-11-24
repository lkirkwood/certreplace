use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::fmt::Display;
use std::path::PathBuf;

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

#[derive(Debug, Clone)]
/// Models an X509 certificate.
pub struct Cert {
    pub cert: X509,
    pub common_name: String,
    pub locator: PEMLocator,
}

#[derive(Debug, Clone)]
/// Models an X509 certificate private key.
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

#[derive(Debug, Clone)]
/// Models the location of a PEMPart on disk.
pub struct PEMLocator {
    /// Path to the file containing the bytes.
    pub path: PathBuf,
    /// Index of the start of the bytes in the file.
    pub start: usize,
    /// Index of the end of the bytes in the file.
    pub end: usize,
}

#[derive(Debug)]
/// Holds paths of all the objects to be replaced.
pub struct ReplacePaths {
    pub certs: Vec<PEMLocator>,
    pub keys: Vec<PEMLocator>,
}
