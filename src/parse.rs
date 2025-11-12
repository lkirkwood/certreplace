use crate::model::{Cert, PEMKind, PEMLocator, PEMPart, PKIObject, PrivKey};
use anyhow::Result;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::{fs, str};

/// Parses a private key from some bytes.
pub fn parse_privkey(content: &[u8]) -> Option<PKey<Private>> {
    if let Ok(pkey) = PKey::private_key_from_pem_passphrase(content, &[]) {
        Some(pkey)
    } else if let Ok(pkey) = PKey::private_key_from_der(content) {
        Some(pkey)
    } else {
        PKey::private_key_from_pkcs8(content).ok()
    }
}

/// Parses a certificate from some bytes.
pub fn parse_cert(content: &[u8]) -> Option<X509> {
    if let Ok(cert) = X509::from_pem(content) {
        Some(cert)
    } else {
        X509::from_der(content).ok()
    }
}

/// PEM labels for objects we dont care about.
const IGNORED_LABELS: [&str; 3] = ["TRUSTED CERTIFICATE", "X509 CRL", "PUBLIC KEY"];

/// Parses X509 certs and privkeys from a PEM encoded file.
pub fn parse_pkiobjs(path: &PathBuf) -> Result<Vec<PKIObject>> {
    let mut pkiobjs = Vec::new();
    let content = fs::read(path)?;
    for part in get_pem_parts(&content) {
        if !IGNORED_LABELS.contains(&part.label.as_ref()) {
            if let Some(privkey) = parse_privkey(part.data) {
                pkiobjs.push(PKIObject::PrivKey(PrivKey {
                    key: privkey,
                    locator: PEMLocator {
                        kind: PEMKind::PrivKey,
                        path: path.clone(),
                        start: part.start,
                        end: part.start + part.data.len(),
                    },
                }));
            } else if let Some(cert) = parse_cert(part.data) {
                if let Some(common_name) = get_cn(&cert) {
                    pkiobjs.push(PKIObject::Cert(Cert {
                        content: cert,
                        common_name,
                        locator: PEMLocator {
                            kind: PEMKind::Cert,
                            path: path.clone(),
                            start: part.start,
                            end: part.start + part.data.len(),
                        },
                    }));
                }
            }
        }
    }

    Ok(pkiobjs)
}

/// The chars at the beginning or end of a PEM boundary.
const PEM_BOUNDARY: [char; 5] = ['-', '-', '-', '-', '-'];
/// The chars at the beginning of a PEM start label.
const PEM_BEGIN: [char; 5] = ['B', 'E', 'G', 'I', 'N'];
/// The chars at the beginning of a PEM end label.
const PEM_END: [char; 5] = ['-', 'E', 'N', 'D', ' '];
/// Some chars to strip off a PEM label.
const LABEL_TRIM: [char; 2] = ['-', ' '];

/// Parses the data into PEM parts.
pub fn get_pem_parts(data: &[u8]) -> Vec<PEMPart<'_>> {
    let mut parts = Vec::new();

    let mut in_boundary = false;
    let mut in_label = false;
    let mut in_end = false;

    let mut start = 0;
    let mut label = String::new();

    let mut index = 0;
    let mut buf = VecDeque::new();
    for byte in data {
        let char = char::from(byte.to_owned());
        index += 1;
        buf.push_back(char);
        if buf.len() > 5 {
            buf.pop_front();
        }

        if buf == PEM_BOUNDARY {
            in_boundary ^= true;
            in_label = false;

            if in_end {
                in_end = false;
                parts.push(PEMPart {
                    label: label.trim_matches(&LABEL_TRIM as &[_]).to_string(),
                    data: &data[start..index],
                    start,
                });
                label = String::new();
            }
        } else if in_boundary & (buf == PEM_BEGIN) {
            start = index - 10;
            in_label = true;
        } else if in_boundary & (buf == PEM_END) {
            in_end = true;
        } else if in_label {
            label.push(char);
        }
    }

    parts
}

/// Gets the common name from an OpenSSL certificate if possible.
pub fn get_cn(cert: &X509) -> Option<String> {
    if let Some(data) = cert.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
        if let Ok(string) = data.data().as_utf8() {
            return Some(string.to_string());
        }
    }
    None
}
