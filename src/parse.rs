use crate::model::*;
use anyhow::Result;
use jwalk::WalkDir;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use paris::error;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::{fs, str};

// Finding

/// Finds certificates in the path that match the cn, and returns them.
/// Finds their matching privkeys if the parameter is true.
pub fn find_certs(path: PathBuf, cn: &CommonName, privkeys: bool) -> Vec<PEMLocator> {
    let mut certs = Vec::new();
    let mut keys = Vec::new();
    for path in find_pkiobj_files(path) {
        match parse_pkiobjs(path) {
            Err(err) => error!("{:?}", err),
            Ok(pkiobjs) => {
                for pkiobj in pkiobjs {
                    match pkiobj {
                        PKIObject::Cert(cert) => {
                            if cn.matches(&cert.common_name) {
                                certs.push(cert);
                            }
                        }
                        PKIObject::PrivKey(pkey) => keys.push(pkey),
                    }
                }
            }
        }
    }

    let mut pems = Vec::new();
    for cert in certs {
        if cn.matches(&cert.common_name) {
            if privkeys {
                if let Ok(pubkey) = cert.cert.public_key() {
                    // TODO use extract_if once stabilised
                    // https://github.com/rust-lang/rust/issues/43244
                    let mut _keys = vec![];
                    for key in keys {
                        if key.key.public_eq(&pubkey) {
                            pems.push(key.locator);
                        } else {
                            _keys.push(key);
                        }
                    }
                    keys = _keys;
                } else {
                    error!("Failed to read public key from X509: {cert:?}");
                }
            }
            pems.push(cert.locator);
        }
    }

    pems
}

/// Finds files with pem/crt/key/cer/der extensions in the provided path.
pub fn find_pkiobj_files(path: PathBuf) -> Vec<PathBuf> {
    let mut paths = vec![];
    for file in WalkDir::new(path).into_iter().flatten() {
        if let Some(name) = file.file_name.to_str() {
            if let Some((_, "pem" | "crt" | "key" | "cer" | "der")) = name.rsplit_once('.') {
                paths.push(file.path());
            }
        }
    }
    paths
}

// Parsing

/// Parses a private key from some bytes.
pub fn parse_privkey(content: &[u8]) -> Option<PKey<Private>> {
    if let Ok(pkey) = PKey::private_key_from_pem_passphrase(content, &[]) {
        Some(pkey)
    } else if let Ok(pkey) = PKey::private_key_from_der(content) {
        return Some(pkey);
    } else if let Ok(pkey) = PKey::private_key_from_pkcs8(content) {
        return Some(pkey);
    } else {
        return None;
    }
}

/// Parses a certificate from some bytes.
pub fn parse_cert(content: &[u8]) -> Option<X509> {
    if let Ok(cert) = X509::from_pem(content) {
        Some(cert)
    } else if let Ok(cert) = X509::from_der(content) {
        Some(cert)
    } else {
        None
    }
}

/// PEM labels for objects we dont care about.
const IGNORED_LABELS: [&str; 3] = ["TRUSTED CERTIFICATE", "X509 CRL", "PUBLIC KEY"];

/// Parses X509 certs and privkeys from a PEM encoded file.
pub fn parse_pkiobjs(path: PathBuf) -> Result<Vec<PKIObject>> {
    let mut pkiobjs = Vec::new();
    if let Ok(content) = fs::read(&path) {
        for part in get_pem_parts(&content)? {
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
                            cert,
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
    };

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
pub fn get_pem_parts(data: &[u8]) -> Result<Vec<PEMPart<'_>>> {
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
    Ok(parts)
}

// Utils

/// Gets the common name from a certificate if possible.
pub fn get_cn(cert: &X509) -> Option<String> {
    if let Some(data) = cert.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
        if let Ok(string) = data.data().as_utf8() {
            return Some(string.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, path::PathBuf};

    use regex::Regex;

    use crate::model::{CommonName, PEMKind, PEMLocator};

    use super::{find_certs, find_pkiobj_files};

    fn found_certs() -> Vec<PEMLocator> {
        vec![
            PEMLocator {
                start: 0,
                end: 3322,
                kind: PEMKind::PrivKey,
                path: PathBuf::from("test/search/bob.key"),
            },
            PEMLocator {
                start: 16857,
                end: 18901,
                kind: PEMKind::Cert,
                path: PathBuf::from("test/search/alice.pem"),
            },
        ]
    }

    #[test]
    fn test_find_certs() {
        let found = find_certs(
            PathBuf::from("test/search/"),
            &CommonName::Literal("localhost".to_string()),
            true,
        );
        assert_eq!(found_certs(), found);
    }

    #[test]
    fn test_find_regex_certs() {
        let found = find_certs(
            PathBuf::from("test/search/"),
            &CommonName::Pattern(Regex::new("local.*").unwrap()),
            true,
        );
        assert_eq!(found_certs(), found)
    }

    fn found_pkiobj_files() -> HashSet<PathBuf> {
        HashSet::from([
            PathBuf::from("test/search/bob.key"),
            PathBuf::from("test/search/alice.pem"),
        ])
    }

    #[test]
    fn test_find_pkiobj_files() {
        let found = HashSet::from_iter(find_pkiobj_files(PathBuf::from("test/search")));
        assert_eq!(found_pkiobj_files(), found);
    }
}
