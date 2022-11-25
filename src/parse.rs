use crate::model::*;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::{fs, str};

// Finding

/// Finds certificates in the path that match the cn, and returns them.
/// Finds their matching privkeys if the parameter is true.
pub fn find_certs(path: PathBuf, cn: &str, privkeys: bool) -> Vec<PEMLocator> {
    let mut certs = Vec::new();
    let mut keys = Vec::new();
    for path in find_pkiobj_files(path) {
        match parse_pkiobjs(path) {
            Err(err) => println!("{:?}", err),
            Ok(pkiobjs) => {
                for pkiobj in pkiobjs {
                    match pkiobj {
                        PKIObject::Cert(cert) => {
                            if cert.common_name == cn {
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
        if cert.common_name == cn {
            if privkeys {
                match match_privkeys(&cert.cert, keys) {
                    Ok((matched, unmatched)) => {
                        pems.extend(matched.into_iter().map(|k| k.locator));
                        keys = unmatched;
                    }
                    Err((err, unmatched)) => {
                        println!("Error on cert at {:?}: {:?}", cert.locator, err);
                        keys = unmatched;
                    }
                }
            }
            pems.push(cert.locator);
        }
    }

    return pems;
}

pub fn find_pkiobj_files(path: PathBuf) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    match fs::read_dir(&path) {
        Err(err) => println!("Failed while reading directory in {:?}: {:?}", path, err),
        Ok(entries) => {
            for entry in entries {
                if let Err(err) = entry {
                    println!("Failed while reading directory in {:?}: {:?}", path, err);
                    continue;
                } else {
                    let entry = entry.unwrap();
                    if let Ok(ftype) = entry.file_type() {
                        if ftype.is_dir() {
                            // Recurse
                            paths.extend(find_pkiobj_files(entry.path()));
                        } else {
                            if let Some((_, ext)) =
                                entry.file_name().to_string_lossy().rsplit_once('.')
                            {
                                match ext {
                                    "pem" | "crt" | "cer" | "der" | "key" => {
                                        paths.push(entry.path())
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return paths;
}

// Parsing

/// Parses a private key from a file.
pub fn parse_privkey(content: &[u8]) -> Option<PKey<Private>> {
    if let Ok(pkey) = PKey::private_key_from_pem(&content) {
        return Some(pkey);
    } else if let Ok(pkey) = PKey::private_key_from_der(&content) {
        return Some(pkey);
    } else if let Ok(pkey) = PKey::private_key_from_pkcs8(&content) {
        return Some(pkey);
    } else {
        return None;
    };
}

/// Parses a certificate from some bytes.
pub fn parse_cert(content: &[u8]) -> Option<X509> {
    return if let Ok(cert) = X509::from_pem(&content) {
        Some(cert)
    } else if let Ok(cert) = X509::from_der(&content) {
        Some(cert)
    } else {
        None
    };
}

/// Parses X509 certs and privkeys from a PEM encoded file.
pub fn parse_pkiobjs(path: PathBuf) -> Result<Vec<PKIObject>, ParseError> {
    let mut pkiobjs = Vec::new();
    match fs::read(&path) {
        Ok(content) => {
            for part in get_pem_parts(&content)? {
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
                } else {
                    println!("Failed to parse PKI object from PEM part at: {:?}", path);
                }
            }
        }
        Err(err) => {
            return Err(ParseError {
                msg: format!(
                    "Failed to read contents of potential cert at {:?}: {:?}",
                    path, err
                ),
            })
        }
    };
    return Ok(pkiobjs);
}

const PEM_BOUNDARY: [char; 5] = ['-', '-', '-', '-', '-'];
const PEM_BEGIN: [char; 5] = ['B', 'E', 'G', 'I', 'N'];
const PEM_END: [char; 5] = ['-', 'E', 'N', 'D', ' '];

/// Parses the data into PEM parts.
pub fn get_pem_parts<'a>(data: &'a [u8]) -> Result<Vec<PEMPart<'a>>, ParseError> {
    let mut parts = Vec::new();

    let mut in_boundary = false;
    let mut in_end = false;
    let mut start = 0;

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
            if in_end {
                in_end = false;
                parts.push(PEMPart {
                    data: &data[start..index],
                    start,
                })
            }
        } else if in_boundary & (buf == PEM_BEGIN) {
            start = index - 10;
        } else if in_boundary & (buf == PEM_END) {
            in_end = true;
        }
    }
    return Ok(parts);
}

// Utils

/// Splits the keys into those that match the certificate (left) and those that dont (right).
/// Upon error all keys are returned with the error.
pub fn match_privkeys(
    cert: &X509,
    keys: Vec<PrivKey>,
) -> Result<(Vec<PrivKey>, Vec<PrivKey>), (ParseError, Vec<PrivKey>)> {
    if let Ok(pubkey) = cert.public_key() {
        return Ok(keys.into_iter().partition(|key| key.key.public_eq(&pubkey)));
    } else {
        return Err((
            ParseError {
                msg: format!("Failed to read public key from X509: {:?}", cert),
            },
            keys,
        ));
    }
}

/// Gets the common name from a certificate if possible.
pub fn get_cn(cert: &X509) -> Option<String> {
    if let Some(data) = cert.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
        if let Ok(string) = data.data().as_utf8() {
            return Some(string.to_string());
        }
    }
    return None;
}
