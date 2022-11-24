mod model;

use log::{error, warn};
use model::*;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::collections::VecDeque;
use std::fmt::Display;
use std::path::PathBuf;
use std::{
    fs,
    io::{self, Write},
    str,
};
use structopt::StructOpt;

#[derive(StructOpt)]
pub struct Cli {
    /// Path to search in.
    pub path: String,
    /// Common name to match in target certificates.
    #[structopt(short = "cn")]
    pub common_name: Option<String>,
    /// Path to public key to use as replacement.
    #[structopt(long = "cert")]
    pub certificate: Option<String>,
    /// Path to private key to use as replacement.
    #[structopt(long = "priv")]
    pub private_key: Option<String>,
}

fn main() {
    let args = Cli::from_args();

    let verb = match &args.certificate {
        Some(cert_path) => {
            let cert = choose_cert(cert_path, args.common_name.as_ref()).unwrap();
            let privkey = match &args.private_key {
                None => None,
                Some(privkey_path) => Some(choose_privkey(privkey_path, &cert).unwrap()),
            };
            Verb::Replace {
                cn: cert.common_name.clone(),
                cert,
                privkey,
            }
        }
        None => match args.common_name {
            None => panic!("No certificate or common name provided."),
            Some(cn) => Verb::Find { cn },
        },
    };

    if get_user_consent(&verb) {
        let paths = find_certs(PathBuf::from(args.path), verb.cn(), verb.privkeys());
        match verb {
            Verb::Find { cn: _ } => print_paths(paths),
            Verb::Replace {
                cn: _,
                cert,
                privkey,
            } => replace_paths(paths, cert, privkey),
        }
    } else {
        panic!(
            "User declined to replace objects for common name: {}",
            verb.cn()
        );
    }
}

/// Parses a private key from a file.
fn parse_privkey(content: &[u8]) -> Option<PKey<Private>> {
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
fn parse_cert(content: &[u8]) -> Option<X509> {
    return if let Ok(cert) = X509::from_pem(&content) {
        Some(cert)
    } else if let Ok(cert) = X509::from_der(&content) {
        Some(cert)
    } else {
        None
    };
}

/// Gets the common name from a certificate if possible.
fn get_cn(cert: &X509) -> Option<String> {
    if let Some(data) = cert.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
        if let Ok(string) = data.data().as_utf8() {
            return Some(string.to_string());
        }
    }
    return None;
}

/// Chooses a certificate matching a common name from some pki objs,
/// or returns an error if there is no unique match.
fn choose_cert(path: &str, cn: Option<&String>) -> Result<Cert, ParseError> {
    let path = PathBuf::from(path);
    let pkis = parse_pkiobjs(PathBuf::from(path)).unwrap();

    if cn.is_none() {
        let mut certs = Vec::new();
        for pki in pkis {
            if let PKIObject::Cert(cert) = pki {
                certs.push(cert);
            }
        }
        if certs.len() == 1 {
            return Ok(certs.pop().unwrap());
        } else {
            return Err(ParseError {
                msg: "Certificate file does not contain exactly one certificate, so a common name must be provided.".to_string() 
            });
        }
    } else {
        let cn = cn.unwrap();

        let mut certs = Vec::new();
        for pki in pkis {
            match pki {
                PKIObject::Cert(cert) => {
                    if &cert.common_name == cn {
                        certs.push(cert);
                    }
                }
                PKIObject::PrivKey(_) => {}
            }
        }
        if certs.len() == 1 {
            return Ok(certs.pop().unwrap());
        } else {
            return Err(ParseError {
                msg: format!("Certificate file does not contain exactly one certificate with common name: {}", cn)
            });
        }
    }
}

/// Chooses a private key matching a cert from some pki objs,
/// or returns an error if there is no unique match.
fn choose_privkey(path: &str, cert: &Cert) -> Result<PrivKey, ParseError> {
    if let Ok(pubkey) = cert.cert.public_key() {
        let path = PathBuf::from(path);
        let pkis = parse_pkiobjs(PathBuf::from(path)).unwrap();
        let mut privkeys = Vec::new();

        for pki in pkis {
            match pki {
                PKIObject::PrivKey(pkey) => {
                    if pkey.key.public_eq(&pubkey) {
                        privkeys.push(pkey);
                    }
                }
                PKIObject::Cert(_) => {}
            }
        }
        if privkeys.len() == 1 {
            return Ok(privkeys.pop().unwrap());
        } else {
            return Err(ParseError {
                msg: format!(
                "Provided file does not contain exactly one private key match cert with common name: {}",
                cert.common_name
            ),
            });
        }
    } else {
        return Err(ParseError {
            msg: format!(
                "Failed to get public key from provided certificate, cn: {}",
                cert.common_name
            ),
        });
    }
}

/// Returns true if user confirms operation.
fn get_user_consent(verb: &Verb) -> bool {
    print!("{}; Okay? (y/n): ", verb);
    io::stdout()
        .flush()
        .expect("Failed to flush stdout when printing confirmation message.");

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read user confirmation for target common name.");
    return input.to_lowercase().starts_with("y");
}

/// Finds certificates in the path that match the cn, and returns them.
/// Finds their matching privkeys if the parameter is true.
fn find_certs(path: PathBuf, cn: &str, privkeys: bool) -> ReplacePaths {
    let mut certs = Vec::new();
    let mut keys = Vec::new();
    for path in find_pkiobj_files(path) {
        match parse_pkiobjs(path) {
            Err(err) => error!("{:?}", err),
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

    let mut matched_certs = Vec::new();
    let mut matched_keys = Vec::new();
    for cert in certs {
        if cert.common_name == cn {
            if privkeys {
                match match_privkeys(&cert.cert, keys) {
                    Ok((matched, unmatched)) => {
                        matched_keys.extend(matched);
                        keys = unmatched;
                    }
                    Err((err, unmatched)) => {
                        error!("Error on cert at {:?}: {:?}", cert.locator, err);
                        keys = unmatched;
                    }
                }
            }
            matched_certs.push(cert.locator);
        }
    }

    return ReplacePaths {
        certs: matched_certs,
        keys: matched_keys.into_iter().map(|k| k.locator).collect(),
    };
}

fn find_pkiobj_files(path: PathBuf) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    match fs::read_dir(&path) {
        Err(err) => error!("Failed while reading directory in {:?}: {:?}", path, err),
        Ok(entries) => {
            for entry in entries {
                if let Err(err) = entry {
                    error!("Failed while reading directory in {:?}: {:?}", path, err);
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

#[derive(Debug)]
struct ParseError {
    msg: String,
}
impl std::error::Error for ParseError {}
impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to parse certificate: {}", self.msg)
    }
}

/// Parses X509 certs and privkeys from a PEM encoded file.
fn parse_pkiobjs(path: PathBuf) -> Result<Vec<PKIObject>, ParseError> {
    let mut pkiobjs = Vec::new();
    match fs::read(&path) {
        Ok(content) => {
            for part in get_pem_parts(&content)? {
                if let Some(privkey) = parse_privkey(part.data) {
                    pkiobjs.push(PKIObject::PrivKey(PrivKey {
                        key: privkey,
                        locator: PEMLocator {
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
                                path: path.clone(),
                                start: part.start,
                                end: part.start + part.data.len(),
                            },
                        }));
                    }
                } else {
                    warn!("Failed to parse PKI object from PEM part: {:?}", part);
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
fn get_pem_parts<'a>(data: &'a [u8]) -> Result<Vec<PEMPart<'a>>, ParseError> {
    let string = match str::from_utf8(data) {
        Ok(_string) => _string,
        Err(err) => {
            return Err(ParseError {
                msg: format!("Failed to decode file data as utf-8: {:?}", err),
            })
        }
    };
    let mut parts = Vec::new();

    let mut in_boundary = false;
    let mut in_part = false;
    let mut in_end = false;
    let mut start = 0;

    let mut index = 0;
    let mut part_buf = Vec::new();
    let mut buf = VecDeque::new();
    for char in string.chars() {
        index += 1;
        buf.push_back(char);
        if buf.len() > 5 {
            buf.pop_front();
        }

        if in_part | in_boundary {
            part_buf.push(char);
        }

        if buf == PEM_BOUNDARY {
            in_boundary ^= true;
            if in_end {
                in_end = false;
                parts.push(PEMPart {
                    data: &data[start..index + 1],
                    start,
                })
            }
        } else if in_boundary & (buf == PEM_BEGIN) {
            in_part = true;
            start = index - 10;
        } else if in_boundary & (buf == PEM_END) {
            in_part = false;
            in_end = true;
        }
    }
    return Ok(parts);
}

/// Splits the keys into those that match the certificate (left) and those that dont (right).
/// Upon error all keys are returned with the error.
fn match_privkeys(
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

// fn replace_cert(path: &str, content: &str) {
//     let backup_path = format!("{}.bkp", &path);
//     let backup_result = fs::copy(path, &backup_path); // TODO add date
//     if backup_result.is_ok() {
//         let write_result = fs::write(&path, &content);
//         if write_result.is_err() {
//             warn!("Failed to write to certificate at {}", path);
//         }
//     } else {
//         warn!(
//             "Failed to backup certificate at {} to {}",
//             path, backup_path
//         );
//     }
// }

/// Prints the paths.
fn print_paths(paths: ReplacePaths) {
    println!("Matching certificates:");
    for cert in paths.certs {
        println!("\t{:#?}", cert);
    }
    println!("Matching private keys:");
    for key in paths.keys {
        println!("\t{:#?}", key);
    }
}

/// Replaces the paths with the new data.
fn replace_paths(paths: ReplacePaths, cert: Cert, privkey: Option<PrivKey>) {
    todo!("Implement replacing.")
}
