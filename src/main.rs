mod model;

use log::error;
use model::*;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::fmt::Display;
use std::path::PathBuf;
use std::{
    fs,
    io::{self, Write},
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
            let mut x509s = parse_cert(
                &fs::read(&cert_path).expect("Failed to read provided private key file."),
            );
            let x509 = match x509s.len() {
                1 => x509s.pop().unwrap(),
                other => panic!("Wrong number of certs found in provided file: {}", other),
            };
            let cn = match get_cn(&x509) {
                None => match args.common_name {
            None => panic!("No common name provided and failed to parse one from the provided certificate.."),
                    Some(cn) => cn,
                }
                Some(cn) => cn
            };
            let cert = Cert {
                cert: x509,
                common_name: cn.clone(),
                path: PathBuf::from(cert_path),
            };

            let privkey = match args.private_key {
                None => None,
                Some(privkey_path) => {
                    let content =
                        fs::read(&privkey_path).expect("Failed to read provided private key file.");
                    Some(PrivKey {
                        key: parse_privkey(&content).unwrap(),
                        path: PathBuf::from(privkey_path),
                    })
                }
            };
            Verb::Replace { cn, cert, privkey }
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
fn parse_cert(content: &[u8]) -> Vec<X509> {
    return if let Ok(cert) = X509::from_pem(&content) {
        vec![cert]
    } else if let Ok(cert) = X509::from_der(&content) {
        vec![cert]
    } else if let Ok(certs) = X509::stack_from_pem(&content) {
        certs
    } else {
        vec![]
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
    for path in find_pkiobjs(path, privkeys) {
        match parse_pkiobjs(path) {
            Err(err) => error!("{err}"),
            Ok(pkiobjs) => {
                for pkiobj in pkiobjs {
                    match pkiobj {
                        PKIObject::Cert(cert) => {
                            if cert.common_name == cn {
                                println!("{:?}", cert.cert.not_after());
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
                match find_privkeys(&cert.cert, keys) {
                    Ok((matched, unmatched)) => {
                        matched_keys.extend(matched);
                        keys = unmatched;
                    }
                    Err((err, unmatched)) => {
                        error!("Error on cert at {:?}: {:?}", cert.path, err);
                        keys = unmatched;
                    }
                }
            }
            matched_certs.push(cert.path);
        }
    }

    return ReplacePaths {
        certs: matched_certs,
        keys: matched_keys.into_iter().map(|k| k.path).collect(),
    };
}

fn find_pkiobjs(path: PathBuf, privkeys: bool) -> Vec<PathBuf> {
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
                            paths.extend(find_pkiobjs(entry.path(), privkeys));
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
            if let Some(key) = parse_privkey(&content) {
                pkiobjs.push(PKIObject::PrivKey(PrivKey { key, path }));
            } else {
                for cert in parse_cert(&content) {
                    if let Some(common_name) = get_cn(&cert) {
                        pkiobjs.push(PKIObject::Cert(Cert {
                            cert,
                            common_name,
                            path: path.clone(),
                        }))
                    }
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

/// Splits the keys into those that match the certificate (left) and those that dont (right).
/// Upon error all keys are returned with the error.
fn find_privkeys(
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
    println!("Matching certificates:");
    for key in paths.keys {
        println!("\t{:#?}", key);
    }
}

/// Replaces the paths with the new data.
fn replace_paths(paths: ReplacePaths, cert: Cert, privkey: Option<PrivKey>) {
    todo!("Implement replacing.")
}
