use log::{error, warn};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::fmt::Display;
use std::path::PathBuf;
use std::{fs, io};
use structopt::StructOpt;

#[derive(StructOpt)]
struct Cli {
    /// Path to search in.
    path: String,
    /// Common name to match in target certificates.
    #[structopt(short = "cn")]
    common_name: Option<String>,
    /// Path to public key to use as replacement.
    #[structopt(long = "cert")]
    certificate: String,
    /// Path to private key to use as replacement.
    #[structopt(long = "priv")]
    private_key: Option<String>,
}

#[derive(Debug, Clone)]
/// Models an X509 certificate.
struct Cert {
    cert: X509,
    common_name: String,
    path: PathBuf,
}

#[derive(Debug, Clone)]
/// Models an X509 certificate private key.
struct PrivKey {
    key: PKey<Private>,
    path: PathBuf,
}

#[derive(Debug)]
/// A X509 cert and its corresponding private key.
struct CertBundle {
    cert: Cert,
    privkey: Option<PrivKey>,
}

#[derive(Debug)]
enum PKIObject {
    Cert(Cert),
    PrivKey(PrivKey),
}

fn main() {
    let args = Cli::from_args();
    let new_cert_path = args.certificate;
    let new_privkey_path = args.private_key;

    let new_cert = match fs::read(&new_cert_path) {
        Err(err) => panic!("Failed to read file at {}: {:?}", new_cert_path, err),
        Ok(content) => match new_cert_path.rsplit_once('.') {
            None => panic!("No file extension on new certificate to infer format from."),
            Some((_, ext)) => match ext {
                "pem" | "crt" | "cer" => X509::from_pem(&content).unwrap(),
                other => todo!("Support extension {}", other),
            },
        },
    };

    let common_name = match args.common_name {
        Some(cn) => cn,
        None => get_cn(&new_cert).expect("Failed to get common name from provided certificate."),
    };

    if get_user_consent(&common_name, new_privkey_path.is_some()) {
        let privkey = match new_privkey_path {
            Some(file) => {
                match parse_privkey(&fs::read(file).expect("Failed to read supplied private key."))
                {
                    Some(pkey) => Some(pkey),
                    None => panic!("Failed to parse private key from provided file."),
                }
            }
            None => None,
        };

        for bundle in find_certs(PathBuf::from(args.path), &common_name, privkey.is_some()) {
            let privkey = match bundle.privkey {
                None => "no".to_string(),
                Some(pkey) => format!("yes, at {:?}", pkey.path),
            };
            println!(
                "Matching bundle: {:?}; Has privkey: {}",
                bundle.cert.path, privkey
            );
        }
    } else {
        panic!(
            "User declined to replace objects for common name: {}",
            common_name
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

/// Gets the common name from a certificate if possible.
fn get_cn(cert: &X509) -> Option<String> {
    if let Some(data) = cert.subject_name().entries_by_nid(Nid::COMMONNAME).last() {
        if let Ok(string) = data.data().as_utf8() {
            return Some(string.to_string());
        }
    }
    return None;
}

/// Returns true if user confirms operation.
fn get_user_consent(cn: &str, privkeys: bool) -> bool {
    if privkeys == true {
        println!(
            "Replacing certificates and private keys with common name matching: \"{}\". Okay? (y/n)", 
            cn
        );
    } else {
        println!(
            "Replacing certificates with common name matching: \"{}\". Okay? (y/n)",
            cn
        );
    }

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read user confirmation for target common name.");
    return input.to_lowercase().starts_with("y");
}

/// Finds certificates in the path that match the cn, and returns them.
/// Finds their matching privkeys if the parameter is true.
fn find_certs(path: PathBuf, cn: &str, privkeys: bool) -> Vec<CertBundle> {
    let mut bundles = Vec::new();

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
                                certs.push(cert)
                            }
                        }
                        PKIObject::PrivKey(pkey) => keys.push(pkey),
                    }
                }
            }
        }
    }

    for cert in certs {
        if cert.common_name == cn {
            let privkey = if privkeys {
                find_privkey(&cert.cert, &keys)
            } else {
                None
            };

            bundles.push(CertBundle { cert, privkey })
        }
    }

    return bundles;
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
            } else if let Ok(cert) = X509::from_pem(&content) {
                if let Some(common_name) = get_cn(&cert) {
                    pkiobjs.push(PKIObject::Cert(Cert {
                        cert,
                        common_name,
                        path,
                    }));
                }
            } else if let Ok(cert) = X509::from_der(&content) {
                if let Some(common_name) = get_cn(&cert) {
                    pkiobjs.push(PKIObject::Cert(Cert {
                        cert,
                        common_name,
                        path,
                    }));
                }
            } else if let Ok(certs) = X509::stack_from_pem(&content) {
                for cert in certs {
                    if let Some(common_name) = get_cn(&cert) {
                        pkiobjs.push(PKIObject::Cert(Cert {
                            cert,
                            common_name,
                            path: path.clone(),
                        }));
                    }
                }
            } else {
                return Err(ParseError {
                    msg: format!("Failed to parse data from file at: {:?}", path),
                });
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

/// Returns the private key matching the public key in the certificate.
fn find_privkey(cert: &X509, keys: &Vec<PrivKey>) -> Option<PrivKey> {
    if let Ok(pubkey) = cert.public_key() {
        for (index, key) in keys.iter().enumerate() {
            if key.key.public_eq(&pubkey) {
                return Some(keys.get(index).unwrap().clone());
            }
        }
    }
    return None;
}

fn replace_cert(path: &str, content: &str) {
    let backup_path = format!("{}.bkp", &path);
    let backup_result = fs::copy(path, &backup_path); // TODO add date
    if backup_result.is_ok() {
        let write_result = fs::write(&path, &content);
        if write_result.is_err() {
            warn!("Failed to write to certificate at {}", path);
        }
    } else {
        warn!(
            "Failed to backup certificate at {} to {}",
            path, backup_path
        );
    }
}
