mod model;
mod parse;

use model::*;
use parse::*;
use std::path::PathBuf;
use std::{
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
