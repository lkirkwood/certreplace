mod model;
mod parse;

use model::*;
use parse::*;
use regex::Regex;
use time::format_description::well_known::iso8601::EncodedConfig;

use paris::{error, info};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::exit;
use std::{
    io::{self, Write},
    str,
};
use structopt::StructOpt;
use time::{
    format_description::well_known::iso8601::{Config, Iso8601},
    OffsetDateTime,
};

/// The help text to error for the regex parameter.
const REGEX_HELP: &str = "Rust regex pattern that subject name (common name or an alternative name) must match in x509 certificates.";

/// The help text to display for the common name parameter.
const COMMON_NAME_HELP: &str =
    "Subject name (common name or an alternative name) that must be present in x509 certificates.";

/// The help text to display for the certificate parameter.
const CERTIFICATE_HELP: &str = "Path to file containing certificate to use as a replacement. \
If this file contains only one certificate, no common name needs to be provided.
Will just find matching certs if not provided.";

/// The help text to display for the private key parameter.
const PRIVATE_KEY_HELP: &str = "Path to file containing private key to use as a replacement. \
Private keys will not be replaced if this is not provided.";

/// The help text to display for the force parameter.
const FORCE_HELP: &str = "If this is set the user will not be prompted to confirm the operation.";

/// Structopt cli struct.
#[derive(StructOpt)]
pub struct Cli {
    /// Path to search in.
    pub path: String,
    /// Rust regex pattern for common name to match.
    #[structopt(short = "e", long = "regex", help = REGEX_HELP)]
    pub regex: Option<String>,
    /// Common or alternative name to match in target certificates.
    #[structopt(short = "n", long = "name", help = COMMON_NAME_HELP)]
    pub name: Option<String>,
    /// Path to file with x509 certificate to use as replacement.
    #[structopt(short = "c", long = "cert", help = CERTIFICATE_HELP)]
    pub certificate: Option<String>,
    /// Path to file with private key to use as replacement.
    #[structopt(short = "p", long = "priv", help = PRIVATE_KEY_HELP)]
    pub private_key: Option<String>,
    /// Whether to force the operation (don't prompt for confirmation)
    #[structopt(short = "f", long = "force", help = FORCE_HELP)]
    pub force: bool,
}

/// Main loop of the app.
fn main() {
    let args = Cli::from_args();

    if args.regex.is_some() & args.name.is_some() {
        error!("Please only use one of regex (-e) and common name (-n) parameters.");
        exit(1);
    }

    let cn = match args.name {
        None => match args.regex {
            None => None,
            Some(pattern) => match Regex::new(&pattern) {
                Ok(pattern) => Some(CommonName::Pattern(pattern)),
                Err(err) => {
                    error!("Invalid regular expression {pattern}: {err}");
                    exit(1);
                }
            },
        },
        Some(cn) => Some(CommonName::Literal(cn)),
    };

    let verb = match &args.certificate {
        Some(cert_path) => {
            let cert = match choose_cert(cert_path, cn.as_ref()) {
                Ok(cert) => cert,
                Err(err) => {
                    error!("{err}");
                    exit(1);
                }
            };

            let privkey = match &args.private_key {
                None => None,
                Some(privkey_path) => Some(choose_privkey(privkey_path, &cert).unwrap()),
            };

            Verb::Replace {
                cn: CommonName::Literal(cert.common_name.clone()),
                cert,
                privkey,
            }
        }
        None => match cn {
            Some(cn) => Verb::Find { cn },
            None => {
                error!("Must provide one of name, regex, or certificate to use for search.");
                exit(1);
            }
        },
    };

    if args.force || confirm_action(&verb) {
        let paths = find_certs(PathBuf::from(args.path), verb.cn(), verb.privkeys());
        match verb {
            Verb::Find { .. } => print_pems(paths),
            Verb::Replace {
                cn: _,
                cert,
                privkey,
            } => replace_pems(paths, cert, privkey),
        }
    } else {
        error!(
            "User declined to replace objects for common name: {}",
            verb.cn()
        );
        exit(1);
    }
}

/// Chooses a certificate matching a common name from a file of pki objs,
/// or returns an error if there is no unique match.
fn choose_cert(path: &str, cn: Option<&CommonName>) -> Result<Cert, ParseError> {
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
                msg: "Replacement file does not contain exactly one certificate, so a common name must be provided.".to_string()
            });
        }
    } else {
        let cn = cn.unwrap();

        let mut certs = Vec::new();
        for pki in pkis {
            match pki {
                PKIObject::Cert(cert) => {
                    if cn.matches(&cert.common_name) {
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
                msg: format!("Replacement file does not contain exactly one certificate with common name matching \"{cn}\"")
            });
        }
    }
}

/// Chooses a private key matching a cert from a file of pki objs,
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
                "Failed to get public key from provided certificate with common name matching \"{}\"",
                cert.common_name
            ),
        });
    }
}

/// Returns true if user confirms operation.
fn confirm_action(verb: &Verb) -> bool {
    match verb {
        Verb::Find { .. } => {
            info!("{verb}");
            return true;
        }
        Verb::Replace {
            cn: _,
            cert,
            privkey,
        } => {
            info!("{verb}");
            info!("Replacement certificate: {:?}", cert.locator.path);
            if let Some(privkey) = privkey {
                info!("Replacement private key: {:?}", privkey.locator.path);
            }
            print!("Okay? (y/n) ");
            io::stdout()
                .flush()
                .expect("Failed to flush stdout when printing confirmation message.");
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .expect("Failed to read user confirmation for target common name.");
            return input.to_lowercase().starts_with("y");
        }
    }
}

/// Prints the locations of pems.
fn print_pems(pems: Vec<PEMLocator>) {
    println!();
    info!("Matching certificates:");
    for cert in &pems {
        if cert.kind == PEMKind::Cert {
            println!("\t{:#?}", cert.path);
        }
    }

    println!();
    info!("Matching private keys:");
    for key in &pems {
        if key.kind == PEMKind::PrivKey {
            println!("\t{:#?}", key.path);
        }
    }
}

/// Maps pems by their file paths.
fn pems_by_path(pems: Vec<PEMLocator>) -> HashMap<PathBuf, Vec<PEMLocator>> {
    let mut map = HashMap::new();
    for pem in pems {
        if !map.contains_key(&pem.path) {
            map.insert(pem.path.clone(), vec![]);
        }
        map.get_mut(&pem.path).unwrap().push(pem);
    }
    return map;
}

/// Configures the format of the Iso8601 datetime.
const DATETIME_FORMAT_CONFIG: EncodedConfig = Config::DEFAULT
    .set_use_separators(false)
    .set_time_precision(
        time::format_description::well_known::iso8601::TimePrecision::Minute {
            decimal_digits: None,
        },
    )
    .encode();

/// Replaces the target pems with the new data.
fn replace_pems(targets: Vec<PEMLocator>, cert: Cert, privkey: Option<PrivKey>) {
    let cert_pem = match cert.cert.to_pem() {
        Ok(pem) => pem,
        Err(err) => {
            error!("Failed to convert new certificate to PEM: {:?}", err);
            exit(1);
        }
    };

    let (pkey_pem, pkey_path) = if let Some(privkey) = privkey {
        match privkey.key.private_key_to_pem_pkcs8() {
            Ok(pem) => (pem, privkey.locator.path),
            Err(err) => {
                error!("Failed to convert new private key to PEM: {err}");
                exit(1);
            }
        }
    } else {
        (vec![], PathBuf::new())
    };

    let now = match OffsetDateTime::now_utc().format(&(Iso8601 as Iso8601<DATETIME_FORMAT_CONFIG>))
    {
        Ok(datetime) => datetime,
        Err(err) => {
            error!("Failed to format datetime: {err}");
            exit(1);
        }
    };
    let mut any_changed = false;

    for (path, pems) in pems_by_path(targets) {
        if (path == cert.locator.path) | (path == pkey_path) {
            continue;
        }

        if let Err(err) = backup_file(&path, &now) {
            error!("Failed to backup file at {path:#?}: {err}");
            continue;
        }

        let mut content = match fs::read(&path) {
            Err(err) => {
                error!("Failed to read file marked for modification at {path:#?}: {err}");
                return;
            }
            Ok(bytes) => bytes,
        };

        // pems always read in order, so offset can be scalar.
        let mut offset: isize = 0;
        let mut changed = false;
        for locator in pems {
            let pem = match locator.kind {
                PEMKind::Cert => &cert_pem,
                PEMKind::PrivKey => &pkey_pem,
            };

            let (target_start, target_end) = (locator.start as isize, locator.end as isize);
            let (start, end) = (
                0.max(target_start + offset) as usize,
                0.max(target_end + offset) as usize,
            );

            if &content[start..=end] != pem {
                changed = true;
            }

            content = [&content[..start], pem, &content[end..]].concat();
            offset += pem.len() as isize - (target_end - target_start);
        }

        if changed {
            info!("Replacing PEMs in {path:#?}");
            if let Err(err) = fs::write(path, content) {
                error!("Error writing: {err}")
            };
            any_changed = true;
        }
    }

    if !any_changed {
        info!("Did not change any files.")
    }
}

/// Creates a backup of a file with the provided datetime and ".bkp" appended to the filename.
fn backup_file(path: &PathBuf, datetime: &str) -> Result<(), io::Error> {
    let ext = match path.extension() {
        None => String::new(),
        Some(os_str) => os_str.to_string_lossy().to_string(),
    };
    let mut bkp_path = path.clone();
    bkp_path.set_extension(format!("{ext}.{datetime}.bkp",));
    fs::copy(path, bkp_path)?;
    return Ok(());
}
