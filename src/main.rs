mod model;
mod parse;

use anyhow::{bail, Context, Result};
use model::{Cert, CommonName, PEMKind, PEMLocator, PKIObject, PrivKey, Replacement, Verb};
use parse::{find_certs, parse_pkiobjs};
use regex::Regex;
use time::format_description::well_known::iso8601::EncodedConfig;

use clap::Parser;
use paris::{error, info, warn};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::exit;
use std::{
    io::{self, Write},
    str,
};
use time::{
    format_description::well_known::iso8601::{Config, Iso8601},
    OffsetDateTime,
};

/// The help text to error for the regex parameter.
const REGEX_HELP: &str = "Rust regex pattern that subject name \
                          (common name or an alternative name) must match in x509 certificates.";

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

#[derive(Parser)]
pub struct Cli {
    /// Path to search in.
    pub path: String,
    /// Rust regex pattern for common name to match.
    #[arg(short = 'e', long = "regex", help = REGEX_HELP)]
    pub regex: Option<String>,
    /// Common or alternative name to match in target certificates.
    #[arg(short = 'n', long = "name", help = COMMON_NAME_HELP)]
    pub name: Option<String>,
    /// Path to file with x509 certificate to use as replacement.
    #[arg(short = 'c', long = "cert", help = CERTIFICATE_HELP)]
    pub certificate: Option<String>,
    /// Path to file with private key to use as replacement.
    #[arg(short = 'p', long = "priv", help = PRIVATE_KEY_HELP)]
    pub private_key: Option<String>,
    /// Whether to force the operation (don't prompt for confirmation)
    #[arg(short = 'f', long = "force", help = FORCE_HELP)]
    pub force: bool,
}

fn main() {
    let args = Cli::parse();

    if args.regex.is_some() & args.name.is_some() {
        error!("Please only use one of regex (-e) and common name (-n) parameters.");
        exit(1);
    }

    let common_name = match args.name {
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
        Some(common_name) => Some(CommonName::Literal(common_name)),
    };

    let verb = match &args.certificate {
        Some(cert_path) => {
            let cert = match choose_cert(cert_path, common_name.as_ref()) {
                Ok(cert) => cert,
                Err(err) => {
                    error!("{err}");
                    exit(1);
                }
            };

            let privkey = args
                .private_key
                .as_ref()
                .map(|privkey_path| choose_privkey(privkey_path, &cert).unwrap());

            Verb::Replace {
                name: CommonName::Literal(cert.common_name.clone()),
                cert,
                privkey,
            }
        }
        None => {
            if let Some(common_name) = common_name {
                Verb::Find { name: common_name }
            } else {
                error!("Must provide one of name, regex, or certificate to use for search.");
                exit(1);
            }
        }
    };

    if args.force || confirm_action(&verb) {
        let paths = find_certs(&PathBuf::from(args.path), verb.name(), verb.privkeys());
        match verb {
            Verb::Find { .. } => print_pems(&paths),
            Verb::Replace { cert, privkey, .. } => {
                if let Err(err) = replace_pems(paths, &cert, privkey) {
                    error!("{err}");
                    exit(1);
                }
            }
        }
    } else {
        error!(
            "User declined to replace objects for common name: {}",
            verb.name()
        );
        exit(1);
    }
}

/// Chooses a certificate matching a common name from an input file of pki objs,
/// or returns an error if there is no unique match.
fn choose_cert(path: &str, name: Option<&CommonName>) -> Result<Cert> {
    let path = PathBuf::from(path);
    let pkis = parse_pkiobjs(&path).with_context(|| {
        format!(
            "Failed to parse certificates or keys from {}",
            path.display()
        )
    })?;

    if let Some(name) = name {
        let mut certs = Vec::new();
        for pki in pkis {
            match pki {
                PKIObject::Cert(cert) => {
                    if name.matches(&cert.common_name) {
                        certs.push(cert);
                    }
                }
                PKIObject::PrivKey(_) => {}
            }
        }
        if certs.len() == 1 {
            Ok(certs.pop().unwrap())
        } else {
            bail!(
                "Replacement file does not contain exactly one certificate \
                with common name matching \"{name}\""
            )
        }
    } else {
        let mut certs = Vec::new();
        for pki in pkis {
            if let PKIObject::Cert(cert) = pki {
                certs.push(cert);
            }
        }

        if certs.len() == 1 {
            Ok(certs.pop().unwrap())
        } else {
            bail!(
                "Replacement file does not contain exactly one certificate, \
                so a common name must be provided."
            )
        }
    }
}

/// Chooses a private key matching a cert from a file of pki objs,
/// or returns an error if there is no unique match.
fn choose_privkey(path: &str, cert: &Cert) -> Result<PrivKey> {
    if let Ok(pubkey) = cert.content.public_key() {
        let path = PathBuf::from(path);
        let pkis = parse_pkiobjs(&path).unwrap();
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
            Ok(privkeys.pop().unwrap())
        } else {
            bail!(
                "Provided file does not contain exactly one private key match cert with common name: {}",
                cert.common_name
            )
        }
    } else {
        bail!(
            "Failed to get public key from provided certificate with common name matching \"{}\"",
            cert.common_name
        )
    }
}

/// Returns true if user confirms operation.
fn confirm_action(verb: &Verb) -> bool {
    match verb {
        Verb::Find { .. } => {
            info!("{verb}");
            true
        }
        Verb::Replace {
            name: _,
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
            input.to_lowercase().starts_with('y')
        }
    }
}

/// Prints the locations of pems.
fn print_pems(pems: &[PEMLocator]) {
    println!();
    info!("Matching certificates:");
    for cert in pems {
        if cert.kind == PEMKind::Cert {
            println!("\t{}", cert.path.display());
        }
    }

    println!();
    info!("Matching private keys:");
    for key in pems {
        if key.kind == PEMKind::PrivKey {
            println!("\t{}", key.path.display());
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
    map
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
fn replace_pems(
    targets: Vec<PEMLocator>,
    cert: &Cert,
    privkey: Option<PrivKey>,
) -> Result<Vec<Replacement>> {
    let cert_pem = cert
        .content
        .to_pem()
        .context("Failed to convert the input certificate to a PEM")?;

    let (pkey_pem, pkey_path) = if let Some(privkey) = privkey {
        (
            privkey
                .key
                .private_key_to_pem_pkcs8()
                .context("Failed to convert new private key to PEM")?,
            privkey.locator.path,
        )
    } else {
        (vec![], PathBuf::new())
    };

    let now = OffsetDateTime::now_utc()
        .format(&(Iso8601 as Iso8601<DATETIME_FORMAT_CONFIG>))
        .context("Failed to format the current date and time")?;
    let mut replacements = Vec::new();

    for (path, pems) in pems_by_path(targets) {
        if (path == cert.locator.path) | (path == pkey_path) {
            continue;
        }

        let mut content = fs::read(&path).with_context(|| {
            format!(
                "Failed to read file marked for modification at {}",
                path.display()
            )
        })?;

        let mut offset = 0;
        let mut changed = false;
        for locator in pems {
            let pem = match locator.kind {
                PEMKind::Cert => cert_pem.trim_ascii_end(),
                PEMKind::PrivKey => pkey_pem.trim_ascii_end(),
            };

            let (start, end) = (locator.start + offset, locator.end + offset);

            if &content[start..=end] != pem {
                changed = true;
                content = [&content[..start], pem, &content[end..]].concat();
            }

            offset += pem.len() - (locator.end - locator.start);
        }

        if changed {
            let backup = match backup_file(&path, &now) {
                Ok(bkp_path) => bkp_path,
                Err(err) => {
                    error!("Failed to backup file at {}: {err}", path.display());
                    warn!(
                        "Not touching file at {} due to backup error.",
                        path.display()
                    );
                    continue;
                }
            };

            info!("Replacing PEMs in {}", path.display());
            if let Err(err) = fs::write(&path, content) {
                error!("Error writing: {err}");
                continue;
            }

            replacements.push(Replacement {
                backup,
                modified: path,
            });
        }
    }

    if replacements.is_empty() {
        info!("Did not change any files.");
    }

    Ok(replacements)
}

/// Creates a backup of a file with the provided datetime and ".bkp" appended to the filename.
/// Returns the path of the backup.
fn backup_file(path: &PathBuf, datetime: &str) -> Result<PathBuf> {
    let ext = match path.extension() {
        None => String::new(),
        Some(os_str) => os_str.to_string_lossy().to_string(),
    };
    let mut bkp_path = path.clone();
    bkp_path.set_extension(format!("{ext}.{datetime}.bkp",));
    fs::copy(path, &bkp_path)?;

    Ok(bkp_path)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_backup() {
        let original = PathBuf::from_str("./test/search/alice.pem").unwrap();
        backup_file(&original, "testtime").unwrap();

        let backup = format!("{}.testtime.bkp", original.display());

        assert_eq!(fs::read(&original).unwrap(), fs::read(&backup).unwrap());

        fs::remove_file(&backup).unwrap();
    }

    #[test]
    fn test_replace_certs() {
        let incert_path = "./test/mock-certs/leaf-replace.pem";
        let incert = choose_cert(incert_path, None).unwrap();

        let paths = find_certs(
            &PathBuf::from_str("./test/mock-certs").unwrap(),
            &CommonName::Literal(incert.common_name.clone()),
            false,
        )
        .into_iter()
        // remove file we want to use for comparison later
        .filter(|loc| !loc.path.ends_with("full-chain-replaced.pem"))
        .collect::<Vec<_>>();

        let replacements = replace_pems(paths, &incert, None).unwrap();
        let mut modified: Vec<PathBuf> = replacements
            .iter()
            .map(|repl| repl.modified.clone())
            .collect();
        modified.sort();

        let old_leaf = PathBuf::from_str("./test/mock-certs/leaf.pem").unwrap();
        let old_fullchain = PathBuf::from_str("./test/mock-certs/full-chain.pem").unwrap();
        assert_eq!(
            modified,
            Vec::from([old_fullchain.clone(), old_leaf.clone()])
        );

        let new_leaf_content = fs::read(&old_leaf).unwrap();
        assert_eq!(fs::read(&incert_path).unwrap(), new_leaf_content);

        let new_fullchain_content = fs::read(&old_fullchain).unwrap();
        assert_eq!(
            fs::read("./test/mock-certs/full-chain-replaced.pem").unwrap(),
            new_fullchain_content
        );

        for replacement in replacements {
            let backup_content = fs::read(&replacement.backup).unwrap();
            fs::write(&replacement.modified, backup_content).unwrap();
            fs::remove_file(&replacement.backup).unwrap();
        }
    }
}
