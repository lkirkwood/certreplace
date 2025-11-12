mod model;
mod parse;
mod replace;
mod search;

use replace::replace_pems;
use search::{choose_cert, choose_privkey};

use model::{CommonName, PEMKind, PEMLocator, Verb};
use parse::find_certs;
use regex::Regex;

use clap::Parser;
use paris::{error, info};
use std::path::PathBuf;
use std::process::exit;
use std::{
    io::{self, Write},
    str,
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
