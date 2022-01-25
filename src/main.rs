use structopt::StructOpt;
use x509_parser::prelude::X509Certificate;
use std::fmt::Error;
use std::path::PathBuf;
use std::{fs, io};
use std::collections::HashSet;
use log::warn;

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
    private_key: String
}

struct CertBundle {
    /// Path to public key
    public_key_path: String,
    /// Path to private key
    private_key_path: String,
    /// Common name from the public key
    common_name: String
}

fn main() {
    let args = Cli::from_args();
    let search_path = args.path;
    let new_cert_path = args.certificate;
    let new_privkey_path = args.private_key;

    let new_cert = fs::read_to_string(new_cert_path.clone())
        .expect(format!("Failed to read file at {}", new_cert_path).as_str());

    let new_privkey = fs::read_to_string(new_privkey_path.clone())
        .expect(format!("Failed to read file at {}", new_privkey_path).as_str());

    let common_name = match args.common_name {
        Some(cn) => cn,
        None => cn_from_public_key(&new_cert)
            .expect("Failed to parse common name from public key.")
    };
    let common_name = cn_from_public_key(&new_cert)
        .expect("Failed to parse common name from public key.");

    let certs: Vec<X509Certificate> = Vec::new();
    let privkeys: Vec<String> = Vec::new();
    for path in match search_for_certs(&search_path) {
        Err(err) => panic!("{}", err), 
        Ok(paths) => paths
    } {
        // TODO implement parsing
    }
}

fn valid_cn(common_name: &String) -> bool {true}

fn cn_from_public_key(public_key: &String) -> Result<String, Error> {
    Ok(String::from("domain.com"))
}

const SEARCH_EXTENSIONS: [&str; 5] = [
    "pem", "cer", "der", "crt", "key"
];

/// Recursively searches a directory for files with matching extensions. 
/// Returns their paths.
fn search_for_certs(path: &str) -> Result<HashSet<PathBuf>, io::Error> {
    let mut paths = HashSet::new();
    for entry in fs::read_dir(&path)? {
        let entry = match entry {
            Err(_) => continue, Ok(val) => val};
        let entry_type = match entry.file_type() {
            Err(_) => continue, Ok(val) => val};

        if entry_type.is_file() {
            let path = entry.path();
            let ext = match path.extension() {
                None => continue, Some(val) => match val.to_str() {
                    None => continue, Some(val) => val}};
            if SEARCH_EXTENSIONS.contains(&ext) {
                paths.insert(path);
            }

        }
    }
    return Ok(paths);
}

fn replace_cert(path: &str, content: &str) {
    let backup_path = format!("{}.bkp", &path);
    let backup_result = fs::copy(path, &backup_path); // TODO add date
    if backup_result.is_ok() {
        let write_result = fs::write(&path, &content);
        if write_result.is_err() {
            warn!("Failed to write to certificate at {}", path);}
    } else {
        warn!("Failed to backup certificate at {} to {}", path, backup_path);
    }
}