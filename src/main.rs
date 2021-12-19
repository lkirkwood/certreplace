use structopt::StructOpt;
use std::{fs, str::FromStr};
use log::warn;

#[derive(StructOpt)]
struct Cli {
    /// Path to public key to use as replacement.
    public_key: String,
    /// Path to private key to use as replacement.
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
    let public_key_path = args.public_key;
    let private_key_path = args.private_key;

    let public_key = fs::read_to_string(public_key_path.clone())
        .expect(format!("Failed to read file at {}", public_key_path).as_str());

    let private_key = fs::read_to_string(private_key_path.clone())
        .expect(format!("Failed to read file at {}", private_key_path).as_str());

    let common_name = cn_from_public_key(&public_key);
    
    for certfile in scan_for_certs(&common_name) {
        if certfile.common_name == common_name {
            replace_cert(&certfile.public_key_path, &public_key);
            replace_cert(&certfile.private_key_path, &private_key)
        }
    }
}

fn valid_cn(common_name: &str) -> bool {true}

fn cn_from_public_key(public_key: &str) -> &str {"domain.com"}

fn scan_for_certs(common_name: &str) -> Vec<CertBundle> {Vec::new()}

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