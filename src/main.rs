use structopt::StructOpt;
use std::{fs, io};
use std::collections::HashSet;
use log::warn;

const TEST_CN: &str = "domain.com";

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

    let common_name = cn_from_public_key(&public_key)
        .expect("Failed to parse common name from public key.");

    for certfile in search_for_certs(&common_name) {
        replace_cert(&certfile.public_key_path, &public_key);
        replace_cert(&certfile.private_key_path, &private_key);
    }
}

fn valid_cn(common_name: &String) -> bool {true}

#[derive(PartialEq, Eq, Hash)]
/// A public or private X.509 key
struct Key {
    /// The string content of the key.
    value: String,
    /// Common name from the key, if is_public.
    common_name: Option<String>,
    /// Whether this key is a public key.
    is_public: bool
}

impl Key {
    fn valid_pubkey(string: &String) -> bool {true} //TODO implement pub/privkey validation
    
    fn valid_privkey(string: &String) -> bool {true}

    fn pubkey_from_string(string: &String) -> Result<Key, InvalidKey> {
        cn_from_public_key(string).and_then(|cn| Ok(Key {
            value: String::from("public key"),
            common_name: Some(cn),
            is_public: true
        }))
    }

    fn privkey_from_string(string: &String) -> Result<Key, InvalidKey> {
        Ok(Key {
            value: String::from("private key"),
            common_name: None,
            is_public: false
        })
    }
}

#[derive(Debug, Clone)]
/// A string which could not be parsed as a public or private X.509 key.
struct InvalidKey {string: String}

fn cn_from_public_key(public_key: &String) -> Result<String, InvalidKey> {Ok(String::from("domain.com"))}

const SEARCH_LOCATIONS: [&str; 3] = [
    "/etc/ssl/",
    "/etc/nginx",
    "/etc/httpd"
];

fn search_for_certs(common_name: &String) -> Vec<CertBundle> {
    let mut certs: Vec<CertBundle> = Vec::new();
    let mut keys = KeySet{public_keys: HashSet::new(), private_keys: HashSet::new()};
    for path in SEARCH_LOCATIONS.iter() {
        for key_set in search_dir(path, common_name) {
            keys.public_keys.extend(key_set.public_keys)
        }
    }
    return certs
}

const SEARCH_EXTENSIONS: [&str; 0] = [

];

/// Set of X.509 certificate keys.
struct KeySet {
    /// Public X.509 keys
    public_keys: HashSet<Key>,
    /// Private X.509 keys
    private_keys: HashSet<Key>
}

/// Recursively searches a directory for X.509 keys.
fn search_dir(path: &str, common_name: &String) -> Result<KeySet, io::Error> {
    let mut keys = KeySet {public_keys: HashSet::new(), private_keys: HashSet::new()};
    for entry in fs::read_dir(&path)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue
        };
        let entry_type = match entry.file_type() {
            Ok(entry_type) => entry_type,
            Err(_) => continue
        };

        if entry_type.is_file() {
            let contents = match fs::read_to_string(entry.path()) {
                Ok(contents) => contents,
                Err(_) => continue
            };

            match Key::pubkey_from_string(&contents) {
                Ok(key) => match &key.common_name {
                    Some(cn) => {if cn == common_name {
                        keys.public_keys.insert(key);};},
                    None => continue
                }
                Err(key) => match Key::privkey_from_string(&key.string) {
                    Ok(key) => {keys.private_keys.insert(key);},
                    Err(_) => continue
                }
            };
        }
    }
    return Ok(keys);
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