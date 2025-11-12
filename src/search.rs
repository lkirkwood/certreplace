use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use jwalk::WalkDir;
use paris::error;

use crate::{
    model::{Cert, CommonName, PEMLocator, PKIObject, PrivKey},
    parse::parse_pkiobjs,
};

/// Chooses a certificate matching a common name from an input file of pki objs,
/// or returns an error if there is no unique match.
pub fn choose_cert(path: &str, name: Option<&CommonName>) -> Result<Cert> {
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
pub fn choose_privkey(path: &str, cert: &Cert) -> Result<PrivKey> {
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

/// Finds certificates in the path that match the cn, and returns them.
/// Finds their matching privkeys if the parameter is true.
pub fn find_certs(path: &PathBuf, cn: &CommonName, privkeys: bool) -> Vec<PEMLocator> {
    let mut certs = Vec::new();
    let mut keys = Vec::new();
    for path in find_pkiobj_files(path) {
        match parse_pkiobjs(&path) {
            Err(err) => error!("{:?}", err),
            Ok(pkiobjs) => {
                for pkiobj in pkiobjs {
                    match pkiobj {
                        PKIObject::Cert(cert) => {
                            if cn.matches(&cert.common_name) {
                                certs.push(cert);
                            }
                        }
                        PKIObject::PrivKey(pkey) => keys.push(pkey),
                    }
                }
            }
        }
    }

    let mut pems = Vec::new();
    for cert in certs {
        if cn.matches(&cert.common_name) {
            if privkeys {
                if let Ok(pubkey) = cert.content.public_key() {
                    pems.extend(
                        keys.extract_if(.., |key| key.key.public_eq(&pubkey))
                            .map(|pubkey| pubkey.locator),
                    );
                } else {
                    error!("Failed to read public key from X509: {cert:?}");
                }
            }
            pems.push(cert.locator);
        }
    }

    pems
}

/// Finds files with pem/crt/key/cer/der extensions in the provided path.
pub fn find_pkiobj_files(path: &PathBuf) -> Vec<PathBuf> {
    let mut paths = vec![];
    for file in WalkDir::new(path).into_iter().flatten() {
        if let Some(name) = file.file_name.to_str() {
            if let Some((_, "pem" | "crt" | "key" | "cer" | "der")) = name.rsplit_once('.') {
                paths.push(file.path());
            }
        }
    }
    paths
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, path::PathBuf};

    use regex::Regex;

    use crate::model::{CommonName, PEMKind, PEMLocator};

    use super::{find_certs, find_pkiobj_files};

    fn found_certs() -> Vec<PEMLocator> {
        vec![
            PEMLocator {
                start: 0,
                end: 3322,
                kind: PEMKind::PrivKey,
                path: PathBuf::from("test/search/bob.key"),
            },
            PEMLocator {
                start: 16857,
                end: 18901,
                kind: PEMKind::Cert,
                path: PathBuf::from("test/search/alice.pem"),
            },
        ]
    }

    #[test]
    fn test_find_certs() {
        let found = find_certs(
            &PathBuf::from("test/search/"),
            &CommonName::Literal("localhost".to_string()),
            true,
        );
        assert_eq!(found_certs(), found);
    }

    #[test]
    fn test_find_regex_certs() {
        let found = find_certs(
            &PathBuf::from("test/search/"),
            &CommonName::Pattern(Regex::new("local.*").unwrap()),
            true,
        );
        assert_eq!(found_certs(), found)
    }

    fn found_pkiobj_files() -> HashSet<PathBuf> {
        HashSet::from([
            PathBuf::from("test/search/bob.key"),
            PathBuf::from("test/search/alice.pem"),
        ])
    }

    #[test]
    fn test_find_pkiobj_files() {
        let found = HashSet::from_iter(find_pkiobj_files(&PathBuf::from("test/search")));
        assert_eq!(found_pkiobj_files(), found);
    }
}
