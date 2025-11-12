use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::{
    model::{Cert, CommonName, PKIObject, PrivKey},
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
