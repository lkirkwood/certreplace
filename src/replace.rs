use crate::model::{Cert, PEMKind, PEMLocator, PrivKey, Replacement};
use anyhow::{Context, Result};
use std::{collections::HashMap, fs, path::PathBuf};
use time::{
    format_description::well_known::{
        iso8601::{Config, EncodedConfig},
        Iso8601,
    },
    OffsetDateTime,
};

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
pub fn replace_pems(
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
                    eprintln!("Failed to backup file at {}: {err}", path.display());
                    eprintln!(
                        "Not touching file at {} due to backup error.",
                        path.display()
                    );
                    continue;
                }
            };

            eprintln!("Replacing PEMs in {}", path.display());
            if let Err(err) = fs::write(&path, content) {
                eprintln!("Error writing: {err}");
                continue;
            }

            replacements.push(Replacement {
                backup,
                modified: path,
            });
        }
    }

    if replacements.is_empty() {
        eprintln!("Did not change any files.");
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{
        model::CommonName,
        search::{choose_cert, find_certs},
    };

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
