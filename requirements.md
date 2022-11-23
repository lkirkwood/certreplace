# Requirements
---

- Discovers x509 certificates in the specified location.
- Replaces discovered certificates with those provided by the user, 
**only** if they match the common name specified, or the common name on the new certificate if none is provided.
- Creates backups of the original certificates, using a naming scheme that allows this process to be repeated without losing previous backups.
- Is able to find the corresponding private key for a certificate.
- If a new private key is provided, replaces the private keys of the old certificates.