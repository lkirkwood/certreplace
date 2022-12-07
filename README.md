# certreplace

A tool for replacing SSL certificates and their associated private keys.

## Usage

`certreplace /path/to/search -n <string>`

Certreplace will, given a string, find all of the PEM encoded x509 certificates in the path provided
with the same subject common name as the string. 
Additionally, it will find all the PEM, DER or PKCS8 private keys that match at least one certificate.

`certreplace /path -n <string> --cert <path>`

If you provide the path to a file containing only one certificate with the correct common name,
all other certificates that are found will be replaced with the one found in the provided file.
This does not affect the other data in the file.

`certreplace /path  --cert <path>`

If you only provide the certificate path, and the file only contains one x509 certificate,
the common name will be extracted and used to find certificates to replace.

`certreplace /path [-n <string>] --cert <path> --priv <path>`

If you provide a path to a file containing a single private key 
that matches the given certificate's public key, any private keys found that match
certificates about to be replaced will *also* be replaced.
