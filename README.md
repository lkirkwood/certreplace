# certreplace

A tool for finding/replacing SSL certificates and their associated private keys.

## Usage

Certreplace will **always** back up files with time-stamped names if they will be modified.
Unless the `-f, --force` parameter is used, certreplace will always confirm before modifying any files.

Certreplace can find certificates in two ways. If given a name (`-n, --name`) or regex pattern (`-e, --regex`), it will find x509 certificates with a Subject Common Name or Subject Alternative Name matching that value.

If given a path to a certificate file (`-c, --cert`) it will attempt to find other certificates matching the input cert using the following steps:
+ If there is only one public cert in the file, the common name and alternative names will be used. Similar to running with the `-n, --name` parameter.
+ If you *additionally* provide a path to a private key file (`-p, --priv`) with only one private key in it, the public cert in the input file matching the provided private key will be used to search. This lets you use cert files with multiple public certs as input.

If you provided a public cert with `-c, --cert`, certreplace will attempt to replace any matching certs it finds with the input cert (after confirming each one).
If you provided a private key with `-p, --priv`, certreplace will replace the private keys of matching certs aswell.

## Examples

1. `certreplace /path/to/search --name <common name>`

This will find all certificates with a Subject Common Name or Subject Alternative Names value *exactly equal* to the `common name` parameter.
Additionally, it will find private keys that match one of the certificates.

2. `certreplace /path/to/search --regex <regex pattern>`

This will find all certificates with a Subject Common Name or Subject Alternative Names value *matching* the `regex pattern` parameter.
Additionally, it will find private keys that match one of the certificates.

3. `certreplace /path --name <common name> --cert <path>`

Like example 1, but will replace matches with the input certificate.

4. `certreplace /path --name <common name> --cert <path> --priv <path>`

Like example 3, but will try to replace the private keys of matches with the input privkey.

5. `certreplace /path --cert <path>`

Like example 3, but will match based on the common/alternative names in the input certificate.

6. `certreplace /path --cert <path> --priv <path>`

Like example 4, but will match based on the input certificate like example 5.

