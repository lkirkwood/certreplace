# Requirements
---

- Discovers certificates from likely locations, or optionally additional paths.
- Replaces discovered certificates with those provided by the user, 
**only** if they match the common name extracted from the new certificates.
- Creates backups of the original certificates, using a naming scheme that allows this process to be repeated without losing previous backups.