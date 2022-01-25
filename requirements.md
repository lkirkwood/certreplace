# Requirements
---

- Discovers certificates in the specified location.
- Replaces discovered certificates with those provided by the user, 
**only** if they match the common name specified.
- Creates backups of the original certificates, using a naming scheme that allows this process to be repeated without losing previous backups.