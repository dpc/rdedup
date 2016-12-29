# (unreleased)
## Added
- Support to remove multiple names in a single call in lib and command line
- Missing "changepassphrase" command to rdedup
- Improved stats to store, du, gc api calls and commands
- Changelog to repository

# v1.0.1
## Added
- Ability to change the passphrase for the private key

## Changed
- Cleaned up code by removing unnecessary code and utilizing constants as well as
running rustfmt on the code base.
- Reduced memory consumption by shrinking channels for store pipeline
- Ignore invalid files in chunk and index folders and assembling chunks list
- Deferred syncing and renaming of new chunks to optimize file io

# v1.0.0
- Started changelog, see commits for details leading up to this release
