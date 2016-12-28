# (unreleased)
- Added support to remove multiple names in a single call in lib and command line
- Added missing "changepassphrase" command to rdedup
- Added improved stats to store, du, gc api calls and commands
- Added changelog to repository

# v1.0.1
- Cleaned up code by removing unnecessary code and utilizing constants as well as
running rustfmt on the code base.
- Reduced memory consumption by shrinking channels for store pipeline
- Added ability to change the passphrase for the private key
- Ignore invalid files in chunk and index folders and assembling chunks list
- Deferred syncing and renaming of new chunks to optimize file io


# v1.0.0
- Started changelog, see commits for details leading up to this release
