# Using rdedup with rbup for regular backups

This is a simple example of a script used to backup regularly with rbup as the
utility stream the file / folder structure as well as the data into a ```name```
in your rdedup repo.

Script:
```bash
#!/bin/bash

stamp=$(date +"%y-%m-%d")
base="home"

rdup -cv /dev/null /path/to/backup | rdedup store $base-$stamp
```

This script creates a new name using the timestamp at the end to differentiate
it from previous backups. rdedup will ignore duplicate data being sent to it so
each run of this script will create a full backup of the data but only store a
single reference to duplicate data in the repo meaning that only different data
is actually stored on disk.

rdedup will output statistics of the run into the
console so you can see the number of new chunks and new bytes that have been
written to your repo.


## Restoring the data
To restore the data the command is simple. You can create it as a script if you
want to abstract the slightly complex command.

To restore a name from rdedup what has used rbup run the following:
```bash
rdedup load name | rdup-up "/path/to/restore/to"
```
*Replace name with the name in the repo that has the point in time you want the
data from*
