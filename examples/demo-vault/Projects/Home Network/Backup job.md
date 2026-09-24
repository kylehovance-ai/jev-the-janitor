---
created: 2023-09-24
aliases: [Backups]
---
# Backup job

Nightly rsync from the server to the USB disk, then a weekly copy to the disk that lives at my sister's.

```sh
#!/bin/sh
set -e
SRC=/srv/data
DST=/mnt/backup
rsync -a --delete --exclude '*.tmp' "$SRC/" "$DST/"
date > "$DST/.last-run"
```

Bug fixed on 2024-11-02: the exclude pattern was `'*.tmp*'` with a trailing star, which matched the `photos.tmp-migration` directory and skipped three weeks of photos. Now `'*.tmp'` exactly.

Restore test: monthly, one random file, from each disk.
