---
created: 2026-04-06
---
# Prune the backup snapshots

```sh
find /mnt/backup/snapshots -maxdepth 1 -mtime +14 -type d -exec rm -r {} +
```
Keep 14 daily. The weekly ones live elsewhere.
