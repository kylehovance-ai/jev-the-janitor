---
created: 2024-02-13
---
# Postgres vacuum for the rest of us

Autovacuum usually suffices; a manual vacuum after a big delete reclaims the space sooner.

- Added a monthly vacuum to cron and stopped worrying.
- Applies to: [[Sensor database]].
