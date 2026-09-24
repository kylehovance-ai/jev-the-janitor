---
created: 2023-10-04
---
# Network troubleshooting log

Every outage and what fixed it. Long, on purpose: the pattern is the point, and the pattern is that I had forgotten the last time.

## 2024-01-30: wifi drops on the top floor every evening

Symptom: wifi drops on the top floor every evening. Went straight to the router log this time.

Cause: the neighbour's access point had moved onto our channel around dinner time.

Fix: fixed channel 36 instead of auto; the drops stopped the same night.

Time lost: ten minutes, for once.

## 2024-02-14: server unreachable after a power cut

Symptom: server unreachable after a power cut. Blamed the ISP for the first half hour.

Cause: the USB disk mounted before the network was up and the backup timer hung on a stale mount.

Fix: nofail in fstab and a 30-second delay on the timer.

Time lost: two hours.

## 2024-04-05: cameras all offline at once

Symptom: cameras all offline at once. Restarted the wrong thing twice.

Cause: the VLAN 20 lease had expired and the reservation carried a typo in one MAC octet.

Fix: corrected the MAC; leases renewed within a minute.

Time lost: most of an evening.

## 2024-04-06: guest wifi with no internet

Symptom: guest wifi with no internet. Started with the last thing I had changed, which was it.

Cause: the isolate-clients flag also isolated the gateway after the firmware update.

Fix: re-added the gateway exception under the flag.

Time lost: ten minutes, for once.

## 2024-05-02: printer works from the laptop, not from the phone

Symptom: printer works from the laptop, not from the phone. Restarted the wrong thing twice.

Cause: mDNS does not cross VLANs, and the phone was on the guest network.

Fix: phone onto the main wifi; guests do not print, and that is fine.

Time lost: an hour.

## 2024-06-04: sensor node stops reporting at 3 am

Symptom: sensor node stops reporting at 3 am. Asked the household what they had changed. Nothing, they said, accurately.

Cause: the router's scheduled reboot took the node's lease with it.

Fix: reboot moved to 4:30 and the node given a retry loop.

Time lost: half a Saturday.

## 2024-06-19: backup disk full

Symptom: backup disk full. Assumed the disk had died; it had not.

Cause: snapshots had never been pruned.

Fix: keep 14 daily and 8 weekly; a weekly cron does the pruning.

Time lost: an hour.

## 2024-06-30: dashboard empty

Symptom: dashboard empty. Restarted the wrong thing twice.

Cause: Postgres had run out of disk after the log table grew for a year.

Fix: vacuumed, and a monthly vacuum in cron.

Time lost: an hour.

## 2024-07-05: file copies to the share crawl

Symptom: file copies to the share crawl. Asked the household what they had changed. Nothing, they said, accurately.

Cause: the cable behind the desk was a 100 Mbit patch lead from a drawer.

Fix: a proper lead; 940 Mbit after.

Time lost: ten minutes, for once.

## 2024-08-05: router admin page unreachable

Symptom: router admin page unreachable. Went straight to the router log this time.

Cause: I had changed the admin address months ago and remembered the old one.

Fix: it is 192.168.10.1; written in [[Network layout]].

Time lost: twenty minutes.

## 2024-09-02: laptop forgets the wifi after sleep

Symptom: laptop forgets the wifi after sleep. Asked the household what they had changed. Nothing, they said, accurately.

Cause: power management on the wifi card, a default.

Fix: turned it off in the driver settings.

Time lost: an hour.

## 2024-09-13: time on the server drifts

Symptom: time on the server drifts. Started with the last thing I had changed, which was it.

Cause: NTP was pointed at a host that no longer answers.

Fix: pool servers instead; drift gone.

Time lost: an hour.

## 2024-09-17: sensor readings arrive twice

Symptom: sensor readings arrive twice. Assumed the disk had died; it had not.

Cause: the node retried on a timeout that was really a slow ack.

Fix: idempotent insert keyed on the timestamp.

Time lost: twenty minutes.

## 2025-02-16: share unreachable from the phone

Symptom: share unreachable from the phone. Started with the last thing I had changed, which was it.

Cause: the SMB version the phone app speaks was disabled.

Fix: enabled SMB2 minimum; SMB1 stays off.

Time lost: most of an evening.

## 2025-03-03: router reboots at random

Symptom: router reboots at random. Blamed the ISP for the first half hour.

Cause: overheating in the cupboard; the vent slots were behind a box.

Fix: moved the box; a small fan later.

Time lost: twenty minutes.

## 2025-03-12: wifi slow when the microwave runs

Symptom: wifi slow when the microwave runs. Read the log instead of guessing, which is new.

Cause: 2.4 GHz interference, as everyone says.

Fix: moved the living-room devices to 5 GHz.

Time lost: ten minutes, for once.

## 2025-04-06: backup job runs twice a night

Symptom: backup job runs twice a night. Restarted the wrong thing twice.

Cause: two timers, one from an old install.

Fix: removed the stale timer file.

Time lost: half a Saturday.

## 2025-04-30: camera stream stutters

Symptom: camera stream stutters. Blamed the ISP for the first half hour.

Cause: the switch port had negotiated half duplex.

Fix: forced full duplex on that port; a new cable later.

Time lost: twenty minutes.

## 2025-06-15: guest devices see the printer

Symptom: guest devices see the printer. Went straight to the router log this time.

Cause: the guest VLAN had a static route left from testing.

Fix: removed the route.

Time lost: an hour.

## 2025-08-28: server disk warning at 90%

Symptom: server disk warning at 90%. Restarted the wrong thing twice.

Cause: the media share had grown with a phone backup nobody asked for.

Fix: moved the phone backup to the backup disk.

Time lost: an hour.

## 2025-09-02: dashboard shows the wrong day

Symptom: dashboard shows the wrong day. Went straight to the router log this time.

Cause: the container's timezone was UTC while the node stamps local.

Fix: everything in UTC now; the chart labels convert.

Time lost: ten minutes, for once.

## 2025-09-11: no DHCP for new devices

Symptom: no DHCP for new devices. Asked the household what they had changed. Nothing, they said, accurately.

Cause: the lease pool of a hundred addresses was full of dead leases.

Fix: shortened the lease time to 12 hours.

Time lost: two hours.

## 2025-11-15: wifi password rejected on a new phone

Symptom: wifi password rejected on a new phone. Restarted the wrong thing twice.

Cause: the printed card had the old password from before the spring rotation.

Fix: reprinted the card; the manager was right all along.

Time lost: half a Saturday.

## 2026-02-13: cannot reach the router from VLAN 30

Symptom: cannot reach the router from VLAN 30. Started with the last thing I had changed, which was it.

Cause: by design, then forgotten.

Fix: nothing to fix; wrote it down.

Time lost: an hour.

## 2026-02-16: sensor node reboots when the greenhouse fan starts

Symptom: sensor node reboots when the greenhouse fan starts. Restarted the wrong thing twice.

Cause: voltage dip on the shared supply.

Fix: separate supply for the node.

Time lost: twenty minutes.

## 2026-03-18: backup restore test fails on one file

Symptom: backup restore test fails on one file. Checked the cables first, then the lights, then rebooted everything, which fixed nothing.

Cause: a filename with a character the off-site disk's filesystem refuses.

Fix: renamed the file; the disk is exFAT and stays that way.

Time lost: an hour.

## 2026-04-04: router firmware update stuck at 40%

Symptom: router firmware update stuck at 40%. Went straight to the router log this time.

Cause: the update needs a wired client and I was on wifi.

Fix: did it from the laptop on a cable.

Time lost: most of an evening.

## 2026-04-14: server fan loud at night

Symptom: server fan loud at night. Blamed the ISP for the first half hour.

Cause: the fan curve defaulted after a firmware update.

Fix: set the curve again and wrote the settings down.

Time lost: ten minutes, for once.

## 2026-05-20: share mounts read-only after a crash

Symptom: share mounts read-only after a crash. Checked the cables first, then the lights, then rebooted everything, which fixed nothing.

Cause: the disk's journal needed a check.

Fix: fsck, then a clean mount; the crash was the power cut above.

Time lost: ten minutes, for once.

## 2026-07-07: phone app for the cameras does not work away from home

Symptom: phone app for the cameras does not work away from home. Went straight to the router log this time.

Cause: by design: VLAN 20 has no route out.

Fix: nothing to fix; see [[Camera VLAN decision]].

Time lost: a lunch break.

## Short entries

One-liners from the notebook, mostly things that fixed themselves or needed a cable.
- 2024-03-22: switch port 4 dead; moved to 5
- 2024-04-28: laptop wifi: forget and rejoin
- 2024-06-04: sensor node: battery in the clock
- 2024-07-11: printer: power cycle, as ever
- 2024-08-17: guest wifi: password on the card was right, the guest typed 0 for O
- 2024-09-23: server: full /tmp after a failed download
- 2024-10-30: router: reboot after 90 days uptime, then fine
- 2024-12-06: backup: disk not spun up in time; second attempt fine
- 2025-01-12: dashboard: browser cache
- 2025-02-18: cameras: one lens fogged, not a network problem at all
- 2025-03-27: share: a stale lock file from the crash
- 2025-05-03: wifi: the microwave again
- 2025-06-09: node: loose header pin
- 2025-07-16: router: DNS cache after the ISP changed resolvers
- 2025-08-22: server: NTP again, after the pool changed
- 2025-09-28: printer: mDNS, phone on the wrong wifi again
- 2025-11-04: backup: the off-site disk was at my sister's
- 2025-12-11: switch: a kink in the cable behind the desk
- 2026-01-17: dashboard: the container restarted with the old image
- 2026-02-23: cameras: PoE budget exceeded when the fourth one was added

## Patterns

- Half of these were something I had changed and forgotten. The log exists so the next one takes ten minutes.
- A quarter were cables. Buy good cables and label them.
- The rest were defaults: lease times, power management, timezones, fan curves.
- Nothing here was the ISP, ever, despite how often I blamed them.

## Device inventory

| device | address | VLAN | note |
|---|---|---|---|
| router | 192.168.10.1 | 10 | the one with the VLAN support; replaced the old box in 2023 |
| switch, 8 port | 192.168.10.2 | 10 | PoE on ports 1 to 4 for the cameras |
| server | 192.168.10.5 | 10 | backup, sensor database, media share |
| printer | 192.168.10.7 | 10 | reserved; mDNS only on this VLAN |
| sensor node | 192.168.10.50 | 10 | greenhouse; posts every five minutes |
| laptop | dhcp | 10 | wifi; power management off |
| phone A | dhcp | 10 | main wifi so it can print |
| phone B | dhcp | 30 | guest by choice; cannot print, does not mind |
| camera, front | 192.168.20.11 | 20 | PoE port 1 |
| camera, back | 192.168.20.12 | 20 | PoE port 2 |
| camera, side | 192.168.20.13 | 20 | PoE port 3 |
| camera, greenhouse | 192.168.20.14 | 20 | PoE port 4; the fourth one exceeded the PoE budget once |
| access point, upstairs | 192.168.10.3 | 10 | channel 36, fixed |
| access point, downstairs | 192.168.10.4 | 10 | channel 44, fixed |
| TV | dhcp | 30 | guest VLAN; it phones home enough already |
| thermostat | dhcp | 30 | guest VLAN, internet only |
| off-site backup disk | none | none | lives at my sister's; swapped quarterly |
| USB backup disk | none | none | on the server; nightly rsync |

## Monthly checks

- restore one random file from each backup disk
- check the snapshot count is 14 daily and 8 weekly
- vacuum the sensor database
- read the router log for anything repeating
- confirm the cameras still have no route out (curl from VLAN 20 must fail)
- check the server disk is under 80%
- rotate the guest wifi password in spring and autumn
- test the smoke alarm, which is not network but lives on this list
- check NTP drift on the server
- update the router firmware if there is one, from a cable
- reprint the guest card if the password rotated
- swap the off-site disk when visiting my sister

## Firmware and updates

- 2024-01-02: router firmware, security fix; rebooted twice
- 2024-02-10: server kernel update; the fan curve reset (see the entry above)
- 2024-03-20: camera firmware, all four; the stutter got better
- 2024-04-28: switch firmware; no visible change
- 2024-06-06: access point firmware; channel setting survived
- 2024-07-15: server: Postgres minor version
- 2024-08-23: server: rsync version bump, exclude patterns unchanged
- 2024-10-01: router: DNS resolver list refreshed after the ISP changed theirs
- 2024-11-09: sensor node: new build with the retry loop
- 2024-12-18: dashboard container rebuilt with UTC
- 2025-01-26: laptop wifi driver; power management setting had to be redone
- 2025-03-06: server: fstab nofail added
- 2025-04-14: router: lease time to 12 hours
- 2025-05-23: switch: port 3 forced full duplex
- 2025-07-01: server: NTP pool servers
- 2025-08-09: camera, greenhouse: PoE budget fixed by moving it to port 4 alone
- 2025-09-17: router: guest VLAN static route removed
- 2025-10-26: server: SMB2 minimum enabled
- 2025-12-04: sensor node: separate supply
- 2026-01-12: router: reboot moved to 4:30
- 2026-02-20: backup: weekly cron for pruning
- 2026-03-31: dashboard: cache-busting header
- 2026-05-09: printer: fixed address reserved
- 2026-06-17: server: /tmp cleared and a tmpfiles rule added

## What I would do differently

- Buy the switch with more PoE budget the first time; the fourth camera cost a weekend.
- Label every cable at both ends before it goes behind the desk.
- Put the router where it can breathe; the cupboard was a mistake I still live with.
- Keep the config in this vault from day one, not after the first dead router.
- One VLAN for cameras is right; a VLAN for the TV and the thermostat was worth it too.
- Write the restore test into the calendar, not into good intentions.
- Fixed channels on the access points from the start; auto was never right in this street.
- A UPS for the server, so the power cut entry above never happens again.
- Reserve addresses for anything that needs finding; DHCP for anything that does not.
- The dashboard wanted to be clever and I let it, for a month. Three lines is enough.

## Config fragments kept for reference

| where | the setting, in words |
|---|---|
| rsync exclude | --exclude '*.tmp' exactly; no trailing star |
| fstab | UUID=... /mnt/backup ext4 defaults,nofail 0 2 |
| systemd timer | OnCalendar=*-*-* 02:30:00 with a 30 s ExecStartPre sleep |
| router: vlan 20 | no ip route 0.0.0.0/0; isolate from 10 and 30 |
| router: reboot | weekly, Sunday 04:30, not 03:00 |
| postgres | autovacuum on; a monthly VACUUM ANALYZE readings by cron anyway |
| node | POST every 300 s; retry 3 times with 10 s backoff; idempotent on timestamp |
| access points | channels 36 and 44 fixed, 80 MHz, power medium |
| dhcp | lease 12h; reservations for .5 .7 .50 and the four cameras |
| smb | min protocol SMB2; guest disabled; one share, one user |
| ntp | pool servers, four of them; drift checked monthly |
| dashboard | reads the last 24 h, three lines, UTC labels converted in the browser |

## Numbers worth keeping

- The backup disk holds 14 daily and 8 weekly snapshots and sits at about 60% after pruning.
- The sensor database grows by roughly 105,000 rows a year and stays under a gigabyte.
- Copies to the share run at 940 Mbit on the good cable and 94 on the bad one; the difference is the whole story of that cable.
- The router has rebooted on schedule 140 times and unexpectedly four, three of them heat.
- Four cameras draw about 26 W together; the switch's PoE budget is 30 W, which is why the fourth was a problem.
- The guest VLAN has seen 31 distinct devices in two years, most of them once.
- Restore tests: 26 run, 25 passed, the one failure was the exFAT filename above.
- Time lost to network problems in year one: about 30 hours. Year two: about 6. This log is most of the difference.
