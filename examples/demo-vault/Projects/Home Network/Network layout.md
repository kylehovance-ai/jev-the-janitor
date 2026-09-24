---
created: 2023-09-16
---
# Network layout

- Router: 192.168.10.1, DHCP 192.168.10.100 to .199.
- Server: 192.168.10.5 (static). Runs the backup job, the sensor database and the media share.
- Cameras: VLAN 20, 192.168.20.0/24, no route to the internet. See [[Camera VLAN decision]].
- Guest wifi: VLAN 30, 192.168.30.0/24, internet only.
- Greenhouse sensor node: 192.168.10.50, reports to the server every five minutes.
