---
created: 2023-09-18
---
# Router config

The bits of the router config I always need again.

```
interface vlan20
  description cameras
  ip address 192.168.20.1/24
  no ip route 0.0.0.0/0
interface vlan30
  description guests
  ip address 192.168.30.1/24
  isolate-clients
```

DHCP reservations: server 192.168.10.5, printer 192.168.10.7, sensor node 192.168.10.50.

Admin login is the usual local account. The password is in the password manager, not here.
