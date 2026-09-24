---
created: 2023-09-29
---
# Sensor database

The greenhouse sensor node posts to a small Postgres on the server. Connection string for the dashboard script (local only, the database is not reachable from outside the LAN):

    postgres://greenhouse:Fak3Passw0rd@localhost:5432/sensors

Table `readings(at timestamptz, temp_c real, humidity real, soil real)`. One row every five minutes, about 105,000 rows a year. Vacuum monthly.

The dashboard reads the last 24 hours and draws three lines. Nothing clever.
