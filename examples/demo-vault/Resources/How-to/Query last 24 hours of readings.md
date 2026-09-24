---
created: 2024-09-02
---
# Query last 24 hours of readings

```sql
SELECT at, temp_c FROM readings WHERE at > now() - interval '24 hours' ORDER BY at;
```
