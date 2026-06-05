# ARPEX Database Design

## File

```text
arpex/database.py
```

## Purpose

The database is the permanent memory of ARPEX.

Responsibilities:

* Store devices
* Store IP history
* Store attackers
* Store attacks
* Store events
* Support dashboard queries
* Support filtering and searching
* Maintain historical records

The database does NOT:

* Detect attacks
* Capture packets
* Send alerts
* Render UI

---

# Database Engine

```text
SQLite
```

Database file:

```text
data/arpex.db
```

---

# Table: devices

Purpose:

Store all approved and discovered devices.

```sql
devices
```

| Column           | Type     | Notes                          |
| ---------------- | -------- | ------------------------------ |
| id               | INTEGER  | Primary Key                    |
| mac_address      | TEXT     | UNIQUE                         |
| current_ip       | TEXT     | Current IP                     |
| hostname         | TEXT     | Nullable                       |
| vendor           | TEXT     | Nullable                       |
| device_name      | TEXT     | User-defined name              |
| status           | TEXT     | Trusted / Suspicious / Blocked |
| first_seen       | DATETIME | First appearance               |
| last_seen        | DATETIME | Most recent appearance         |
| currently_online | BOOLEAN  | Current status                 |

---

# Table: device_ip_history

Purpose:

Track all IP addresses ever used by a device.

```sql
device_ip_history
```

| Column     | Type     |
| ---------- | -------- |
| id         | INTEGER  |
| device_id  | INTEGER  |
| ip_address | TEXT     |
| first_seen | DATETIME |
| last_seen  | DATETIME |

Relationship:

```text
device_id
↓
devices.id
```

---

# Table: attackers

Purpose:

Track attacker identities and statistics.

```sql
attackers
```

| Column           | Type        |
| ---------------- | ----------- |
| id               | INTEGER     |
| mac_address      | TEXT UNIQUE |
| hostname         | TEXT NULL   |
| vendor           | TEXT        |
| first_seen       | DATETIME    |
| last_seen        | DATETIME    |
| attack_count     | INTEGER     |
| currently_active | BOOLEAN     |

Retention:

```text
Forever
```

---

# Table: attacks

Purpose:

Store detailed forensic attack records.

```sql
attacks
```

| Column              | Type        |
| ------------------- | ----------- |
| id                  | INTEGER     |
| attack_id           | TEXT UNIQUE |
| timestamp           | DATETIME    |
| event_type          | TEXT        |
| severity            | TEXT        |
| verification_status | TEXT        |
| victim_ip           | TEXT        |
| victim_mac          | TEXT        |
| victim_vendor       | TEXT        |
| attacker_mac        | TEXT        |
| attacker_vendor     | TEXT        |
| interface           | TEXT        |
| pcap_file           | TEXT        |
| notes               | TEXT        |

Example:

```text
ATT-000021
```

Retention:

```text
30 Days
```

---

# Table: events

Purpose:

Power the live dashboard timeline.

```sql
events
```

| Column            | Type      |
| ----------------- | --------- |
| id                | INTEGER   |
| timestamp         | DATETIME  |
| event_type        | TEXT      |
| severity          | TEXT      |
| device_mac        | TEXT      |
| device_ip         | TEXT      |
| message           | TEXT      |
| related_attack_id | TEXT NULL |
| metadata          | TEXT NULL |

Example Events:

```text
NEW_DEVICE

DEVICE_APPROVED

DEVICE_ONLINE

DEVICE_OFFLINE

ARP_SPOOFING

GATEWAY_SPOOFING
```

Retention:

```text
60 Days
```

---

# Device Status Values

```text
TRUSTED

SUSPICIOUS

BLOCKED
```

---

# Event Severity Values

```text
LOW

MEDIUM

HIGH

CRITICAL
```

---

# Verification Status Values

```text
VERIFIED

UNVERIFIED
```

---

# Search Requirements

Database must support:

```text
Search by IP

Search by MAC

Search by Hostname

Search by Device Name

Search by Vendor

Search by Attack ID
```

---

# Dashboard Filtering Requirements

```text
Filter by Severity

Filter by Event Type

Filter by Device Status

Filter by Date Range

Filter by Online Devices

Filter by Offline Devices

Filter by Attacker
```

---

# Retention Policy

```text
devices
→ Forever

device_ip_history
→ Forever

attackers
→ Forever

attacks
→ 30 Days

events
→ 60 Days
```

---

# Recommended Indexes

```sql
CREATE INDEX idx_devices_mac
ON devices(mac_address);

CREATE INDEX idx_devices_ip
ON devices(current_ip);

CREATE INDEX idx_events_timestamp
ON events(timestamp);

CREATE INDEX idx_attacks_attack_id
ON attacks(attack_id);

CREATE INDEX idx_attackers_mac
ON attackers(mac_address);
```

---

# Future Dashboard Features Supported

```text
Live Activity Feed

Device Inventory

Historical Devices

Known Attackers

Attack Timeline

Attack Search

Advanced Filters

Device Search

Evidence Viewer

Statistics Panels
```

---

# Project Philosophy

The database must prioritize:

```text
Simplicity
↓
Maintainability
↓
Performance
↓
Future Expansion
```

This schema is designed for a portfolio-grade cybersecurity project while remaining practical for real-world personal use.
