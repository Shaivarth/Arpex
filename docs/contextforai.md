# ARPEX Project Continuation Context

## Project Overview

ARPEX (ARP Exploitation Detection & Response Platform) is a local-first cybersecurity application designed to detect, verify, investigate, and track ARP spoofing attacks on a LAN.

Primary purpose:

* Portfolio-grade cybersecurity project
* Demonstrate networking, cybersecurity, Python, databases, testing, and web development skills

Secondary purpose:

* Real personal network monitoring tool

---

# Current Development Status

Development is currently in the implementation phase.

Planning phase is complete.

Architecture is frozen unless a major issue is discovered.

The project is being built incrementally:

Design → Implement → Test → Continue

Each module is fully tested before moving to the next.

---

# Technology Stack

Backend:

* Python 3.12+
* SQLite
* FastAPI (later)
* Scapy (later)

Frontend:

* HTML
* CSS
* JavaScript

Testing:

* Pytest

Deployment:

* Docker

---

# Project Structure

ARPEX/

├── arpex/
│   ├── **init**.py
│   ├── database.py
│   ├── detector.py
│   ├── fingerprint.py
│   ├── alerts.py
│   ├── config.py
│   └── utils.py
│
├── tests/
│
├── captures/
├── logs/
├── data/
├── config/
├── docker/
│
├── main.py
├── README.md
└── requirements.txt

---

# Overall Architecture

Startup:

python3 main.py

Flow:

Load Config
↓
Initialize Database
↓
Detect Active Interface
↓
Start Detector
↓
Start Active Discovery
↓
Start Dashboard
↓
Open Browser Automatically

After startup, everything is controlled from the web dashboard.

No CLI interaction after launch.

---

# Dashboard Design

Pages:

* Dashboard
* Devices
* Attackers
* Attacks
* Events
* Evidence
* Settings

---

# UI Style

The project intentionally uses a retro UNIX/sysadmin interface.

Design requirements:

* Dark olive background
* Green/light text
* Monospace font
* Square borders
* No rounded corners
* No glassmorphism
* No modern SaaS style

Visual inspiration:

Old network monitoring tools and UNIX administration consoles.

---

# Device Lifecycle

New Device
↓
UNAPPROVED

User may:

* Approve
* Mark Suspicious
* Block

Monitoring starts immediately even before approval.

Status progression:

TRUSTED
↓
Attack Detected
↓
SUSPICIOUS

Automatic transition only in this direction.

Returning to TRUSTED or BLOCKED is manual.

---

# Detection Philosophy

ARPEX must not blindly trust ARP packets.

Verification is required.

Detection flow:

ARP Packet
↓
Mapping Changed
↓
Verification ARP Request
↓
Verified
↓
Attack Recorded

Only verified attacks create alerts.

---

# Database Status

database.py is COMPLETE (V1).

Implemented and tested:

✓ Schema creation
✓ Index creation
✓ Device API
✓ IP history tracking
✓ Attacker API
✓ Attack API
✓ Event API
✓ Search API
✓ Filtering API
✓ CSV Export
✓ Backup
✓ Restore
✓ Retention cleanup

Tests currently pass.

pytest result:

4 passed

---

# Database Tables

devices

Stores:

* MAC address
* Current IP
* Hostname
* Vendor
* Device name
* Approval status
* Status
* Online state
* First seen
* Last seen

device_ip_history

Stores:

* Historical IP addresses

attackers

Stores:

* MAC
* Vendor
* Hostname
* Attack count
* First seen
* Last seen

attacks

Stores:

* ATT-XXXXXX ID
* Severity
* Victim
* Attacker
* Verification status
* PCAP evidence

events

Stores:

* Event timeline
* Dashboard feed

---

# Retention Policies

Devices:
Forever

IP History:
Forever

Attackers:
Forever

Attacks:
30 Days

Events:
60 Days

---

# Search Features

Implemented:

search_devices()

search_attackers()

search_attacks()

search_events()

Filtering:

filter_devices()

filter_attacks()

filter_events()

---

# Evidence System

Evidence files stored in:

captures/

Example:

ATT-000021.pcap

Dashboard supports:

* Metadata viewing
* Downloading PCAP

---

# Backup System

Implemented:

create_backup()

restore_backup()

Database backups use SQLite file copies.

---

# Testing Philosophy

Each module must be tested before moving forward.

Tests use a dedicated temporary database.

Tests must not share state.

Avoid test contamination.

---

# Development Order

Original plan:

1. database.py
2. detector.py
3. alerts.py
4. fingerprint.py
5. FastAPI Backend
6. Dashboard Frontend
7. Backup System
8. Docker
9. Tests

However, after database completion, the next module chosen is:

fingerprint.py

before detector.py.

Reason:

detector.py depends on vendor identification.

fingerprint.py will provide:

* Vendor lookup
* OUI database support
* Device identification helpers

---

# fingerprint.py Goals

Purpose:

Identify vendors from MAC addresses.

Examples:

00:50:56
→ VMware

00:1A:79
→ Apple

Requirements:

* Offline operation
* No external API calls
* Local OUI database
* Fast lookups
* Reusable by detector.py

Expected functions:

lookup_vendor()

normalize_mac()

load_oui_database()

Potential future additions:

* Device fingerprinting
* Host classification
* Manufacturer statistics

---

# Coding Style Requirements

Important:

Do NOT generate huge files at once.

Work incrementally.

For each module:

1. Design
2. Implement part
3. Compile
4. Test
5. Continue

Comments should be meaningful.

Avoid decorative comment separators everywhere.

Code should prioritize:

1. Maintainability
2. Simplicity
3. Correctness
4. Performance

---

# Current Next Task

Next file:

arpex/fingerprint.py

Goal:

Design and implement an offline MAC vendor lookup system that will later be used by detector.py for device discovery and attacker profiling.

The database layer is considered complete and should not require architectural changes unless a bug is discovered.
