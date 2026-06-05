# ARPEX - Master System Design Document

## Project Name

```text
ARPEX
ARP Exploitation Detection & Response Platform
```

---

# Project Goal

ARPEX is a local-first cybersecurity monitoring platform designed to detect, verify, investigate, and track ARP spoofing attacks.

Primary Goal:

```text
Portfolio Project
```

Secondary Goal:

```text
Personal Network Security Tool
```

---

# Core Features

```text
✓ ARP Spoofing Detection
✓ Gateway Spoofing Detection
✓ Device Discovery
✓ Device Approval Workflow
✓ Active Network Discovery
✓ Offline Vendor Lookup
✓ Attacker Profiling
✓ Evidence Collection (PCAP)
✓ Historical Tracking
✓ Live Dashboard
✓ CSV Export
✓ Backup & Restore
```

---

# Technology Stack

```text
Backend:
- Python
- Scapy
- SQLite
- FastAPI

Frontend:
- HTML
- CSS
- JavaScript

Testing:
- Pytest

Deployment:
- Docker
```

---

# Project Structure

```text
ARPEX/
│
├── arpex/
│   ├── __init__.py
│   ├── detector.py
│   ├── fingerprint.py
│   ├── database.py
│   ├── alerts.py
│   ├── config.py
│   └── utils.py
│
├── dashboard/
│   ├── templates/
│   └── static/
│
├── tests/
│
├── captures/
├── logs/
├── data/
├── docker/
├── config/
│
├── main.py
├── requirements.txt
├── requirements-dev.txt
├── README.md
├── LICENSE
└── .gitignore
```

---

# Startup Flow

User runs:

```bash
python3 main.py
```

Startup Process:

```text
Load Configuration
        ↓
Load Database
        ↓
Validate Directories
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
        ↓
User Uses Dashboard
```

---

# First-Time Setup

On first launch:

```text
Devices Discovered
```

Example:

```text
Router
MacBook
Phone
Unknown Device
```

User may:

```text
Approve
Mark Suspicious
Block
```

Monitoring starts immediately even before approval.

---

# Detection Engine

File:

```text
arpex/detector.py
```

Responsibilities:

```text
Listen for ARP Traffic
Learn Device Mappings
Detect MAC Changes
Verify Suspicious Activity
Generate Events
```

---

# Detection Workflow

```text
ARP Packet Received
        ↓
Known Device?
        ↓
No
        ↓
NEW_DEVICE Event
        ↓
Store Device
```

or

```text
Known Device
        ↓
MAC Changed
        ↓
Verification ARP Request
        ↓
Verified
        ↓
ARP_SPOOFING Event
```

---

# Verification System

Before alerting:

```text
Who has IP?
```

ARPEX sends an ARP request.

Only verified attacks generate alerts.

---

# Event Types

```text
NEW_DEVICE
DEVICE_APPROVED
DEVICE_ONLINE
DEVICE_OFFLINE

ARP_SPOOFING
GATEWAY_SPOOFING
```

---

# Severity Levels

```text
LOW
MEDIUM
HIGH
CRITICAL
```

---

# Alert Cooldown

```text
10 Seconds
```

Duplicate attack alerts are suppressed.

---

# Active Discovery

Interval:

```text
10 Minutes
```

Purpose:

```text
Find Quiet Devices
Update Online Status
Maintain Inventory
```

---

# Device Lifecycle

```text
New Device
        ↓
Unapproved
        ↓
Trusted
```

or

```text
New Device
        ↓
Suspicious
```

or

```text
New Device
        ↓
Blocked
```

---

# Automatic Status Changes

```text
Trusted
        ↓
Attack Detected
        ↓
Suspicious
```

Automatic.

User may later:

```text
Trust
Block
```

manually.

---

# Database Tables

```text
devices
device_ip_history
attackers
attacks
events
```

---

# Device Identity

Primary Identity:

```text
MAC Address
```

A MAC change creates a new device.

---

# Device Information

Stored Data:

```text
MAC Address
Current IP
Hostname
Vendor
Device Name
Status

First Seen
Last Seen

Online Status
```

---

# IP History

ARPEX tracks:

```text
Current IP
Historical IPs
```

for every device.

---

# Vendor Lookup

Offline.

Uses local OUI database.

Example:

```text
00:50:56
↓
VMware
```

---

# Attacker Tracking

Stored Information:

```text
MAC Address
Hostname
Vendor

First Seen
Last Seen

Attack Count
Current Status
```

Retention:

```text
Forever
```

---

# Attack Records

Stored Information:

```text
Attack ID
Timestamp

Victim
Attacker

Severity
Verification Status

PCAP Evidence
```

Retention:

```text
30 Days
```

---

# Event Records

Stored Information:

```text
Timestamp
Type
Severity

Device

Message

Related Attack
```

Retention:

```text
60 Days
```

---

# Evidence System

Suspicious traffic only.

Storage:

```text
captures/
```

Example:

```text
ATT-000021.pcap
```

Dashboard supports:

```text
View Metadata
Download PCAP
```

---

# Dashboard Pages

```text
Dashboard
Devices
Attackers
Attacks
Events
Evidence
Settings
```

---

# Dashboard Home

Displays:

```text
Network Health

Devices Online

Trusted Devices
Suspicious Devices
Blocked Devices

Known Attackers

Recent Events

Recent Attacks
```

---

# Real-Time Updates

Dashboard updates automatically.

No page refresh required.

Updates include:

```text
New Devices
Device Status Changes
Events
Attacks
Alerts
```

---

# Alert Banner

When an attack occurs:

```text
Banner Appears
```

Displays:

```text
Severity
Victim
Attacker
```

Includes:

```text
View Details
```

Button.

Visible:

```text
4 Seconds
```

Then disappears.

Event remains stored.

---

# UI Design

Style:

```text
Retro UNIX
Retro Sysadmin Console
90s Technical Dashboard
```

Inspired by:

```text
Old Network Monitoring Tools
Terminal Interfaces
Classic Technical Software
```

---

# UI Rules

```text
Dark Olive Background
Light Green Text
Monospace Fonts

Square Borders
No Rounded Corners

No Gradients
No Glassmorphism

Information Dense
Text Focused
```

---

# Detail Views

Use Popups.

```text
Device Popup
Attacker Popup
Attack Popup
Event Popup
```

No separate detail pages.

---

# Search Features

Support:

```text
Search by IP
Search by MAC
Search by Hostname
Search by Vendor
Search by Device Name
Search by Attack ID
```

---

# Filtering Features

Support:

```text
Severity

Event Type

Status

Date Range

Online Devices

Offline Devices

Attackers
```

---

# Export Features

```text
Devices → CSV

Events → CSV

Attacks → CSV
```

---

# Backup Features

```text
Backup Database

Restore Database
```

via dashboard.

---

# Authentication

Version 1:

```text
Disabled
```

Deployment target:

```text
localhost
```

Future:

```text
Optional Authentication
```

---

# Excluded From V1

```text
Network Map

User Accounts

Cloud Sync

Remote Access

AI Analysis

Advanced Authentication
```

---

# Development Order

```text
1. database.py
2. detector.py
3. alerts.py
4. fingerprint.py
5. FastAPI Backend
6. Dashboard Frontend
7. Backup System
8. CSV Export
9. Docker
10. Tests
```

---

# Success Criteria

A successful ARPEX V1 should:

```text
Detect ARP Spoofing

Track Devices

Track Attackers

Store Evidence

Provide Real-Time Visibility

Look Professional

Demonstrate:
- Networking
- Cybersecurity
- Python
- Databases
- Web Development
```

while remaining understandable, maintainable, and deployable on a personal machine.
