# ARPEX Development Context (Post-Database Phase)

## Current Project Status

ARPEX is currently in active development.

Completed modules:

✓ database.py (Complete V1)
✓ fingerprint.py (Complete V1)

Next module:

→ detector.py

---

# Completed Module: database.py

The database layer is considered complete.

Implemented:

* SQLite backend
* Schema creation
* Index creation
* Device management
* IP history tracking
* Attacker management
* Attack management
* Event management
* Search APIs
* Filter APIs
* CSV exports
* Database backup
* Database restore
* Retention cleanup

---

# Database Tables

## devices

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
* Gateway flag

Status values:

* TRUSTED
* SUSPICIOUS
* BLOCKED

Approval values:

* APPROVED
* UNAPPROVED

---

## device_ip_history

Stores:

* Device ID
* Historical IP addresses
* First seen
* Last seen

Retention:

Forever

---

## attackers

Stores:

* MAC address
* Vendor
* Hostname
* Attack count
* Active state
* First seen
* Last seen

Retention:

Forever

---

## attacks

Stores:

* ATT-XXXXXX identifier
* Severity
* Verification status
* Victim information
* Attacker information
* Interface
* PCAP evidence path
* Notes

Retention:

30 Days

Attack IDs never reuse old numbers.

Example:

ATT-000001
ATT-000002
ATT-000003

---

## events

Stores:

* Timeline events
* Severity
* Message
* Related attack
* Metadata

Retention:

60 Days

---

# Search & Filtering

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

# Backup System

Implemented:

create_backup()
restore_backup()

---

# Export System

Implemented:

export_devices_csv()
export_attacks_csv()
export_events_csv()

---

# Cleanup System

Implemented:

cleanup_old_attacks()
cleanup_old_events()
run_cleanup_tasks()

---

# Database Testing Status

Current tests:

✓ Device creation
✓ Attacker creation
✓ Attack creation
✓ Event creation
✓ Backup creation

Result:

4 passed

Database considered stable.

---

# Completed Module: fingerprint.py

Purpose:

Offline MAC vendor identification.

No internet dependency.

No external APIs.

---

# OUI Storage

Location:

config/oui.json

Example:

{
"005056": "VMware",
"001A79": "Apple"
}

Loaded once at startup.

Cached in memory.

---

# FingerprintManager

Implemented:

load_oui_database()
reload_database()

normalize_mac()

extract_oui()

lookup_vendor()

database_loaded()

total_vendors()

---

# MAC Normalization Rules

Supported:

00:50:56:AA:BB:CC
00-50-56-AA-BB-CC
005056AABBCC
00:50:56:aa:bb:cc

All become:

00:50:56:AA:BB:CC

---

# Vendor Lookup Rules

Known OUI:

Returns vendor name.

Unknown OUI:

Returns:

"Unknown"

Invalid MAC:

Returns:

"Unknown"

Missing oui.json:

* Warning logged
* Empty cache loaded
* Application continues running

No exceptions raised.

---

# Fingerprint Testing Status

Current tests:

✓ MAC normalization
✓ Invalid MAC handling
✓ OUI extraction
✓ Vendor lookup
✓ Unknown vendor lookup
✓ Invalid vendor lookup

Result:

6 passed

Fingerprint module considered complete for V1.

---

# Total Test Status

Database tests:

4 passed

Fingerprint tests:

6 passed

Total:

10 passing tests

0 failures

---

# Next Module: detector.py

This is the core cybersecurity component.

Detector is responsible for:

* Network monitoring
* ARP inspection
* Mapping verification
* Attack detection
* Evidence generation
* Event creation

Detector is NOT responsible for:

* Database schema
* Dashboard rendering
* Vendor lookup logic

It may use those systems.

---

# Detector Architecture

Class:

class Detector

Primary methods planned:

start()
stop()

process_packet()

verify_mapping()

handle_attack()

capture_evidence()

---

# Detector Runtime State

Detector maintains:

self.running

self.interface

self.database

self.fingerprint

self.gateway_ip

self.gateway_mac

self.ip_mac_cache

self.detector_thread

---

# Startup Workflow

Application startup:

Load Config
↓
Initialize Database
↓
Load OUI Database
↓
Detect Active Interface
↓
Detect Default Gateway
↓
Resolve Gateway MAC
↓
Active Network Discovery
↓
Build Baseline
↓
Store Devices
↓
Start Detector Thread
↓
Start Dashboard

Everything after startup is controlled through the web dashboard.

---

# Gateway Handling

Gateway is automatically detected.

No manual configuration required.

Process:

Read Routing Table
↓
Get Default Gateway
↓
Resolve Gateway MAC
↓
Store Device
↓
Mark:

is_gateway = True

Future settings page may allow manual override.

---

# Baseline Creation

Detector does not begin monitoring blindly.

Startup process:

ARP Sweep
↓
Discover Devices
↓
Build Initial IP→MAC Map
↓
Cache Known State

Example:

192.168.1.1 → Gateway MAC
192.168.1.10 → Laptop MAC
192.168.1.15 → Phone MAC

---

# New Device Handling

New device discovered:

Create Device Record
↓
Create Event

Event:

NEW_DEVICE

Severity:

LOW

No attack record created.

No alert generated.

User later decides:

APPROVE
SUSPICIOUS
BLOCK

---

# Detection Philosophy

Never trust a single ARP packet.

Bad:

ARP Packet
↓
Attack

Correct:

ARP Packet
↓
Mapping Change
↓
Verification
↓
Decision

---

# Mapping Change Detection

Monitor:

IP → MAC

Example:

Before:

192.168.1.1
↓
AA:AA:AA:AA:AA:AA

After:

192.168.1.1
↓
BB:BB:BB:BB:BB:BB

↓

Verification triggered immediately.

No waiting period.

---

# Verification Strategy

Verification occurs immediately.

Three independent ARP verification requests.

Example:

Attempt 1 → Gateway MAC
Attempt 2 → Gateway MAC
Attempt 3 → Attacker MAC

Majority decision wins.

Verification uses:

3 attempts

with short timeout.

---

# Severity Rules

Verified attack:

Victim = Gateway

↓

Event Type:

GATEWAY_SPOOFING

Severity:

CRITICAL

Otherwise:

ARP_SPOOFING

Severity:

HIGH

---

# Cache Handling

After verification:

Detector updates cache.

Example:

Old:

192.168.1.1
→ AA

Verified:

192.168.1.1
→ BB

Cache becomes:

192.168.1.1
→ BB

This prevents endless duplicate detections.

---

# Evidence Strategy

Attack confirmed:

Capture forensic evidence.

Store:

captures/ATT-XXXXXX.pcap

Database:

attacks.pcap_file

stores path.

Purpose:

Evidence viewing
Evidence download
Wireshark analysis

---

# Evidence Scope

Not continuous packet capture.

Only forensic snapshot.

Target:

~200 packets

around attack occurrence.

Small enough for personal use.

Large enough for investigation.

---

# Attack Deduplication

Same:

attacker_mac
victim_ip
event_type

within:

10 minutes

↓

Reuse existing attack.

Update attack statistics.

Do NOT create a new attack.

After window expires:

Create new attack.

---

# Detector Threading Model

Detector runs in a background thread.

Reason:

Packet capture must never block dashboard responsiveness.

Lifecycle:

detector.start()

detector.stop()

---

# detector.py Development Plan

Part 1

* Imports
* Detector class
* Constructor
* State variables
* Thread lifecycle

Part 2

* Interface detection
* Gateway detection
* Active discovery
* Baseline creation

Part 3

* Packet capture
* Packet processing
* Cache tracking

Part 4

* Verification system
* Majority voting

Part 5

* Attack handling
* Deduplication
* Event creation

Part 6

* Evidence capture
* PCAP storage
* Final integration

---

# Project Philosophy

Priority order:

1. Correctness
2. Maintainability
3. Simplicity
4. Performance

Architecture should remain modular.

Detector should use database.py and fingerprint.py instead of reimplementing their functionality.

Avoid large rewrites.

Continue using:

Design
↓
Implement
↓
Test
↓
Continue

for every future module.
