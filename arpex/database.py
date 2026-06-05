    # PART 1
from __future__ import annotations

import sqlite3
import json
import csv
import shutil
from pathlib import Path
from datetime import datetime
from enum import Enum
from typing import Optional, Any



# CONSTANTS

DEFAULT_DB_PATH = Path("data/arpex.db")


# ENUMS

class DeviceStatus(str, Enum):
    TRUSTED = "TRUSTED"
    SUSPICIOUS = "SUSPICIOUS"
    BLOCKED = "BLOCKED"


class ApprovalStatus(str, Enum):
    APPROVED = "APPROVED"
    UNAPPROVED = "UNAPPROVED"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"


# DATABASE MANAGER

class DatabaseManager:
    """
    Central SQLite manager for ARPEX.

    Responsibilities:
    - Open/close connections
    - Create schema
    - Create indexes
    - Future CRUD operations
    """

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = db_path

        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.connection: Optional[sqlite3.Connection] = None

    # CONNECTION MANAGEMENT

    def connect(self) -> None:
        """Connect to SQLite database."""

        if self.connection:
            return

        self.connection = sqlite3.connect(
            self.db_path,
            check_same_thread=False
        )

        self.connection.row_factory = sqlite3.Row

        self.connection.execute(
            "PRAGMA foreign_keys = ON;"
        )

    def close(self) -> None:
        """Close active database connection."""

        if self.connection:
            self.connection.close()
            self.connection = None

    def _row_to_dict(self, row: sqlite3.Row) -> Optional[dict]:
        """
        Convert sqlite row to standard dictionary.
        """
        if row is None:
            return None

        return dict(row)

    # INITIALIZATION

    def initialize_database(self) -> None:
        """
        Initialize ARPEX database.
        """

        self.connect()

        self._create_tables()
        self._create_indexes()

    # TABLE CREATION

    def _create_tables(self) -> None:

        cursor = self.connection.cursor()

        # DEVICES

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            mac_address TEXT UNIQUE NOT NULL,
            current_ip TEXT,

            hostname TEXT,
            vendor TEXT,
            device_name TEXT,

            approval_status TEXT NOT NULL
                DEFAULT 'UNAPPROVED',

            status TEXT NOT NULL
                DEFAULT 'TRUSTED',

            is_gateway BOOLEAN NOT NULL
                DEFAULT 0,

            currently_online BOOLEAN NOT NULL
                DEFAULT 0,

            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,

            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL
        );
        """)

        # DEVICE IP HISTORY

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_ip_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            device_id INTEGER NOT NULL,

            ip_address TEXT NOT NULL,

            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,

            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,

            FOREIGN KEY(device_id)
            REFERENCES devices(id)
            ON DELETE CASCADE
        );
        """)

        # ATTACKERS

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS attackers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            mac_address TEXT UNIQUE NOT NULL,

            hostname TEXT,
            vendor TEXT,

            attack_count INTEGER NOT NULL
                DEFAULT 0,

            currently_active BOOLEAN NOT NULL
                DEFAULT 0,

            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,

            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL
        );
        """)

        # ATTACKS

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            attack_id TEXT UNIQUE NOT NULL,

            attacker_id INTEGER,

            timestamp DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,

            occurrence_count INTEGER NOT NULL
                DEFAULT 1,

            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,

            verification_status TEXT NOT NULL,

            victim_ip TEXT,
            victim_mac TEXT,
            victim_vendor TEXT,

            attacker_mac TEXT,
            attacker_vendor TEXT,

            interface TEXT,

            pcap_file TEXT,
            notes TEXT,

            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,

            FOREIGN KEY(attacker_id)
            REFERENCES attackers(id)
            ON DELETE SET NULL
        );
        """)

        # EVENTS

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp DATETIME NOT NULL,

            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,

            device_mac TEXT,
            device_ip TEXT,

            message TEXT NOT NULL,

            related_attack_id TEXT,

            metadata TEXT,

            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL
        );
        """)

        self.connection.commit()

    # INDEX CREATION

    def _create_indexes(self) -> None:

        cursor = self.connection.cursor()

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_devices_mac
        ON devices(mac_address);
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_devices_ip
        ON devices(current_ip);
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_timestamp
        ON events(timestamp);
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_attacks_attack_id
        ON attacks(attack_id);
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_attackers_mac
        ON attackers(mac_address);
        """)

        self.connection.commit()

    # PART 2
    # DEVICE MANAGEMENT API

    def create_device(
    self,
    mac_address: str,
    current_ip: str,
    hostname: Optional[str] = None,
    vendor: Optional[str] = None,
    device_name: Optional[str] = None,
    approval_status: str = ApprovalStatus.UNAPPROVED.value,
    status: str = DeviceStatus.TRUSTED.value,
    is_gateway: bool = False,
    currently_online: bool = True
    ) -> dict:
        """
        Create a device if it does not exist.
        Returns existing device if MAC already exists.
        """

        existing = self.get_device_by_mac(mac_address)

        if existing:
            return existing

        now = datetime.utcnow().isoformat()

        cursor = self.connection.cursor()

        cursor.execute(
            """
            INSERT INTO devices (
                mac_address,
                current_ip,
                hostname,
                vendor,
                device_name,
                approval_status,
                status,
                is_gateway,
                currently_online,
                first_seen,
                last_seen,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                mac_address,
                current_ip,
                hostname,
                vendor,
                device_name,
                approval_status,
                status,
                is_gateway,
                currently_online,
                now,
                now,
                now,
                now
            )
        )

        self.connection.commit()

        device = self.get_device_by_mac(mac_address)

        if current_ip:
            self.add_ip_history(device["id"], current_ip)

        return device


    def get_device_by_mac(self, mac_address: str) -> Optional[dict]:
        """
        Get device using MAC address.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM devices
            WHERE mac_address = ?
            """,
            (mac_address,)
        )

        row = cursor.fetchone()

        return self._row_to_dict(row)


    def get_device_by_ip(self, ip_address: str) -> Optional[dict]:
        """
        Get device using current IP.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM devices
            WHERE current_ip = ?
            """,
            (ip_address,)
        )

        row = cursor.fetchone()

        return self._row_to_dict(row)


    def list_devices(self) -> list[dict]:
        """
        Return all devices.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM devices
            ORDER BY last_seen DESC
            """
        )

        rows = cursor.fetchall()

        return [dict(row) for row in rows]


    def update_device(self, device_id: int, **fields: Any) -> bool:
        """
        Generic device updater.
        """

        if not fields:
            return False

        fields["updated_at"] = datetime.utcnow().isoformat()

        set_clause = ", ".join(
            f"{column} = ?"
            for column in fields.keys()
        )

        values = list(fields.values())
        values.append(device_id)

        cursor = self.connection.cursor()

        cursor.execute(
            f"""
            UPDATE devices
            SET {set_clause}
            WHERE id = ?
            """,
            values
        )

        self.connection.commit()

        return cursor.rowcount > 0


    def update_device_status(
        self,
        device_id: int,
        status: str
    ) -> bool:
        """
        Update device status.
        """

        return self.update_device(
            device_id,
            status=status
        )


    def update_device_ip(
        self,
        device_id: int,
        new_ip: str
    ) -> bool:
        """
        Update current IP and IP history.
        """

        device = self.get_device(device_id)

        if not device:
            return False

        self.add_ip_history(
            device_id,
            new_ip
        )

        return self.update_device(
            device_id,
            current_ip=new_ip,
            last_seen=datetime.utcnow().isoformat()
        )


    def get_device(self, device_id: int) -> Optional[dict]:
        """
        Get device by ID.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM devices
            WHERE id = ?
            """,
            (device_id,)
        )

        row = cursor.fetchone()

        return self._row_to_dict(row)


    def add_ip_history(
        self,
        device_id: int,
        ip_address: str
    ) -> None:
        """
        Create or update IP history entry.
        """

        now = datetime.utcnow().isoformat()

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM device_ip_history
            WHERE device_id = ?
            AND ip_address = ?
            """,
            (
                device_id,
                ip_address
            )
        )

        existing = cursor.fetchone()

        if existing:
            cursor.execute(
                """
                UPDATE device_ip_history
                SET
                    last_seen = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    now,
                    now,
                    existing["id"]
                )
            )
        else:
            cursor.execute(
                """
                INSERT INTO device_ip_history (
                    device_id,
                    ip_address,
                    first_seen,
                    last_seen,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    ip_address,
                    now,
                    now,
                    now,
                    now
                )
            )

        self.connection.commit()


    def get_ip_history(
        self,
        device_id: int
    ) -> list[dict]:
        """
        Return all IP history for a device.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM device_ip_history
            WHERE device_id = ?
            ORDER BY last_seen DESC
            """,
            (device_id,)
        )

        rows = cursor.fetchall()

        return [dict(row) for row in rows]
    
    # PART 3

    def create_attacker(
        self,
        mac_address: str,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        currently_active: bool = True
    ) -> dict:
        """
        Create attacker if it does not exist.
        If it already exists, update last_seen and return it.
        """

        existing = self.get_attacker_by_mac(mac_address)

        now = datetime.utcnow().isoformat()

        if existing:
            self.update_attacker(
                existing["id"],
                hostname=hostname or existing["hostname"],
                vendor=vendor or existing["vendor"],
                currently_active=currently_active,
                last_seen=now
            )

            return self.get_attacker(existing["id"])

        cursor = self.connection.cursor()

        cursor.execute(
            """
            INSERT INTO attackers (
                mac_address,
                hostname,
                vendor,
                attack_count,
                currently_active,
                first_seen,
                last_seen,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                mac_address,
                hostname,
                vendor,
                0,
                currently_active,
                now,
                now,
                now,
                now
            )
        )

        self.connection.commit()

        return self.get_attacker_by_mac(mac_address)


    def get_attacker_by_mac(
        self,
        mac_address: str
    ) -> Optional[dict]:
        """
        Get attacker by MAC address.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM attackers
            WHERE mac_address = ?
            """,
            (mac_address,)
        )

        row = cursor.fetchone()

        return self._row_to_dict(row)


    def get_attacker(
        self,
        attacker_id: int
    ) -> Optional[dict]:
        """
        Get attacker by ID.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM attackers
            WHERE id = ?
            """,
            (attacker_id,)
        )

        row = cursor.fetchone()

        return self._row_to_dict(row)


    def list_attackers(self) -> list[dict]:
        """
        Return all attackers.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM attackers
            ORDER BY attack_count DESC,
                    last_seen DESC
            """
        )

        rows = cursor.fetchall()

        return [dict(row) for row in rows]


    def update_attacker(
        self,
        attacker_id: int,
        **fields: Any
    ) -> bool:
        """
        Generic attacker updater.
        """

        if not fields:
            return False

        fields["updated_at"] = datetime.utcnow().isoformat()

        set_clause = ", ".join(
            f"{column} = ?"
            for column in fields.keys()
        )

        values = list(fields.values())
        values.append(attacker_id)

        cursor = self.connection.cursor()

        cursor.execute(
            f"""
            UPDATE attackers
            SET {set_clause}
            WHERE id = ?
            """,
            values
        )

        self.connection.commit()

        return cursor.rowcount > 0


    def increment_attack_count(
        self,
        attacker_id: int
    ) -> bool:
        """
        Increase attack count by one.
        """

        attacker = self.get_attacker(attacker_id)

        if not attacker:
            return False

        return self.update_attacker(
            attacker_id,
            attack_count=attacker["attack_count"] + 1,
            last_seen=datetime.utcnow().isoformat()
        )
    
    # PART 4
        
    def _generate_attack_id(self) -> str:
        """
        Generate the next attack ID.
        Format: ATT-000001
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT attack_id
            FROM attacks
            ORDER BY id DESC
            LIMIT 1
            """
        )

        row = cursor.fetchone()

        if not row:
            return "ATT-000001"

        try:
            current_number = int(
                row["attack_id"].split("-")[1]
            )

            return f"ATT-{current_number + 1:06d}"

        except (ValueError, IndexError):
            return f"ATT-{int(datetime.utcnow().timestamp()):06d}"


    def create_attack(
        self,
        event_type: str,
        severity: str,
        verification_status: str,
        victim_ip: Optional[str] = None,
        victim_mac: Optional[str] = None,
        victim_vendor: Optional[str] = None,
        attacker_mac: Optional[str] = None,
        attacker_vendor: Optional[str] = None,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        notes: Optional[str] = None
    ) -> dict:
        """
        Create attack record.
        """

        attack_id = self._generate_attack_id()
        now = datetime.utcnow().isoformat()

        attacker_id = None

        if attacker_mac:
            attacker = self.get_attacker_by_mac(
                attacker_mac
            )

            if attacker:
                attacker_id = attacker["id"]

        cursor = self.connection.cursor()

        cursor.execute(
            """
            INSERT INTO attacks (
                attack_id,
                attacker_id,
                timestamp,
                last_seen,
                occurrence_count,
                event_type,
                severity,
                verification_status,
                victim_ip,
                victim_mac,
                victim_vendor,
                attacker_mac,
                attacker_vendor,
                interface,
                pcap_file,
                notes,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attack_id,
                attacker_id,
                now,
                now,
                1,
                event_type,
                severity,
                verification_status,
                victim_ip,
                victim_mac,
                victim_vendor,
                attacker_mac,
                attacker_vendor,
                interface,
                pcap_file,
                notes,
                now,
                now 
            )
        )

        self.connection.commit()

        return self.get_attack_by_attack_id(
            attack_id
        )


    def get_attack(
        self,
        attack_db_id: int
    ) -> Optional[dict]:
        """
        Get attack by database ID.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM attacks
            WHERE id = ?
            """,
            (attack_db_id,)
        )

        row = cursor.fetchone()

        return self._row_to_dict(row)


    def get_attack_by_attack_id(
        self,
        attack_id: str
    ) -> Optional[dict]:
        """
        Get attack using ATT-XXXXXX ID.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM attacks
            WHERE attack_id = ?
            """,
            (attack_id,)
        )

        row = cursor.fetchone()

        return self._row_to_dict(row)


    def list_attacks(self) -> list[dict]:
        """
        Return all attacks.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM attacks
            ORDER BY timestamp DESC
            """
        )

        rows = cursor.fetchall()

        return [dict(row) for row in rows]


    def update_attack(
        self,
        attack_db_id: int,
        **fields: Any
    ) -> bool:
        """
        Generic attack updater.
        """

        if not fields:
            return False

        fields["updated_at"] = datetime.utcnow().isoformat()

        set_clause = ", ".join(
            f"{column} = ?"
            for column in fields.keys()
        )

        values = list(fields.values())
        values.append(attack_db_id)

        cursor = self.connection.cursor()

        cursor.execute(
            f"""
            UPDATE attacks
            SET {set_clause}
            WHERE id = ?
            """,
            values
        )

        self.connection.commit()

        return cursor.rowcount > 0
    
#abc
    def find_recent_attack(
        self,
        attacker_mac: str,
        victim_ip: str,
        event_type: str
    ) -> Optional[dict]:
        """
        Find recent matching attack
        within 10 minutes.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM attacks
            WHERE attacker_mac = ?
            AND victim_ip = ?
            AND event_type = ?
            AND datetime(last_seen)
                >= datetime('now', '-10 minutes')
            ORDER BY last_seen DESC
            LIMIT 1
            """,
            (
                attacker_mac,
                victim_ip,
                event_type
            )
        )

        row = cursor.fetchone()

        return self._row_to_dict(row)

#occurence updater

    def increment_attack_occurrence(
        self,
        attack_db_id: int
    ) -> bool:
        """
        Increment occurrence count.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            UPDATE attacks
            SET
                occurrence_count =
                    occurrence_count + 1,

                last_seen = ?,

                updated_at = ?
            WHERE id = ?
            """,
            (
                datetime.utcnow().isoformat(),
                datetime.utcnow().isoformat(),
                attack_db_id
            )
        )

        self.connection.commit()

        return cursor.rowcount > 0

    def create_event(
        self,
        event_type: str,
        severity: str,
        message: str,
        device_mac: Optional[str] = None,
        device_ip: Optional[str] = None,
        related_attack_id: Optional[str] = None,
        metadata: Optional[dict] = None
    ) -> dict:
        """
        Create event record.
        """

        now = datetime.utcnow().isoformat()

        metadata_json = None

        if metadata:
            metadata_json = json.dumps(metadata)

        cursor = self.connection.cursor()

        cursor.execute(
            """
            INSERT INTO events (
                timestamp,
                event_type,
                severity,
                device_mac,
                device_ip,
                message,
                related_attack_id,
                metadata,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                event_type,
                severity,
                device_mac,
                device_ip,
                message,
                related_attack_id,
                metadata_json,
                now,
                now
            )
        )

        event_id = cursor.lastrowid

        self.connection.commit()

        return self.get_event(event_id)


    def get_event(
        self,
        event_id: int
    ) -> Optional[dict]:
        """
        Get event by ID.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM events
            WHERE id = ?
            """,
            (event_id,)
        )

        row = cursor.fetchone()

        event = self._row_to_dict(row)

        if event and event["metadata"]:
            try:
                event["metadata"] = json.loads(
                    event["metadata"]
                )
            except json.JSONDecodeError:
                pass

        return event


    def list_events(self) -> list[dict]:
        """
        Return all events.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM events
            ORDER BY timestamp DESC
            """
        )

        rows = cursor.fetchall()

        results = []

        for row in rows:
            event = dict(row)

            if event["metadata"]:
                try:
                    event["metadata"] = json.loads(
                        event["metadata"]
                    )
                except json.JSONDecodeError:
                    pass

            results.append(event)

        return results


    def update_event(
        self,
        event_id: int,
        **fields: Any
    ) -> bool:
        """
        Generic event updater.
        """

        if not fields:
            return False

        if "metadata" in fields and isinstance(
            fields["metadata"],
            dict
        ):
            fields["metadata"] = json.dumps(
                fields["metadata"]
            )

        fields["updated_at"] = datetime.utcnow().isoformat()

        set_clause = ", ".join(
            f"{column} = ?"
            for column in fields.keys()
        )

        values = list(fields.values())
        values.append(event_id)

        cursor = self.connection.cursor()

        cursor.execute(
            f"""
            UPDATE events
            SET {set_clause}
            WHERE id = ?
            """,
            values
        )

        self.connection.commit()

        return cursor.rowcount > 0
    
    def _fetch_one(
        self,
        query: str,
        params: tuple = ()
    ) -> Optional[dict]:
        """
        Execute query and return one record.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            query,
            params
        )

        row = cursor.fetchone()

        return self._row_to_dict(row)


    def _fetch_all(
        self,
        query: str,
        params: tuple = ()
    ) -> list[dict]:
        """
        Execute query and return all records.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            query,
            params
        )

        rows = cursor.fetchall()

        return [dict(row) for row in rows]    
    
    # PART 5

    def search_devices(
        self,
        query: str
    ) -> list[dict]:
        """
        Search devices by MAC, IP, hostname,
        vendor or device name.
        """

        search_term = f"%{query}%"

        return self._fetch_all(
            """
            SELECT *
            FROM devices
            WHERE
                mac_address LIKE ?
                OR current_ip LIKE ?
                OR hostname LIKE ?
                OR vendor LIKE ?
                OR device_name LIKE ?
            ORDER BY last_seen DESC
            """,
            (
                search_term,
                search_term,
                search_term,
                search_term,
                search_term
            )
        )


    def search_attackers(
        self,
        query: str
    ) -> list[dict]:
        """
        Search attackers.
        """

        search_term = f"%{query}%"

        return self._fetch_all(
            """
            SELECT *
            FROM attackers
            WHERE
                mac_address LIKE ?
                OR hostname LIKE ?
                OR vendor LIKE ?
            ORDER BY attack_count DESC
            """,
            (
                search_term,
                search_term,
                search_term
            )
        )


    def search_attacks(
        self,
        query: str
    ) -> list[dict]:
        """
        Search attacks.
        """

        search_term = f"%{query}%"

        return self._fetch_all(
            """
            SELECT *
            FROM attacks
            WHERE
                attack_id LIKE ?
                OR attacker_mac LIKE ?
                OR victim_mac LIKE ?
                OR victim_ip LIKE ?
                OR event_type LIKE ?
            ORDER BY timestamp DESC
            """,
            (
                search_term,
                search_term,
                search_term,
                search_term,
                search_term
            )
        )


    def search_events(
        self,
        query: str
    ) -> list[dict]:
        """
        Search events.
        """

        search_term = f"%{query}%"

        return self._fetch_all(
            """
            SELECT *
            FROM events
            WHERE
                event_type LIKE ?
                OR device_mac LIKE ?
                OR device_ip LIKE ?
                OR message LIKE ?
            ORDER BY timestamp DESC
            """,
            (
                search_term,
                search_term,
                search_term,
                search_term
            )
        )


    def filter_devices(
        self,
        status: Optional[str] = None,
        online_only: bool = False
    ) -> list[dict]:
        """
        Filter devices.
        """

        query = "SELECT * FROM devices WHERE 1=1"
        params = []

        if status:
            query += " AND status = ?"
            params.append(status)

        if online_only:
            query += " AND currently_online = 1"

        query += " ORDER BY last_seen DESC"

        return self._fetch_all(
            query,
            tuple(params)
        )


    def filter_attacks(
        self,
        severity: Optional[str] = None,
        event_type: Optional[str] = None
    ) -> list[dict]:
        """
        Filter attacks.
        """

        query = "SELECT * FROM attacks WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        query += " ORDER BY timestamp DESC"

        return self._fetch_all(
            query,
            tuple(params)
        )


    def filter_events(
        self,
        severity: Optional[str] = None,
        event_type: Optional[str] = None
    ) -> list[dict]:
        """
        Filter events.
        """

        query = "SELECT * FROM events WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        query += " ORDER BY timestamp DESC"

        return self._fetch_all(
            query,
            tuple(params)
        )
    
    # PART 6 

    def export_devices_csv(
        self,
        output_path: str
    ) -> str:
        """
        Export devices to CSV.
        """

        devices = self.list_devices()

        with open(
            output_path,
            "w",
            newline="",
            encoding="utf-8"
        ) as csv_file:

            writer = csv.DictWriter(
                csv_file,
                fieldnames=devices[0].keys() if devices else []
            )

            if devices:
                writer.writeheader()
                writer.writerows(devices)

        return output_path


    def export_attacks_csv(
        self,
        output_path: str
    ) -> str:
        """
        Export attacks to CSV.
        """

        attacks = self.list_attacks()

        with open(
            output_path,
            "w",
            newline="",
            encoding="utf-8"
        ) as csv_file:

            writer = csv.DictWriter(
                csv_file,
                fieldnames=attacks[0].keys() if attacks else []
            )

            if attacks:
                writer.writeheader()
                writer.writerows(attacks)

        return output_path


    def export_events_csv(
        self,
        output_path: str
    ) -> str:
        """
        Export events to CSV.
        """

        events = self.list_events()

        with open(
            output_path,
            "w",
            newline="",
            encoding="utf-8"
        ) as csv_file:

            writer = csv.DictWriter(
                csv_file,
                fieldnames=events[0].keys() if events else []
            )

            if events:
                writer.writeheader()
                writer.writerows(events)

        return output_path


    def create_backup(
        self,
        backup_path: str
    ) -> str:
        """
        Create SQLite backup.
        """

        if self.connection:
            self.connection.commit()

        shutil.copy2(
            self.db_path,
            backup_path
        )

        return backup_path


    def restore_backup(
        self,
        backup_path: str
    ) -> None:
        """
        Restore SQLite backup.
        """

        self.close()

        shutil.copy2(
            backup_path,
            self.db_path
        )

        self.connect()


    def cleanup_old_attacks(
        self,
        retention_days: int = 30
    ) -> int:
        """
        Delete attacks older than retention period.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            DELETE FROM attacks
            WHERE datetime(timestamp)
            < datetime('now', ?)
            """,
            (f"-{retention_days} days",)
        )

        deleted = cursor.rowcount

        self.connection.commit()

        return deleted


    def cleanup_old_events(
        self,
        retention_days: int = 60
    ) -> int:
        """
        Delete events older than retention period.
        """

        cursor = self.connection.cursor()

        cursor.execute(
            """
            DELETE FROM events
            WHERE datetime(timestamp)
            < datetime('now', ?)
            """,
            (f"-{retention_days} days",)
        )

        deleted = cursor.rowcount

        self.connection.commit()

        return deleted


    def run_cleanup_tasks(self) -> dict:
        """
        Run all retention cleanup tasks.
        """

        attacks_deleted = self.cleanup_old_attacks()

        events_deleted = self.cleanup_old_events()

        return {
            "attacks_deleted": attacks_deleted,
            "events_deleted": events_deleted
        }
