# PART 1
from __future__ import annotations
import socket
import json
from pathlib import Path
from typing import Optional

from zeroconf import (
    Zeroconf,
    ServiceBrowser,
    ServiceListener
)

DEFAULT_OUI_PATH = Path("config/oui.json")


class FingerprintManager:
    """
    Offline MAC vendor fingerprinting.

    Responsibilities:
    - Load OUI database
    - Normalize MAC addresses
    - Extract OUI prefixes
    - Lookup vendors

    Does NOT:
    - Scan networks
    - Capture packets
    - Detect attacks
    """

    def __init__(
        self,
        oui_path: Path = DEFAULT_OUI_PATH
    ):
        self.oui_path = oui_path
        self.oui_database: dict[str, str] = {}
        self.load_oui_database()
    def load_oui_database(self) -> None:
        """
        Load OUI database into memory.

        Missing file is allowed.
        """

        if not self.oui_path.exists():
            print(
                f"[WARNING] OUI database not found: "
                f"{self.oui_path}"
            )

            self.oui_database = {}
            return

        try:
            with open(
                self.oui_path,
                "r",
                encoding="utf-8"
            ) as file:

                self.oui_database = json.load(file)

        except Exception as exc:
            print(
                f"[WARNING] Failed loading OUI database: "
                f"{exc}"
            )

            self.oui_database = {}

    def reload_database(self) -> None:
        """
        Reload OUI database.
        """

        self.load_oui_database()

    def normalize_mac(
        self,
        mac_address: Optional[str]
    ) -> Optional[str]:
        """
        Convert MAC to standard form:

        AA:BB:CC:DD:EE:FF
        """

        if not mac_address:
            return None

        mac = (
            str(mac_address)
            .strip()
            .upper()
            .replace("-", "")
            .replace(":", "")
        )

        if len(mac) != 12:
            return None

        try:
            int(mac, 16)
        except ValueError:
            return None

        return ":".join(
            mac[i:i + 2]
            for i in range(0, 12, 2)
        )

    def extract_oui(
        self,
        mac_address: Optional[str]
    ) -> Optional[str]:
        """
        Extract first 6 hex digits.

        Example:

        00:50:56:AA:BB:CC
        ↓
        005056
        """

        normalized = self.normalize_mac(
            mac_address
        )

        if not normalized:
            return None

        return normalized.replace(
            ":",
            ""
        )[:6]
    
    # PART 2 

    def lookup_vendor(
        self,
        mac_address: Optional[str]
    ) -> str:
        """
        Lookup vendor using MAC address.

        Returns:
            Vendor name
            or "Unknown"
        """

        oui = self.extract_oui(
            mac_address
        )

        if not oui:
            return "Unknown"

        return self.oui_database.get(
            oui,
            "Unknown"
        )


    def database_loaded(self) -> bool:
        """
        Check whether OUI database is loaded.
        """

        return len(
            self.oui_database
        ) > 0


    def total_vendors(self) -> int:
        """
        Number of vendors loaded.
        """

        return len(
            self.oui_database
        )
    

    def lookup_hostname(
        self,
        ip_address: str
    ) -> Optional[str]:
        """
        Reverse DNS hostname lookup.
        """

        try:

            hostname, _, _ = (
                socket.gethostbyaddr(
                    ip_address
                )
            )

            return hostname

        except Exception:

            return None
