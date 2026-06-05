from __future__ import annotations
import ipaddress
from collections import Counter, deque
from scapy.all import wrpcap
from scapy.all import (
    ARP,
    Ether,
    conf,
    get_if_addr,
    getmacbyip,
    srp
)
from scapy.all import sniff

import threading
from pathlib import Path
from typing import Optional

from arpex.database import DatabaseManager
from arpex.fingerprint import FingerprintManager


class Detector:
    """
    ARPEX ARP spoofing detector.

    Responsibilities:
    - Monitor ARP traffic
    - Verify IP → MAC mappings
    - Detect spoofing
    - Generate attacks/events
    - Capture evidence

    Does NOT:
    - Manage database schema
    - Render dashboard
    - Perform vendor lookup logic
    """

    def __init__(
        self,
        database: DatabaseManager,
        fingerprint: FingerprintManager,
        interface: Optional[str] = None
    ):
        self.database = database
        self.fingerprint = fingerprint

        self.interface = interface

        self.running = False

        self.gateway_ip: Optional[str] = None
        self.gateway_mac: Optional[str] = None

        self.ip_mac_cache: dict[str, str] = {}

        self.detector_thread: Optional[
            threading.Thread
        ] = None
        
        self.verification_attempts = 3
        self.packet_buffer = deque(maxlen=200)
        
    def start(self) -> None:
        """
        Start detector thread.
        """

        if self.running:
            return

        self.running = True

        self.detector_thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="ARPEX-Detector"
        )

        self.detector_thread.start()

    def stop(self) -> None:
        """
        Stop detector thread.
        """

        self.running = False

        if (
            self.detector_thread
            and self.detector_thread.is_alive()
        ):
            self.detector_thread.join(
                timeout=5
            )

    def is_running(self) -> bool:
        """
        Return detector state.
        """

        return self.running

    def cache_size(self) -> int:
        """
        Number of tracked mappings.
        """

        return len(
            self.ip_mac_cache
        )

    def clear_cache(self) -> None:
        """
        Clear mapping cache.
        """

        self.ip_mac_cache.clear()

    def _run(self) -> None:
        """
        Detector runtime.
        """

        self.detect_interface()

        self.detect_gateway()

        self.resolve_gateway_mac()

        self.build_baseline()

        self.sniff_packets()

    # PART 2

    def detect_interface(self) -> str:
        """
        Detect active network interface.
        """

        if self.interface:
            return self.interface

        self.interface = conf.iface

        return str(self.interface)


    def detect_gateway(self) -> Optional[str]:
        """
        Detect default gateway IP.
        """

        try:
            route = conf.route.route(
                "0.0.0.0"
            )

            self.gateway_ip = route[2]

            return self.gateway_ip

        except Exception:
            return None


    def resolve_gateway_mac(self) -> Optional[str]:
        """
        Resolve gateway MAC address.
        """

        if not self.gateway_ip:
            return None

        try:
            self.gateway_mac = getmacbyip(
                self.gateway_ip
            )

            return self.gateway_mac

        except Exception:
            return None


    def get_local_network(self) -> str:
        """
        Build local CIDR.

        Example:
        192.168.1.25
        ↓
        192.168.1.0/24
        """

        ip_address = get_if_addr(
            self.detect_interface()
        )

        network = ipaddress.ip_network(
            f"{ip_address}/24",
            strict=False
        )

        return str(network)


    def discover_devices(self) -> list[dict]:
        """
        Active ARP discovery.
        """

        network = self.get_local_network()

        packet = (
            Ether(dst="ff:ff:ff:ff:ff:ff")
            /
            ARP(pdst=network)
        )

        answered, _ = srp(
            packet,
            timeout=2,
            verbose=False,
            iface=self.detect_interface()
        )

        devices = []

        for _, response in answered:

            devices.append(
                {
                    "ip": response.psrc,
                    "mac": response.hwsrc
                }
            )

        return devices


    def build_baseline(self) -> None:
        """
        Build initial IP → MAC cache.
        """

        devices = self.discover_devices()

        for device in devices:

            ip_address = device["ip"]
            mac_address = device["mac"]

            self.ip_mac_cache[
                ip_address
            ] = mac_address

            vendor = (
                self.fingerprint.lookup_vendor(
                    mac_address
                )
            )

            existing = (
                self.database.get_device_by_mac(
                    mac_address
                )
            )

            if existing:
                continue

            self.database.create_device(
                mac_address=mac_address,
                current_ip=ip_address,
                vendor=vendor,
                is_gateway=(
                    ip_address
                    ==
                    self.gateway_ip
                )
            )

    # PART 3
    def sniff_packets(self) -> None:
        """
        Start ARP packet capture.
        """

        sniff(
            iface=self.detect_interface(),
            filter="arp",
            store=False,
            prn=self.process_packet,
            stop_filter=lambda _: not self.running
        )


    def process_packet(self, packet) -> None:
        """
        Process incoming ARP packet.
        """

        if not packet.haslayer(ARP):
            return
        
        self.packet_buffer.append(
            packet.copy()
        )

        sender_ip = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc

        if not sender_ip or not sender_mac:
            return

        known_mac = self.ip_mac_cache.get(
            sender_ip
        )

        if known_mac is None:

            self.handle_new_device(
                sender_ip,
                sender_mac
            )

            return

        if known_mac.upper() != sender_mac.upper():

            self.handle_mapping_change(
                sender_ip,
                known_mac,
                sender_mac
            )


    def handle_new_device(
        self,
        ip_address: str,
        mac_address: str
    ) -> None:
        """
        Handle newly discovered device.
        """

        self.ip_mac_cache[
            ip_address
        ] = mac_address

        vendor = (
            self.fingerprint.lookup_vendor(
                mac_address
            )
        )

        existing = (
            self.database.get_device_by_mac(
                mac_address
            )
        )

        if existing:
            return

        self.database.create_device(
            mac_address=mac_address,
            current_ip=ip_address,
            vendor=vendor
        )

        self.database.create_event(
            event_type="NEW_DEVICE",
            severity="LOW",
            device_mac=mac_address,
            device_ip=ip_address,
            message=(
                f"New device discovered: "
                f"{ip_address}"
            )
        )


    def handle_mapping_change(
        self,
        ip_address: str,
        old_mac: str,
        new_mac: str
    ) -> None:
        """
        Mapping change detected.

        Verification will be implemented
        in Part 4.
        """

        print(
            "[ARPEX] Mapping change detected "
            f"{ip_address}: "
            f"{old_mac} -> {new_mac}"
        )

        self.verify_mapping(
            ip_address,
            old_mac,
            new_mac
        )

    def _send_verification_request(
        self,
        ip_address: str
    ) -> Optional[str]:
        """
        Send a fresh ARP request and
        return the responding MAC.
        """

        try:

            packet = (
                Ether(dst="ff:ff:ff:ff:ff:ff")
                /
                ARP(pdst=ip_address)
            )

            answered, _ = srp(
                packet,
                timeout=1,
                verbose=False,
                iface=self.detect_interface()
            )

            if not answered:
                return None

            return answered[0][1].hwsrc

        except Exception:
            return None


    def _get_majority_result(
        self,
        results: list[str]
    ) -> Optional[str]:
        """
        Return majority MAC address.
        """

        if not results:
            return None

        counts = Counter(results)

        winner, votes = counts.most_common(1)[0]

        if votes >= 2:
            return winner

        return None


    def _handle_verification_failure(
        self,
        ip_address: str
    ) -> None:
        """
        Create verification failure event.
        """

        self.database.create_event(
            event_type="VERIFICATION_FAILED",
            severity="MEDIUM",
            device_ip=ip_address,
            message=(
                "ARP verification failed "
                "to reach majority decision."
            )
        )


    def handle_attack(
        self,
        ip_address: str,
        old_mac: str,
        new_mac: str
    ) -> None:
        """
        Handle verified attack.
        """

        attacker_mac = new_mac.upper()

        attacker = self.database.get_attacker_by_mac(
            attacker_mac
        )

        if attacker is None:

            attacker_vendor = (
                self.fingerprint.lookup_vendor(
                    attacker_mac
                )
            )

            attacker = self.database.create_attacker(
                mac_address=attacker_mac,
                vendor=attacker_vendor
            )

        self.database.increment_attack_count(
            attacker["id"]
        )

        if ip_address == self.gateway_ip:

            event_type = (
                "GATEWAY_SPOOFING"
            )

            severity = "CRITICAL"

        else:

            event_type = (
                "ARP_SPOOFING"
            )

            severity = "HIGH"

        existing_attack = (
            self.database.find_recent_attack(
                attacker_mac=attacker_mac,
                victim_ip=ip_address,
                event_type=event_type
            )
        )

        if existing_attack:

            self.database.increment_attack_occurrence(
                existing_attack["id"]
            )

            attack_id = (
                existing_attack["attack_id"]
            )

        else:

            attack = (
                self.database.create_attack(
                    event_type=event_type,
                    severity=severity,
                    verification_status="VERIFIED",
                    victim_ip=ip_address,
                    attacker_mac=attacker_mac,
                    attacker_vendor=(
                        attacker.get(
                            "vendor"
                        )
                    )
                )
            )

            attack_id = attack["attack_id"]

            pcap_file = (
                self.capture_evidence(
                    attack_id
                )
            )

            if pcap_file:

                self.database.update_attack(
                    attack["id"],
                    pcap_file=pcap_file
                )

        self.database.create_event(
            event_type=event_type,
            severity=severity,
            device_ip=ip_address,
            device_mac=attacker_mac,
            related_attack_id=attack_id,
            message=(
                f"{event_type} detected "
                f"against {ip_address}"
            )
        )

    def capture_evidence(
        self,
        attack_id: str
    ) -> Optional[str]:
        """
        Save buffered packets to PCAP.
        """

        try:

            captures_dir = Path(
                "captures"
            )

            captures_dir.mkdir(
                exist_ok=True
            )

            pcap_path = (
                captures_dir
                /
                f"{attack_id}.pcap"
            )

            packets = list(
                self.packet_buffer
            )

            if not packets:
                return None

            wrpcap(
                str(pcap_path),
                packets
            )

            return str(
                pcap_path
            )

        except Exception:

            return None

    def verify_mapping(
        self,
        ip_address: str,
        old_mac: str,
        new_mac: str
    ) -> None:
        """
        Verify mapping change using
        multiple ARP requests.
        """

        results = []

        for _ in range(
            self.verification_attempts
        ):

            mac = self._send_verification_request(
                ip_address
            )

            if mac:
                results.append(
                    mac.upper()
                )

        majority = self._get_majority_result(
            results
        )

        if majority is None:

            self._handle_verification_failure(
                ip_address
            )

            return

        if majority == old_mac.upper():

            self.database.create_event(
                event_type="SPOOFING_ATTEMPT",
                severity="LOW",
                device_ip=ip_address,
                device_mac=new_mac,
                message=(
                    "ARP spoofing attempt observed "
                    "but verification did not "
                    "confirm an attack."
                )
            )

            return

        self.ip_mac_cache[
            ip_address
        ] = majority

        self.handle_attack(
            ip_address,
            old_mac,
            majority
        )

