from __future__ import annotations
import ipaddress
import time
from datetime import datetime
from collections import Counter, deque
from scapy import packet
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
        self.verification_in_progress = threading.Event()

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

        self.presence_thread: Optional[
            threading.Thread
        ] = None
        
        self.verification_attempts = 3
        self.packet_buffer = deque(maxlen=200)
        self.missed_scans: dict[str, int] = {}




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

        self.start_presence_monitor()

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
            timeout=3,
            retry=2,
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
            mac_address = (
                device["mac"].upper()
            )

            self.ip_mac_cache[
                ip_address
            ] = mac_address

            vendor = (
                self.fingerprint.lookup_vendor(
                    mac_address
                )
            )

            hostname = (
                self.fingerprint.lookup_hostname(
                    ip_address
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
                hostname=hostname,
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
        if self.verification_in_progress.is_set():
            return

        if not packet.haslayer(ARP):
            return
        
        if packet[ARP].op != 2:
            return
        
        self.packet_buffer.append(
            packet.copy()
        )

        sender_ip = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc

        local_ip = get_if_addr(
            self.detect_interface()
        )

        if sender_ip == local_ip:
            return

        INVALID_MACS = {
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff"
        }

        if sender_mac.lower() in INVALID_MACS:
            return

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
        mac_address = mac_address.upper()
        
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

        threading.Thread(
            target=self.verify_mapping,
            args=(
                ip_address,
                old_mac,
                new_mac
            ),
            daemon=True
        ).start()


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

    def verify_mapping(self, ip_address, old_mac, new_mac):
        self.verification_in_progress.set()  # block other verifications

        try:
            results = []
            for _ in range(self.verification_attempts):
                mac = self._send_verification_request(ip_address)
                if mac:
                    results.append(mac.upper())

            majority = self._get_majority_result(results)

            if majority is None:
                self._handle_verification_failure(ip_address)
                return

            if majority == old_mac.upper():
                self.database.create_event(
                    event_type="SPOOFING_ATTEMPT",
                    severity="LOW",
                    device_ip=ip_address,
                    device_mac=new_mac,
                    message="ARP spoofing attempt observed but verification did not confirm an attack."
                )
                return

            self.ip_mac_cache[ip_address] = majority
            self.handle_attack(ip_address, old_mac, majority)

        finally:
            self.verification_in_progress.clear()  # allow future verifications


    def start_presence_monitor(
        self
    ) -> None:
        """
        Start device presence tracking.
        """

        self.presence_thread = (
            threading.Thread(
                target=self.presence_loop,
                daemon=True,
                name="ARPEX-Presence"
            )
        )

        self.presence_thread.start()

    def presence_loop(
        self
    ) -> None:
        """
        Track device online/offline state.
        """

        while self.running:

            try:

                self.update_device_presence()

            except Exception as exc:

                print(
                    "[ARPEX] Presence monitor error:",
                    exc
                )

            time.sleep(10)


    def update_device_presence(
        self
    ) -> None:
        """
        Update online/offline device state.
        """

        devices = self.discover_devices()

        active_macs = {
            device["mac"].upper()
            for device in devices
        }

        stored_devices = (
            self.database.get_all_devices()
        )

        for device in stored_devices:

            mac = (
                device["mac_address"]
                .upper()
            )

            if mac in active_macs:

                self.missed_scans.pop(
                    mac,
                    None
                )

                if not device[
                    "currently_online"
                ]:

                    self.database.update_device(
                        device["id"],
                        currently_online=1,
                        last_seen=datetime.utcnow().isoformat()
                    )

            else:

                count = (
                    self.missed_scans.get(
                        mac,
                        0
                    )
                    + 1
                )

                self.missed_scans[
                    mac
                ] = count

                if (
                    count >= 3
                    and
                    device[
                        "currently_online"
                    ]
                ):

                    self.database.update_device(
                        device["id"],
                        currently_online=0
                    )

        for discovered in devices:

            mac = (
                discovered["mac"]
                .upper()
            )

            existing = (
                self.database.get_device_by_mac(
                    mac
                )
            )

            if existing:
                continue

            vendor = (
                self.fingerprint.lookup_vendor(
                    mac
                )
            )

            hostname = (
                self.fingerprint.lookup_hostname(
                    discovered["ip"]
                )
            )

            self.database.create_device(
                mac_address=mac,
                current_ip=discovered["ip"],
                hostname=hostname,
                vendor=vendor
            )



            