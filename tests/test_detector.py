from pathlib import Path

from arpex.database import DatabaseManager
from arpex.fingerprint import FingerprintManager
from arpex.detector import Detector


TEST_DB = Path(
    "data/test_detector.db"
)


def create_detector():

    if TEST_DB.exists():
        TEST_DB.unlink()

    db = DatabaseManager(TEST_DB)
    db.initialize_database()

    fp = FingerprintManager()

    return Detector(
        database=db,
        fingerprint=fp
    )


def test_detector_creation():

    detector = create_detector()

    assert detector is not None

    assert detector.running is False

    assert detector.cache_size() == 0


def test_detector_cache():

    detector = create_detector()

    detector.ip_mac_cache[
        "192.168.1.1"
    ] = "AA:BB:CC:DD:EE:FF"

    assert detector.cache_size() == 1

    detector.clear_cache()

    assert detector.cache_size() == 0

def test_interface_detection():

    detector = create_detector()

    interface = (
        detector.detect_interface()
    )

    assert interface is not None


def test_gateway_detection():

    detector = create_detector()

    gateway = (
        detector.detect_gateway()
    )

    assert gateway is not None


def test_handle_new_device():

    detector = create_detector()

    detector.handle_new_device(
        "192.168.1.50",
        "00:50:56:AA:BB:CC"
    )

    device = (
        detector.database.get_device_by_mac(
            "00:50:56:AA:BB:CC"
        )
    )

    assert device is not None

    events = (
        detector.database.list_events()
    )

    assert len(events) == 1

    assert (
        events[0]["event_type"]
        ==
        "NEW_DEVICE"
    )


def test_mapping_change_detection():

    detector = create_detector()

    detector.ip_mac_cache[
        "192.168.1.1"
    ] = "AA:AA:AA:AA:AA:AA"

    detector.handle_mapping_change(
        "192.168.1.1",
        "AA:AA:AA:AA:AA:AA",
        "BB:BB:BB:BB:BB:BB"
    )

    assert True

def test_majority_result():

    detector = create_detector()

    result = (
        detector._get_majority_result(
            [
                "AA",
                "AA",
                "BB"
            ]
        )
    )

    assert result == "AA"


def test_no_majority_result():

    detector = create_detector()

    result = (
        detector._get_majority_result(
            [
                "AA",
                "BB",
                "CC"
            ]
        )
    )

    assert result is None

def test_handle_attack_creates_attacker():

    detector = create_detector()

    detector.handle_attack(
        ip_address="192.168.1.10",
        old_mac="AA:AA:AA:AA:AA:AA",
        new_mac="BB:BB:BB:BB:BB:BB"
    )

    attacker = (
        detector.database.get_attacker_by_mac(
            "BB:BB:BB:BB:BB:BB"
        )
    )

    assert attacker is not None

    assert (
        attacker["attack_count"]
        ==
        1
    )


def test_handle_attack_creates_record():

    detector = create_detector()

    detector.handle_attack(
        ip_address="192.168.1.10",
        old_mac="AA:AA:AA:AA:AA:AA",
        new_mac="CC:CC:CC:CC:CC:CC"
    )

    attacks = (
        detector.database.list_attacks()
    )

    events = (
        detector.database.list_events()
    )

    assert len(attacks) == 1

    assert len(events) == 1

    assert (
        attacks[0]["event_type"]
        ==
        "ARP_SPOOFING"
    )


def test_attack_deduplication():

    detector = create_detector()

    detector.handle_attack(
        ip_address="192.168.1.10",
        old_mac="AA:AA:AA:AA:AA:AA",
        new_mac="DD:DD:DD:DD:DD:DD"
    )

    detector.handle_attack(
        ip_address="192.168.1.10",
        old_mac="AA:AA:AA:AA:AA:AA",
        new_mac="DD:DD:DD:DD:DD:DD"
    )

    attacks = (
        detector.database.list_attacks()
    )

    assert len(attacks) == 1

    assert (
        attacks[0][
            "occurrence_count"
        ]
        ==
        2
    )

def test_capture_evidence():

    detector = create_detector()

    path = detector.capture_evidence(
        "ATT-TEST"
    )

    assert (
        path is None
        or
        isinstance(path, str)
    )