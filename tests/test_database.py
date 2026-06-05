from pathlib import Path

from arpex.database import DatabaseManager


TEST_DB = Path("data/test_arpex.db")


def create_test_db():
    if TEST_DB.exists():
        TEST_DB.unlink()

    db = DatabaseManager(TEST_DB)
    db.initialize_database()

    return db


def test_create_device():
    db = create_test_db()

    device = db.create_device(
        mac_address="AA:BB:CC:DD:EE:FF",
        current_ip="192.168.1.5",
        hostname="test-device",
        vendor="Test Vendor"
    )

    assert device is not None

    fetched = db.get_device_by_mac(
        "AA:BB:CC:DD:EE:FF"
    )

    assert fetched is not None
    assert fetched["hostname"] == "test-device"

    db.close()


def test_create_attacker():
    db = create_test_db()

    attacker = db.create_attacker(
        mac_address="11:22:33:44:55:66",
        hostname="kali-vm",
        vendor="VMware"
    )

    assert attacker is not None

    fetched = db.get_attacker_by_mac(
        "11:22:33:44:55:66"
    )

    assert fetched is not None
    assert fetched["hostname"] == "kali-vm"

    db.increment_attack_count(
        fetched["id"]
    )

    updated = db.get_attacker(
        fetched["id"]
    )

    assert updated["attack_count"] == 1

    db.close()


def test_create_attack_and_event():
    db = create_test_db()

    db.create_attacker(
        mac_address="11:22:33:44:55:66"
    )

    attack = db.create_attack(
        event_type="ARP_SPOOFING",
        severity="HIGH",
        verification_status="VERIFIED",
        victim_ip="192.168.1.10",
        attacker_mac="11:22:33:44:55:66"
    )

    assert attack is not None
    assert attack["attack_id"].startswith("ATT-")

    event = db.create_event(
        event_type="ARP_SPOOFING",
        severity="HIGH",
        message="ARP spoofing detected",
        related_attack_id=attack["attack_id"]
    )

    assert event is not None

    attacks = db.list_attacks()
    events = db.list_events()

    assert len(attacks) == 1
    assert len(events) == 1

    db.close()

def test_backup_creation():
    from pathlib import Path

    db = create_test_db()

    backup_file = Path(
        "data/test_backup.db"
    )

    if backup_file.exists():
        backup_file.unlink()

    db.create_backup(
        str(backup_file)
    )

    assert backup_file.exists()

    db.close()