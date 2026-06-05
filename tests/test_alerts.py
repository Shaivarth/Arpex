from arpex.alerts import (
    AlertLevel,
    AlertManager
)


def test_alert_manager_creation():

    alerts = AlertManager()

    assert alerts is not None

    assert (
        alerts.total_active_alerts()
        ==
        0
    )


def test_alert_id_generation():

    alerts = AlertManager()

    first = alerts._generate_alert_id()

    second = alerts._generate_alert_id()

    assert first == "ALT-000001"

    assert second == "ALT-000002"


def test_alert_history_initially_empty():

    alerts = AlertManager()

    assert (
        alerts.total_alert_history()
        ==
        0
    )


def test_expiry_calculation():

    alerts = AlertManager()

    expiry = (
        alerts._calculate_expiry(
            AlertLevel.CRITICAL
        )
    )

    assert expiry is not None

def test_create_alert():

    alerts = AlertManager()

    alert = alerts.create_alert(
        AlertLevel.CRITICAL,
        "Gateway Spoofing",
        "Gateway spoofing detected"
    )

    assert alert is not None

    assert (
        alert["level"]
        ==
        "CRITICAL"
    )

    assert (
        alerts.total_active_alerts()
        ==
        1
    )


def test_get_active_alerts():

    alerts = AlertManager()

    alerts.create_alert(
        AlertLevel.INFO,
        "Device",
        "New device discovered"
    )

    active = (
        alerts.get_active_alerts()
    )

    assert len(active) == 1


def test_dismiss_alert():

    alerts = AlertManager()

    alert = alerts.create_alert(
        AlertLevel.WARNING,
        "Warning",
        "Test warning"
    )

    result = (
        alerts.dismiss_alert(
            alert["id"]
        )
    )

    assert result is True

    assert (
        alerts.total_active_alerts()
        ==
        0
    )


def test_recent_alerts():

    alerts = AlertManager()

    for i in range(5):

        alerts.create_alert(
            AlertLevel.INFO,
            f"Test {i}",
            "Message"
        )

    recent = (
        alerts.get_recent_alerts()
    )

    assert len(recent) == 5

from datetime import datetime, timedelta

from arpex.alerts import Alert


def test_has_active_alerts():

    alerts = AlertManager()

    assert (
        alerts.has_active_alerts()
        is False
    )

    alerts.create_alert(
        AlertLevel.INFO,
        "Info",
        "Test"
    )

    assert (
        alerts.has_active_alerts()
        is True
    )


def test_cleanup_expired_alerts():

    alerts = AlertManager()

    expired = Alert(
        id="ALT-999999",
        timestamp=datetime.utcnow().isoformat(),
        level="INFO",
        title="Expired",
        message="Expired alert",
        expires_at=(
            datetime.utcnow()
            -
            timedelta(seconds=10)
        ).isoformat()
    )

    alerts.active_alerts.append(
        expired
    )

    removed = (
        alerts.cleanup_expired_alerts()
    )

    assert removed == 1

    assert (
        alerts.total_active_alerts()
        ==
        0
    )

def test_create_alert_from_event():

    alerts = AlertManager()

    alert = (
        alerts.create_alert_from_event(
            "GATEWAY_SPOOFING",
            "Gateway spoofing detected"
        )
    )

    assert alert is not None

    assert (
        alert["level"]
        ==
        "CRITICAL"
    )

    assert (
        alert["title"]
        ==
        "Gateway Spoofing"
    )


def test_unknown_event_type():

    alerts = AlertManager()

    alert = (
        alerts.create_alert_from_event(
            "UNKNOWN_EVENT",
            "Message"
        )
    )

    assert alert is None

def test_get_latest_alert():

    alerts = AlertManager()

    alerts.create_alert(
        AlertLevel.INFO,
        "First",
        "First Alert"
    )

    alerts.create_alert(
        AlertLevel.CRITICAL,
        "Second",
        "Second Alert"
    )

    latest = (
        alerts.get_latest_alert()
    )

    assert latest is not None

    assert (
        latest["title"]
        ==
        "Second"
    )


def test_alert_counts():

    alerts = AlertManager()

    alerts.create_alert(
        AlertLevel.INFO,
        "Test",
        "Message"
    )

    assert (
        alerts.active_alert_count()
        ==
        1
    )

    assert (
        alerts.history_alert_count()
        ==
        1
    )