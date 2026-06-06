from dashboard.app import (
    create_app
)


def test_create_app():

    app = create_app()

    assert app is not None


def test_health_endpoint():

    app = create_app()

    client = app.test_client()

    response = client.get(
        "/health"
    )

    assert (
        response.status_code
        ==
        200
    )


def test_stats_endpoint():

    app = create_app()

    client = app.test_client()

    response = client.get(
        "/api/stats"
    )

    assert (
        response.status_code
        ==
        200
    )


def test_devices_endpoint():

    app = create_app()

    client = app.test_client()

    response = client.get(
        "/api/devices"
    )

    assert (
        response.status_code
        ==
        200
    )


def test_attacks_endpoint():

    app = create_app()

    client = app.test_client()

    response = client.get(
        "/api/attacks"
    )

    assert (
        response.status_code
        ==
        200
    )


def test_attackers_endpoint():

    app = create_app()

    client = app.test_client()

    response = client.get(
        "/api/attackers"
    )

    assert (
        response.status_code
        ==
        200
    )


def test_events_endpoint():

    app = create_app()

    client = app.test_client()

    response = client.get(
        "/api/events"
    )

    assert (
        response.status_code
        ==
        200
    )

def test_dashboard_summary():

    app = create_app()

    client = app.test_client()

    response = client.get(
        "/api/dashboard"
    )

    assert (
        response.status_code
        ==
        200
    )

    data = response.get_json()

    assert (
        "device_count"
        in data
    )

    assert (
        "attack_count"
        in data
    )

    assert (
        "recent_attacks"
        in data
    )

    assert (
        "recent_events"
        in data
    )

def test_homepage():

    app = create_app()

    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200


def test_devices_page():

    app = create_app()

    client = app.test_client()

    response = client.get("/devices")

    assert response.status_code == 200


def test_alerts_page():

    app = create_app()

    client = app.test_client()

    response = client.get("/alerts")

    assert response.status_code == 200


def test_evidence_page():

    app = create_app()

    client = app.test_client()

    response = client.get("/evidence")

    assert response.status_code == 200