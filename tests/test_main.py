from main import (
    ArpexApplication
)


def test_application_creation():

    app = ArpexApplication()

    assert app is not None

    assert (
        app.is_running()
        is False
    )


def test_manager_defaults():

    app = ArpexApplication()

    assert app.database is None

    assert app.fingerprint is None

    assert app.alerts is None

    assert app.detector is None

def test_initialize_application():

    app = ArpexApplication()

    app.initialize()

    assert app.database is not None

    assert app.fingerprint is not None

    assert app.alerts is not None

    assert app.detector is not None


def test_directory_creation():

    app = ArpexApplication()

    app.create_directories()

    assert True

def test_status_before_init():

    app = ArpexApplication()

    status = app.get_status()

    assert status["running"] is False

    assert status["database"] is False


def test_status_after_init():

    app = ArpexApplication()

    app.initialize()

    status = app.get_status()

    assert status["database"] is True

    assert status["fingerprint"] is True

    assert status["alerts"] is True

    assert status["detector"] is True


def test_graceful_shutdown():

    app = ArpexApplication()

    app.initialize()

    app.graceful_shutdown()

    assert app.is_running() is False

def test_startup_banner():

    app = ArpexApplication()

    app.print_startup_banner()

    assert True