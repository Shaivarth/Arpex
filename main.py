from __future__ import annotations
from pathlib import Path
from typing import Optional
import time
import signal
from arpex.database import (
    DatabaseManager
)

from arpex.fingerprint import (
    FingerprintManager
)

from arpex.alerts import (
    AlertManager
)

from arpex.detector import (
    Detector
)


class ArpexApplication:

    def __init__(
        self
    ):

        self.database: Optional[
            DatabaseManager
        ] = None

        self.fingerprint: Optional[
            FingerprintManager
        ] = None

        self.alerts: Optional[
            AlertManager
        ] = None

        self.detector: Optional[
            Detector
        ] = None

        self.running = False

    def is_running(
        self
    ) -> bool:

        return self.running

# PART 2
    def create_directories(
        self
    ) -> None:

        Path(
            "captures"
        ).mkdir(
            exist_ok=True
        )

        Path(
            "data"
        ).mkdir(
            exist_ok=True
        )


    def initialize(
        self
    ) -> None:

        self.create_directories()

        self.database = (
            DatabaseManager()
        )

        self.database.initialize_database()

        self.fingerprint = (
            FingerprintManager()
        )

        self.alerts = (
            AlertManager()
        )

        self.detector = (
            Detector(
                database=self.database,
                fingerprint=self.fingerprint
            )
        )

    def start(
        self
    ) -> None:

        if self.running:
            return

        if self.detector is None:
            raise RuntimeError(
                "Application not initialized."
            )

        self.detector.start()

        self.running = True


    def stop(
        self
    ) -> None:

        if not self.running:
            return

        if self.detector:

            self.detector.stop()

        self.running = False


    def graceful_shutdown(
        self
    ) -> None:

        self.stop()


    def get_status(
        self
    ) -> dict:

        return {
            "running": self.running,
            "database": (
                self.database
                is not None
            ),
            "fingerprint": (
                self.fingerprint
                is not None
            ),
            "alerts": (
                self.alerts
                is not None
            ),
            "detector": (
                self.detector
                is not None
            )
        }

    def print_startup_banner(
        self
    ) -> None:

        print()

        print(
            "=" * 50
        )

        print(
            "ARPEX"
        )

        print(
            "Advanced ARP Spoofing "
            "Detection System"
        )

        print(
            "=" * 50
        )

        print()


    def run(
        self
    ) -> None:

        self.print_startup_banner()

        self.initialize()

        self.start()

        print(
            "[ARPEX] Application started."
        )

        try:

            while self.running:

                time.sleep(1)

        except KeyboardInterrupt:

            print()

            print(
                "[ARPEX] Shutdown requested."
            )

            self.graceful_shutdown()

def _signal_handler(
    signum,
    frame
):
    raise KeyboardInterrupt


if __name__ == "__main__":

    signal.signal(
        signal.SIGINT,
        _signal_handler
    )

    signal.signal(
        signal.SIGTERM,
        _signal_handler
    )

    app = ArpexApplication()

    app.run()