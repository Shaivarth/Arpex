from __future__ import annotations
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from collections import deque
from typing import Optional


class AlertLevel(Enum):

    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


ALERT_DURATIONS = {
    AlertLevel.INFO: 3,
    AlertLevel.WARNING: 4,
    AlertLevel.ERROR: 5,
    AlertLevel.CRITICAL: 7
}


@dataclass
class Alert:

    id: str

    timestamp: str

    level: str

    title: str

    message: str

    expires_at: str

    def to_dict(self) -> dict:

        return asdict(self)


class AlertManager:

    def __init__(self):

        self._alert_counter = 0

        self.active_alerts = deque()

        self.alert_history = deque(
            maxlen=1000
        )
        self._lock = threading.RLock()

    def _generate_alert_id(self) -> str:

        self._alert_counter += 1

        return (
            f"ALT-{self._alert_counter:06d}"
        )

    def _calculate_expiry(
        self,
        level: AlertLevel
    ) -> str:

        expires_at = (
            datetime.utcnow()
            +
            timedelta(
                seconds=ALERT_DURATIONS[level]
            )
        )

        return expires_at.isoformat()

    def total_active_alerts(
        self
    ) -> int:

        return len(
            self.active_alerts
        )

    def total_alert_history(
        self
    ) -> int:

        return len(
            self.alert_history
        )

    def clear_alerts(
        self
    ) -> None:

        self.active_alerts.clear()

        self.alert_history.clear()

    def create_alert(
        self,
        level: AlertLevel,
        title: str,
        message: str
    ) -> dict:

        now = datetime.utcnow().isoformat()

        alert = Alert(
            id=self._generate_alert_id(),
            timestamp=now,
            level=level.value,
            title=title,
            message=message,
            expires_at=self._calculate_expiry(
                level
            )
        )

        self.active_alerts.append(
            alert
        )

        self.alert_history.append(
            alert
        )

        return alert.to_dict()


    def dismiss_alert(
        self,
        alert_id: str
    ) -> bool:

        for alert in list(
            self.active_alerts
        ):

            if alert.id == alert_id:

                self.active_alerts.remove(
                    alert
                )

                return True

        return False


    def get_active_alerts(
        self
    ) -> list[dict]:

        return [
            alert.to_dict()
            for alert
            in self.active_alerts
        ]


    def get_recent_alerts(
        self,
        limit: int = 50
    ) -> list[dict]:

        history = list(
            self.alert_history
        )

        return [
            alert.to_dict()
            for alert
            in history[-limit:]
        ]

    def cleanup_expired_alerts(
        self
    ) -> int:
        """
        Remove expired alerts.

        Returns:
            Number of alerts removed.
        """

        now = datetime.utcnow()

        removed = 0

        for alert in list(
            self.active_alerts
        ):

            expires_at = datetime.fromisoformat(
                alert.expires_at
            )

            if expires_at <= now:

                self.active_alerts.remove(
                    alert
                )

                removed += 1

        return removed


    def has_active_alerts(
        self
    ) -> bool:

        return (
            len(self.active_alerts)
            > 0
        )
    
    def create_alert_from_event(
        self,
        event_type: str,
        message: str
    ) -> Optional[dict]:
        """
        Convert event into alert.
        """

        mapping = {
            "NEW_DEVICE": (
                AlertLevel.INFO,
                "New Device"
            ),

            "SPOOFING_ATTEMPT": (
                AlertLevel.WARNING,
                "Spoofing Attempt"
            ),

            "VERIFICATION_FAILED": (
                AlertLevel.WARNING,
                "Verification Failed"
            ),

            "ARP_SPOOFING": (
                AlertLevel.ERROR,
                "ARP Spoofing"
            ),

            "GATEWAY_SPOOFING": (
                AlertLevel.CRITICAL,
                "Gateway Spoofing"
            )
        }

        if event_type not in mapping:
            return None

        level, title = mapping[
            event_type
        ]

        return self.create_alert(
            level=level,
            title=title,
            message=message
        )
    

    def get_latest_alert(
        self
    ) -> Optional[dict]:

        if not self.active_alerts:
            return None

        return (
            self.active_alerts[-1]
            .to_dict()
        )


    def active_alert_count(
        self
    ) -> int:

        return len(
            self.active_alerts
        )


    def history_alert_count(
        self
    ) -> int:

        return len(
            self.alert_history
        )