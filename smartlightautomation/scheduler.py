import logging
from datetime import datetime
from threading import Lock, Timer
from time import time

from .light_controllers import light

logger = logging.getLogger(__name__)


class LightScheduler:
    def __init__(self) -> None:
        self._lock = Lock()
        self._timer: Timer | None = None
        self._token: object | None = None

    def schedule(self, action: str, run_at: datetime) -> None:
        if action not in {"on", "off"}:
            raise ValueError("Action must be 'on' or 'off'")

        delay = max(0.0, run_at.timestamp() - time())
        token = object()
        timer = Timer(delay, self._run, args=(action, token))
        timer.daemon = True

        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._token = token
            self._timer = timer
            timer.start()

    def cancel(self) -> bool:
        with self._lock:
            if self._timer is None:
                return False

            self._timer.cancel()
            self._timer = None
            self._token = None
            return True

    def _run(self, action: str, token: object) -> None:
        with self._lock:
            if self._token is not token:
                return
            self._timer = None
            self._token = None

        try:
            if action == "on":
                light.turn_on()
            else:
                light.turn_off()
        except Exception:
            logger.exception("Scheduled light action failed")


scheduler = LightScheduler()


def schedule_light(action: str, run_at: datetime) -> None:
    scheduler.schedule(action, run_at)