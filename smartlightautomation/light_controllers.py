from threading import RLock
from typing import TypedDict


class LightStatus(TypedDict):
    is_on: bool
    brightness: int
    motion: bool
    mode: str


class LightController:
    """Thread-safe in-memory light controller for development and testing."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._is_on = False
        self._brightness = 70
        self._motion = False
        self._mode = "Simulated"

    def get_status(self) -> LightStatus:
        with self._lock:
            return {
                "is_on": self._is_on,
                "brightness": self._brightness,
                "motion": self._motion,
                "mode": self._mode,
            }

    def turn_on(self) -> LightStatus:
        with self._lock:
            self._is_on = True
            return self.get_status()

    def turn_off(self) -> LightStatus:
        with self._lock:
            self._is_on = False
            return self.get_status()

    def set_brightness(self, brightness: int) -> LightStatus:
        if not 0 <= brightness <= 100:
            raise ValueError("Brightness must be from 0 to 100")

        with self._lock:
            self._brightness = brightness
            return self.get_status()


light = LightController()