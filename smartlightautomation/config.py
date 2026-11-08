import os


class Config:
    """Application configuration with environment overrides for deployment."""

    SECRET_KEY = os.getenv("SMARTLIGHT_SECRET_KEY", "change-me-in-production")
    HOST = os.getenv("SMARTLIGHT_HOST", "127.0.0.1")
    PORT = int(os.getenv("SMARTLIGHT_PORT", "5000"))
    DEBUG = os.getenv("SMARTLIGHT_DEBUG", "false").lower() in {"1", "true", "yes", "on"}
    JSON_SORT_KEYS = False