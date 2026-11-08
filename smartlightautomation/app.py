import logging
from datetime import datetime
from math import isfinite
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request

try:
    from .config import Config
    from .light_controllers import light
    from .scheduler import schedule_light, scheduler
except ImportError:
    import sys

    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from smartlightautomation.config import Config
    from smartlightautomation.light_controllers import light
    from smartlightautomation.scheduler import schedule_light, scheduler


def create_app() -> Flask:
    base_dir = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        template_folder=str(base_dir / "templates"),
        static_folder=str(base_dir / "static"),
        static_url_path="/static",
    )
    app.config.from_object(Config)
    app.logger.setLevel(logging.INFO)

    @app.get("/")
    def home() -> str:
        return render_template("index.html")

    @app.get("/health")
    def health() -> Any:
        return jsonify(status="ok", service="smartlightautomation")

    @app.get("/api/status")
    def status() -> Any:
        return jsonify(light.get_status())

    @app.post("/api/<action>")
    def control_light(action: str) -> Any:
        if action not in {"on", "off"}:
            return jsonify(error="Action must be 'on' or 'off'"), 400

        result = light.turn_on() if action == "on" else light.turn_off()
        return jsonify(result)

    @app.post("/api/brightness")
    def set_brightness() -> Any:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error="Expected a JSON object"), 400

        brightness = data.get("brightness")
        if isinstance(brightness, bool) or not isinstance(brightness, (int, float)):
            return jsonify(error="Brightness must be an integer from 0 to 100"), 400
        if (
            brightness < 0
            or brightness > 100
            or not isfinite(brightness)
            or brightness % 1 != 0
        ):
            return jsonify(error="Brightness must be an integer from 0 to 100"), 400

        try:
            result = light.set_brightness(int(brightness))
        except ValueError as error:
            return jsonify(error=str(error)), 400

        return jsonify(result)

    @app.post("/api/schedule")
    def create_schedule() -> Any:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error="Expected a JSON object"), 400

        action = data.get("action")
        time_value = data.get("time")
        if not isinstance(action, str) or action not in {"on", "off"}:
            return jsonify(error="Action must be 'on' or 'off'"), 400
        if not isinstance(time_value, str) or not time_value:
            return jsonify(error="A scheduled date and time is required"), 400

        try:
            run_at = datetime.fromisoformat(time_value.replace("Z", "+00:00"))
        except ValueError:
            return jsonify(error="Scheduled time must be a valid ISO date and time"), 400

        now = datetime.now(run_at.tzinfo) if run_at.tzinfo else datetime.now()
        if run_at <= now:
            return jsonify(error="Scheduled time must be in the future"), 400

        schedule_light(action, run_at)
        return jsonify(message=f"Light scheduled to turn {action} at {time_value}")

    @app.post("/api/schedule/cancel")
    def cancel_schedule() -> Any:
        cancelled = scheduler.cancel()
        message = "Schedule cancelled" if cancelled else "There is no active schedule"
        return jsonify(message=message)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=app.config["HOST"],
        port=app.config["PORT"],
        debug=app.config["DEBUG"],
    )
