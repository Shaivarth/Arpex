from __future__ import annotations

from flask import (
    Flask,
    jsonify,
    request,
    render_template
)
from flask import send_file
from pathlib import Path

from arpex.database import (
    DatabaseManager
)


def create_app() -> Flask:

    app = Flask(__name__)

    db = DatabaseManager()

    db.initialize_database()

    @app.route("/")
    def index():

        devices = db.list_devices()

        attacks = db.list_attacks()

        attackers = db.list_attackers()

        events = db.list_events()

        return render_template(
            "index.html",

            device_count=len(devices),

            attack_count=len(attacks),

            attacker_count=len(attackers),

            event_count=len(events),

            recent_devices=devices[-5:],

            recent_attacks=attacks[-5:],

            recent_events=events[-10:],

            all_devices=devices,
            all_attacks=attacks,
            all_events=events
        )

    @app.route("/health")
    def health():

        return jsonify(
            {
                "healthy": True
            }
        )
    
    @app.route(
        "/download/<attack_id>"
    )
    def download_evidence(
        attack_id
    ):

        attacks = db.list_attacks()

        for attack in attacks:

            if (
                attack["attack_id"]
                ==
                attack_id
            ):

                pcap_file = attack.get(
                    "pcap_file"
                )
                print("[DOWNLOAD]", pcap_file)
                print("[ABSOLUTE]", Path(pcap_file).resolve())
                print("[EXISTS]", Path(pcap_file).exists())
                if (
                    pcap_file
                    and
                    Path(pcap_file).exists()
                ):

                    return send_file(
                        Path(pcap_file).resolve(),
                        as_attachment=True
                    )

        return (
            "Evidence file not found",
            404
        )

    @app.route("/api/stats")
    def stats():

        devices = db.list_devices()

        attacks = db.list_attacks()

        attackers = db.list_attackers()

        events = db.list_events()

        return jsonify(
            {
                "devices": len(devices),
                "attacks": len(attacks),
                "attackers": len(attackers),
                "events": len(events)
            }
        )
    @app.route("/devices")
    def devices_page():

        return render_template(
            "devices.html",
            devices=db.list_devices()
        )
    
    @app.route("/alerts")
    def alerts_page():

        events = db.list_events()

        return render_template(
            "alerts.html",
            events=events[-50:]
        )
    
    @app.route("/evidence")
    def evidence_page():

        attacks = db.list_attacks()

        return render_template(
            "evidence.html",
            attacks=attacks
        )
    
    @app.route("/api/devices")
    def devices():

        return jsonify(
            db.list_devices()
        )


    @app.route("/api/attacks")
    def attacks():

        return jsonify(
            db.list_attacks()
        )


    @app.route("/api/attackers")
    def attackers():

        return jsonify(
            db.list_attackers()
        )


    @app.route("/api/events")
    def events():

        limit = request.args.get(
            "limit",
            default=100,
            type=int
        )

        events = db.list_events()

        return jsonify(
            events[-limit:]
        )
    
    @app.route("/api/dashboard")
    def dashboard_summary():

        devices = db.list_devices()

        attacks = db.list_attacks()

        attackers = db.list_attackers()

        events = db.list_events()

        recent_attacks = attacks[-5:]

        recent_events = events[-10:]

        return jsonify(
            {
                "device_count": len(
                    devices
                ),

                "attack_count": len(
                    attacks
                ),

                "attacker_count": len(
                    attackers
                ),

                "event_count": len(
                    events
                ),

                "recent_attacks":
                    recent_attacks,

                "recent_events":
                    recent_events
            }
        )

    return app

if __name__ == "__main__":

    app = create_app()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )