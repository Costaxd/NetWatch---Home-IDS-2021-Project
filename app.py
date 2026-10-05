from flask import Flask, jsonify, render_template, request


def create_app(db):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/api/summary")
    def summary():
        return jsonify(db.summary())

    @app.route("/api/windows")
    def windows():
        return jsonify(db.recent_windows(request.args.get("minutes", 30, type=int)))

    @app.route("/api/alerts")
    def alerts():
        return jsonify(db.alerts(min(request.args.get("limit", 100, type=int), 500)))

    @app.route("/api/devices")
    def devices():
        return jsonify(db.devices())

    return app
