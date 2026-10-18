"""Read-only demonstration API. No live device capture or host controls."""

from flask import Flask, jsonify

app = Flask(__name__)

SAMPLE = {
    "mode": "demo",
    "synthetic": True,
    "notice": "Synthetic demonstration; no real device or traffic was inspected.",
    "device": "Example smartphone",
    "summary": {
        "connections": 84,
        "destinations": 12,
        "dns_queries": 18,
        "findings": 2,
    },
    "findings": [
        {
            "id": "DEMO-01",
            "severity": "moderate",
            "title": "Unfamiliar network destination",
            "destination": "198.51.100.24",
            "evidence": "Illustrative outbound connection metadata",
            "explanation": "An unknown destination deserves context, not an automatic compromise verdict.",
            "action": "Check which applications were active during the session.",
        },
        {
            "id": "DEMO-02",
            "severity": "low",
            "title": "Unencrypted DNS request",
            "destination": "example.net",
            "evidence": "Illustrative DNS query metadata",
            "explanation": "This domain lookup may be observable to others on the local network.",
            "action": "Review the device's encrypted DNS settings.",
        },
    ],
}


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "mode": "demo", "live_capture": False})


@app.get("/api/report")
def report():
    response = jsonify(SAMPLE)
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
