from flask import Flask, jsonify, render_template, request
from waitress import serve
import hashlib
import os
import json
from match import match

app = Flask(__name__)

log_file = "/var/log/nginx/reverse-proxy-access.log"
latest_alert = None
latest_alert_id = 0
result = {}
last_processed_line = 0

@app.route("/logs", methods=["GET"])
def obtain_logs():
    global last_processed_line
    global latest_alert, latest_alert_id

    with open(log_file, "r") as log:
        lines = log.readlines()

    total_lines = len(lines)

    # If no new lines, just return
    if total_lines <= last_processed_line:
        return jsonify(lines[-50:])

    # Process only NEW lines
    new_lines = lines[last_processed_line:]
    last_processed_line = total_lines

    for line in new_lines:
        try:
            data = json.loads(line)

            if "filename" in data and "SHA256" in data:
                file_name = data["filename"]
                hash_value = data["SHA256"]

                result = match("{}", hash_value)

                if result.get("virustotal", {}).get("verdict") == "MALICIOUS":
                    latest_alert = f"MALICIOUS FILE DETECTED\n{file_name}:{hash_value}"
                    latest_alert_id += 1

        except json.JSONDecodeError:
            continue

    return jsonify(lines[-50:])


# def alert():
#     global result, latest_alert, latest_alert_id, hash_value
#     if result.get("virustotal", {}).get("verdict") == "MALICIOUS":
#         latest_alert = f"MALICIOUS FILE DETECTED\n{file_name}:{hash_value}"
#         latest_alert_id += 1
#     result = {}

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.get("/alert")
def get_alert():
    return jsonify(alert=latest_alert, alert_id=latest_alert_id)

@app.route("/uploads_test", methods=["POST"])
def upload():
    hash_for_file = []
    for file in request.files.values():        
        path = os.path.join("uploads", file.filename)
        file.save(path)
        hash_func = hashlib.new("sha256")
        with open(path, "rb") as reading_hash:
            while chunk:=reading_hash.read(8192):
                hash_func.update(chunk)
        hash_for_file = hash_func.hexdigest()
        event = {"filename": file.filename, "SHA256": hash_for_file}
    with open(log_file, 'a') as log:
        log.write(json.dumps(event)+"\n")
    return "Upload OK", 200

if __name__ == "__main__":
    print("Starting IDS on port 6767...")
    serve(app, host="0.0.0.0", port=6767, threads=2)