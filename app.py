from flask import Flask, jsonify, render_template, request, redirect, url_for
from waitress import serve
import hashlib
import os
import json
from match import match
from cases import insert_case, get_case_by_hash, get_cases, update_case_status

app = Flask(__name__)

log_file = "/var/log/nginx/reverse-proxy-access.log"
latest_alert = None
alert_id = 0
result = {}
last_processed_line = 0

@app.route("/logs", methods=["GET"])
def obtain_logs():
    global last_processed_line
    global latest_alert, alert_id, result

    with open(log_file, "r") as log:
        lines = log.readlines()

    total_lines = len(lines)

    # If no new lines, just return
    if total_lines <= last_processed_line:
        return jsonify(lines[-50:])

    # Process only NEW lines
    new_lines = lines[last_processed_line:]
    last_processed_line = total_lines
    form = {}
    packet = {}
    for line in new_lines:
        try:
            data = json.loads(line)

            if "filename" in data and "SHA256" in data:
                form = data

            if "timestamp" in data and "action" in data:
                packet = data
            
            combine = {**packet, **form}
            if "timestamp" in combine and "filename" in combine and combine.get("method") != "GET":
                result = match(packet, form)
                complete_log = json.dumps(combine)
                log_hash = hashlib.sha256(complete_log.encode()).hexdigest()

                #Checks if case exists
                if get_case_by_hash(log_hash):
                    continue
                else:
                    #Run detection
                    result = match(packet, form)
                    verdict = result.get("virustotal", {}).get("verdict")
                    if verdict in ["SUSPICIOUS", "MALICIOUS"]:
                        latest_alert = f"{verdict} FILE DETECTED\n{form.get('filename')}:{form.get('SHA256')}\n{result}"
                        alert_id += 1
                        insert_case(complete_log, log_hash)

        except json.JSONDecodeError:
            continue

    return jsonify(lines[-50:])

@app.route("/cases")
def cases():
    all_cases = get_cases()
    return render_template("cases.html", cases=all_cases)
    
@app.route("/close/<int:case_id>")
def close_case(case_id):
    update_case_status(0, case_id)
    return redirect(url_for("cases"))

@app.route("/open/<int:case_id>")
def open_case(case_id):
    update_case_status(1, case_id)
    return redirect(url_for("cases"))

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.get("/alert")
def get_alert():
    return jsonify(alert=latest_alert, alert_id=alert_id)

@app.route("/uploads_test", methods=["POST"])
def upload():
    hash_for_file = []
    username = None
    password = None

    for file in request.files.values():        
        path = os.path.join("uploads", file.filename)
        file.save(path)
        hash_func = hashlib.new("sha256")
        with open(path, "rb") as reading_hash:
            while chunk:=reading_hash.read(8192):
                hash_func.update(chunk)
        hash_for_file = hash_func.hexdigest()

    for key, value in request.form.items():
        key_lower = key.lower()
        if any(word in key_lower for word in ["user", "email", "login", "id"]):
            username = value
        if any(word in key_lower for word in ["pass", "pwd", "secret"]):
            password = hashlib.sha256(value.encode('utf-8')).hexdigest()
    
    event = {"username": username, "password": password, "filename": file.filename, "SHA256": hash_for_file}
    with open(log_file, 'a') as log:
        log.write(json.dumps(event)+"\n")
    return "Upload OK", 200

if __name__ == "__main__":
    print("Starting IDS on port 6767...")
    serve(app, host="0.0.0.0", port=6767, threads=5)