from flask import Flask, jsonify, render_template, request, redirect, url_for, g
from waitress import serve
import hashlib
import os
import json
import ast
import sys
import subprocess
from datetime import datetime
from werkzeug.middleware.proxy_fix import ProxyFix
from rule_matching import match
from cases import insert_case, get_case_by_hash, get_cases, get_open_cases, update_case_status, is_case_open

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

log_file = "log/ids-access.log"
ai_path = os.path.abspath("AI_module/run_web_log_ai_2.py")
latest_case = None
case_id = 0
result = {}
last_processed_line = 0

@app.route("/logs", methods=["GET"])
def obtain_logs():
    global last_processed_line
    global latest_case, case_id, result

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
            log_hash = hashlib.sha256(line.encode()).hexdigest()
            
            #Checks if case exists
            if get_case_by_hash(log_hash):
                continue
            else:
                #Run detection
                result, unknown_or_not = match.match(line)
                if result:
                    if unknown_or_not == "unknown":
                        new_case_id = insert_case(line, log_hash, result)
                        os.makedirs("log/ai_logs", exist_ok=True)
                        ai_result = subprocess.Popen(["python3", ai_path, f'{line}', "--llm", "--pretty", "--llm-cache"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) 
                        with open(f"log/ai_logs/{new_case_id:03d}.log", "w") as file:
                                for l in ai_result.stdout:
                                    file.write(l)
                                    file.flush()
                        ai_result.wait()
                    else: 
                        insert_case(line, log_hash, result)
                
        except json.JSONDecodeError:
            continue

    return jsonify(lines[-50:])

@app.template_filter("from_python_literal")
def from_python_literal_filter(value):
    return ast.literal_eval(value)

@app.route("/cases")
def cases():
    all_cases = get_cases()
    case_dict = {}
    for file in os.scandir("log/ai_logs"):
        with open(f"log/ai_logs/{file.name}", "r") as f:
            content = f.read()
        case_id = os.path.splitext(file.name)[0]
        case_dict[f"{case_id}"] = content
    return render_template("cases.html", cases=all_cases, ai_results=case_dict)
    
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
    cases = get_open_cases()
    if not cases:
        return jsonify({"case_id": None, "alert": None, })
    alerts = []
    for i in cases:
        alerts.append({"case_id": i[0], "alert": f"Case {i[0]} is open"})
    return jsonify({"alerts": alerts})


@app.route("/uploads_test", methods=["POST"])
def upload():
    hash_for_file = ""
    if not os.path.exists("uploads"):
        os.mkdir("uploads")
    for file in request.files.values():        
        path = os.path.join("uploads", file.filename)
        file.save(path)
        hash_func = hashlib.new("sha256")
        with open(path, "rb") as reading_hash:
            while chunk:=reading_hash.read(8192):
                hash_func.update(chunk)
        hash_for_file = hash_func.hexdigest()
    g.log_data = {
        "timestamp": datetime.now().strftime("%d-%b-%Y %H:%M:%S"),
        "action": "log",
        "protocol": request.environ.get("SERVER_PROTOCOL"),
        "user_agent": request.headers.get("User-Agent"),
        "referrer": request.headers.get("Referer"),
        "host": request.headers.get("Host"),
        "content-type": request.headers.get("Content-Type"),
        "src_ip": request.headers.get("X-Real-Ip"),
        "src_port": request.environ.get("REMOTE_PORT"),
        "direction": "->",
        "dst_ip": request.host.split(":")[0],
        "dst_port": request.host.split(":")[1] if ":" in request.host else "443",
        "method": request.method,
        "uri": request.headers.get("X-Original-Uri"),
        "status": "",
        "username": request.form.get("username"),
        "password": hashlib.sha256((request.form.get("password")).encode('utf-8')).hexdigest(),
        "filename": file.filename,
        "SHA256": hash_for_file
    }
    return "Uploaded", 200


@app.after_request
def log_after_request(response):
    if hasattr(g, "log_data"):
        g.log_data["status"] = str(response.status_code)
        if not os.path.exists(log_file):
            os.mkdir(log_file)
        with open(log_file, "a") as file:
            file.write(json.dumps(g.log_data) + "\n")
    return response


if __name__ == "__main__":
    print("Starting IDS on port 6767...")
    serve(app, host="0.0.0.0", port=6767, threads=5)