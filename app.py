from flask import Flask, jsonify, render_template, request, redirect, url_for, g, session, flash
from waitress import serve
from datetime import datetime
from db import fetch_one, execute
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from rule_matching.read_rules import load_rules
from rule_matching.ingest import ingest_rules as run_ingest, load_existing_rules
from rule_matching import match
from cases import insert_case, get_case_by_hash, get_cases, get_open_cases, update_case_status, build_event_fingerprint, get_open_case_by_fingerprint, touch_case_occurrence
from AI_module.label_store import is_safelisted_record, DEFAULT_LABELS_DB
from AI_module.log_ai import score_log_record
from apscheduler.schedulers.background import BackgroundScheduler
import hashlib, os, json, ast, re, math, subprocess, tempfile

app = Flask(__name__)
app.secret_key = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

log_file = "log/ids-access.log"
last_processed_line = 0
ai_path = os.path.abspath("AI_module/run_web_log_ai_2.py")
latest_case = None
case_id = 0
result = {}
log_list = []


#<-------LOGIN LOGIC------->
#input validation

def is_valid_username(value):
    if not value: return False
    return bool(re.match(r'^[a-zA-Z0-9_\-]{3,50}$', value))

def is_valid_email(value):
    if not value or len(value) > 254: return False
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', value))

def is_valid_password(value):
    if not value or len(value) < 8 or len(value) > 128: return False
    return bool(re.search(r'[a-zA-Z]', value)) and bool(re.search(r'[0-9]', value))


# -------------------------
# Auth helpers
# -------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return fetch_one("SELECT id, username, email, role FROM users WHERE id=?", (uid,))


def login_required(view_func):
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    wrapper.__name__ = view_func.__name__
    return wrapper

def admin_required(view_func):
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return view_func(*args, **kwargs)
    wrapper.__name__ = view_func.__name__
    return wrapper

@app.context_processor
def inject_user():
    # Makes `user` available in all templates
    return {"user": current_user()}


# -------------------------
# Routing flow
# -------------------------
@app.route("/", methods=["GET"])
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# -------------------------
# Auth pages
# -------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")

    if not username or not email or not password:
        flash("All fields are required.", "danger")
        return redirect(url_for("register"))

    if password != confirm:
        flash("Passwords do not match.", "danger")
        return redirect(url_for("register"))

    if not is_valid_username(username):
        flash("Username must be 3-50 characters, letters/numbers/underscore/hyphen only.", "danger")
        return redirect(url_for("register"))

    if not is_valid_email(email):
        flash("Invalid email address.", "danger")
        return redirect(url_for("register"))

    if not is_valid_password(password):
        flash("Password must be 8-128 chars with at least one letter and one number.", "danger")
        return redirect(url_for("register"))

    existing = fetch_one(
        "SELECT id FROM users WHERE username=? OR email=?",
        (username, email),
    )
    if existing:
        flash("Username or email already exists.", "danger")
        return redirect(url_for("register"))

    pw_hash = generate_password_hash(password)
    execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'user')",
        (username, email, pw_hash),
    )

    flash("Registered successfully. Please log in.", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        return render_template("login.html")

    username_or_email = request.form.get("username_or_email", "").strip()
    password = request.form.get("password", "")

    user = fetch_one(
        "SELECT id, username, email, password_hash, role FROM users WHERE username=? OR email=?",
        (username_or_email, username_or_email.lower()),
    )

    if not user or not check_password_hash(user["password_hash"], password):
        flash("Invalid credentials.", "danger")
        return redirect(url_for("login"))

    session["user_id"] = user["id"]
    session["role"] = user["role"]
    flash(f"Welcome, {user['username']}!", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


# -------------------------
# Logged-in pages (SB Admin layout)
# -------------------------
@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/viewrules", methods=["GET"])
@admin_required
def view_rules():
    PER_PAGE = 100
    PICKLE_FILE = os.path.join(os.path.dirname(__file__), "rule_matching", "rules.pkl")

    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        page = 1
    if page < 1:
        page = 1

    search = request.args.get("q", "").strip()

    try:
        rules_dict = load_rules(PICKLE_FILE)
    except FileNotFoundError:
        flash("rules.pkl not found in project folder.", "danger")
        return redirect(url_for("dashboard"))
    except Exception as e:
        flash(f"Failed to load rules.pkl: {e}", "danger")
        return redirect(url_for("dashboard"))

    items = sorted(rules_dict.items(), key=lambda x: int(x[0]))

    # Server-side search: filter by SID or raw rule text
    if search:
        search_lower = search.lower()
        items = [
            (sid, rule_obj) for sid, rule_obj in items
            if search_lower in str(sid).lower()
            or search_lower in (rule_obj.get("raw", "") if isinstance(rule_obj, dict) else str(rule_obj)).lower()
        ]

    total = len(items)
    total_pages = max(1, math.ceil(total / PER_PAGE))
    if page > total_pages:
        page = total_pages

    start = (page - 1) * PER_PAGE
    end = start + PER_PAGE
    page_items = items[start:end]

    rows = []
    for sid, rule_obj in page_items:
        if isinstance(rule_obj, dict):
            src_ip = rule_obj.get("src_ip", "")
            src_port = rule_obj.get("src_port", "")
            dst_ip = rule_obj.get("dst_ip", "")
            dst_port = rule_obj.get("dst_port", "")
            rows.append({
                "sid": sid,
                "action": rule_obj.get("action", ""),
                "protocol": rule_obj.get("protocol", ""),
                "src": f"{src_ip} {src_port}".strip(),
                "dst": f"{dst_ip} {dst_port}".strip(),
                "raw": rule_obj.get("raw", ""),
            })
        else:
            rows.append({"sid": sid, "action": "", "protocol": "", "src": "", "dst": "", "raw": str(rule_obj)})

    return render_template(
        "Admin/viewRules.html",
        rows=rows,
        page=page,
        per_page=PER_PAGE,
        total=total,
        total_pages=total_pages,
        start_index=start + 1 if total else 0,
        end_index=min(end, total),
        search=search,
    )


@app.route("/ingestrules", methods=["GET", "POST"])
@admin_required
def ingest_rules():
    PICKLE_FILE = os.path.join(os.path.dirname(__file__), "rule_matching", "rules.pkl")

    if request.method == "POST":
        file = request.files.get("rules_file")

        if not file or not file.filename.endswith(".txt"):
            flash("Please upload a valid .txt rules file.", "danger")
            return redirect(url_for("ingest_rules"))

        # Save upload to a temp file, then ingest
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="wb") as tmp:
            tmp_path = tmp.name
            file.save(tmp_path)

        try:
            before = len(load_existing_rules(PICKLE_FILE))
            run_ingest(tmp_path, PICKLE_FILE)
            after = len(load_existing_rules(PICKLE_FILE))
            added = after - before
            flash(f"Ingestion complete. {added} new rule(s) added. Total rules: {after}.", "success")
        except Exception as e:
            flash(f"Ingestion failed: {e}")
        finally:
            os.unlink(tmp_path)

        return redirect(url_for("ingest_rules"))

    # GET — show current rule count
    try:
        existing = load_existing_rules(PICKLE_FILE)
        rule_count = len(existing)
    except Exception:
        rule_count = 0

    return render_template("Admin/ingestRules.html", rule_count=rule_count)



#<-----LOGGING + ANALYSIS------>
def is_post_200(d: dict) -> bool:
    # status might be int or string; normalize to string for comparison
    return d.get("method") == "POST" and str(d.get("status")) == "200"

def has_required_fields(d: dict, required: list[str]) -> bool:
    # present and truthy (non-empty)
    return all(d.get(k) for k in required)

@app.route("/logs_page", methods=["GET"])
@login_required
def logs_page():
    PER_PAGE = 50

    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        page = 1
    page = max(page, 1)

    search = request.args.get("q", "").strip().lower()

    try:
        with open(log_file, "r") as f:
            raw_lines = f.readlines()
    except FileNotFoundError:
        raw_lines = []

    required_keys = ["user_agent", "referrer", "host", "content-type"]

    parsed = []
    for raw in reversed(raw_lines):  # newest first
        line = raw.strip()
        if not line:
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            # keep unparseable lines if you want them searchable/viewable
            parsed.append({"parsed": None, "raw": line})
            continue

        # Only enforce required fields for POST + 200
        if is_post_200(data) and not has_required_fields(data, required_keys):
            continue

        parsed.append({"parsed": data, "raw": line})

    if search:
        parsed = [p for p in parsed if search in p["raw"].lower()]

    total = len(parsed)
    total_pages = max(1, math.ceil(total / PER_PAGE))
    page = min(page, total_pages)

    start = (page - 1) * PER_PAGE
    end = start + PER_PAGE
    page_items = parsed[start:end]

    return render_template(
        "logs.html",
        logs=page_items,
        page=page,
        total=total,
        total_pages=total_pages,
        start_index=start + 1 if total else 0,
        end_index=min(end, total),
        search=search,
    )

@app.route("/logs_analysis", methods=["GET"])
def obtain_logs():
    global latest_case, case_id, result, log_list, last_processed_line

    try:
        with open(log_file, "r") as log:
            lines = log.readlines()
    except FileNotFoundError:
        return jsonify([])

    total_lines = len(lines)
    if total_lines <= last_processed_line:
        return jsonify(lines[-50:])

    new_lines = lines[last_processed_line:]
    last_processed_line = total_lines

    required_keys = ["user_agent", "referrer", "host", "content-type"]

    for raw in new_lines:
        line = raw.strip()
        if not line:
            continue

        # Parse JSON so we can check method/status/fields
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Only enforce required fields for POST + 200
        if is_post_200(data) and not has_required_fields(data, required_keys):
            continue

        try:
            log_hash = hashlib.sha256(line.encode()).hexdigest()
            if get_case_by_hash(log_hash):
                continue

            #event_fingerprint only contains normalized security-relevant fields.
            event_fingerprint = build_event_fingerprint(data)

            # when an analyst labels a case as safe,
            # AI_module/label_event.py stores BOTH:
            #   1) a training row in labels.sqlite3, and
            #   2) a deterministic safe-rule signature in safe_rules.
            # This check uses the safe-rule path for *immediate* suppression, so the next
            # near-identical log can be skipped even before the next retraining run.
            if is_safelisted_record(data, DEFAULT_LABELS_DB):
                continue

            # If the same suspicious pattern is already open, do not open another case.
            # Instead, bump occurrence_count/last_seen so the analyst can see it repeated.
            open_case = get_open_case_by_fingerprint(event_fingerprint)
            if open_case:
                touch_case_occurrence(open_case[0])
                continue

            # Manual / signature rules still run first.
            match_result = match.match(line)
            if not match_result:
                continue

            result, unknown_or_not = match_result

            if unknown_or_not == "unknown":
                # manual rules decide obvious known patterns fast
                # ML reduces noise for unknown traffic
                # Analyst labels from *either* source still go into labels.sqlite3 and
                # will be seen by retrain_daily.py on the next training run
                try:
                    ai_scored = score_log_record(data)
                except Exception:
                    ai_scored = None

                if ai_scored and ai_scored.get("tier") == "LOW":
                    continue

                new_case_id = insert_case(line, log_hash, result, event_fingerprint=event_fingerprint)
                os.makedirs("log/ai_logs", exist_ok=True)

                try:
                    ai_result = subprocess.Popen(
                        ["python3", ai_path, line, "--llm", "--pretty", "--llm-cache"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True
                    )
                    with open(f"log/ai_logs/{new_case_id:03d}.log", "w") as file:
                        for l in ai_result.stdout:
                            file.write(l)
                            file.flush()
                        ai_result.wait()
                except Exception:
                    if ai_scored is not None:
                        with open(f"log/ai_logs/{new_case_id:03d}.log", "w") as file:
                            file.write(json.dumps(ai_scored, indent=2))
            else:
                insert_case(line, log_hash, result, event_fingerprint=event_fingerprint)

        except Exception:
            continue

    return jsonify(lines[-50:])


@app.template_filter("from_python_literal")
@login_required
def from_python_literal_filter(value):
    return ast.literal_eval(value)

@app.route("/cases")
@login_required
def cases():
    status_filter = request.args.get("status", "").lower()
    all_cases = get_cases()
    if status_filter == "open":
        filtered = [c for c in all_cases if c[22] == 1]
        filter_label = "open"
    elif status_filter == "closed":
        filtered = [c for c in all_cases if c[22] == 0]
        filter_label = "closed"
    else:
        filtered = all_cases
        filter_label = ""

    case_dict = {}
    for file in os.scandir("log/ai_logs"):
        with open(f"log/ai_logs/{file.name}", "r") as f:
            content = f.read()
        case_id = os.path.splitext(file.name)[0]
        case_dict[f"{case_id}"] = content
    return render_template("cases.html", cases=filtered, ai_results=case_dict, filter=filter_label)


@app.route("/close/<int:case_id>")
@login_required
def close_case(case_id):
    update_case_status(0, case_id)
    return redirect(url_for("cases"))

@app.route("/open/<int:case_id>")
@login_required
def open_case(case_id):
    update_case_status(1, case_id)
    return redirect(url_for("cases"))

@app.route("/label/<int:case_id>/<label>")
@admin_required
def label_case(case_id, label):
    try:
        user = current_user()
        analyst_name = user["username"] if user else None

        subprocess.run(
            [
                "python3",
                "AI_module/label_event.py",
                "--case-id", str(case_id),
                "--label", label,
                "--update-cases-db",
                "--analyst", analyst_name or "",
            ],
            check=True
        )
    except Exception as e:
        print(f"Labeling failed: {e}")

    return redirect(url_for("cases"))

def run_training():
    try:
        result = subprocess.run(
            ["python3", "AI_module/retrain_daily.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        with open("log/ai_training.log", "a") as f:
            f.write("\n===== TRAINING RUN =====\n")
            f.write(result.stdout)

        print(f"[+] {datetime.now()} AI training completed")

    except Exception as e:
        print(f"[!] Training failed: {e}")


@app.route("/train_ai_now")
@admin_required
def train_ai_now():
    try:
        result = subprocess.run(
            [
                "python3",
                "AI_module/retrain_daily.py",
                "--base-csv", "merged_web_traffic_features_rich_numeric.csv",
                "--labels-db", "data/labels.sqlite3",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True
        )
        os.makedirs("log", exist_ok=True)
        with open("log/ai_training.log", "a") as f:
            f.write("\n===== TRAINING RUN =====\n")
            f.write(result.stdout)
            f.write("\n")

        flash("AI training completed successfully.", "success")
    except subprocess.CalledProcessError as e:
        os.makedirs("log", exist_ok=True)
        with open("log/ai_training.log", "a") as f:
            f.write("\n===== TRAINING FAILED =====\n")
            f.write(e.stdout or "")
            f.write("\n")

        flash(f"Training failed: {e.stdout or 'See log/ai_training.log'}", "danger")
    except Exception as e:
        flash(f"Training failed: {e}", "danger")
    return redirect(url_for("ingest_rules"))


@app.get("/alert")
@login_required
def get_alert():
    cases = get_open_cases()
    if not cases:
        return jsonify({"case_id": None, "alert": None, })
    alerts = []
    for i in cases:
        alerts.append({"case_id": i[0], "alert": f"ALERT: \nTime: {i[2]}\nMethod: {i[14]}\nClient: {i[9]}:{i[10]}\nUsernmae: {i[17]}"})
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
        "protocol": request.headers.get("X-Server-Protocol"),
        "user_agent": request.headers.get("User-Agent"),
        "referrer": request.headers.get("Referer"),
        "host": request.headers.get("Host"),
        "content-type": request.headers.get("Content-Type"),
        "src_ip": request.headers.get("X-Real-Ip"),
        "src_port": request.headers.get("X-Client-Port"),
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
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        with open(log_file, "a") as file:
            file.write(json.dumps(g.log_data) + "\n")
    return response


if __name__ == "__main__":
    print("Starting IDS on port 6767...")
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=run_training,
        trigger="cron",
        hour=8,
        minute=0
    )
    scheduler.start()
    serve(app, host="0.0.0.0", port=6767, threads=10)