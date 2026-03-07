#match.py
import pickle
import requests
import json
import time
import os
import re
from typing import Dict, Any
from dotenv import load_dotenv

# === Config / Paths ===
PICKLE_FILE = "rule_matching/rules.pkl"
WORDLIST_PATH = "wordlist.txt"
BOUNDARY = "----WebKitFormBoundaryYBhhLWdibeuMQdJn"
CONTENT_TYPE = f"multipart/form-data; boundary={BOUNDARY}"
load_dotenv()
VT_API_KEY = os.getenv("API_KEY")

# === SQL PATTERNS ===
SQLI_PATTERNS = [
    r"(\bor\b|\band\b)\s+\d=\d",           # OR 1=1, AND 1=1
    r"(\bor\b|\band\b)\s+'1'='1'",        # OR '1'='1'
    r"['\"]\s*or\s*['\"]\w+['\"]=['\"]\w+['\"]",  # ' or 'a'='a
    r"(--|#)",                            # SQL comment
    r"/\*.*\*/",                          # /* ... */
    r"\bunion\b\s+\bselect\b",            # UNION SELECT
    r"\bselect\b.+\bfrom\b",              # SELECT ... FROM
    r"\binsert\b.+\binto\b",              # INSERT INTO
    r"\bupdate\b.+\bset\b",               # UPDATE ... SET
    r"\bdelete\b.+\bfrom\b",              # DELETE FROM
    r"\bdrop\b\s+\btable\b",              # DROP TABLE
    r"(?i)\bor\b\s+1=1",             # OR 1=1
    r"(?i)\band\b\s+1=1",            # AND 1=1
    r"(?i)\bor\b\s+'1'='1'",         # OR '1'='1'
    r"(?i)\band\b\s+'1'='1'",        # AND '1'='1'
    r"(?i)'\s*or\s*'1'='1",          # ' OR '1'='1
    r"(?i)\"\s*or\s*\"1\"=\"1",      # " OR "1"="1
    r"(?i)\bunion\b\s+\bselect\b",   # UNION SELECT
    r"(?i)(--|#)",                   # SQL comments
    r"/\*.*\*/",
]
SQLI_REGEXES = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in SQLI_PATTERNS]

SQL_STATEMENT_REGEX = re.compile(
    r"""
    \b
    (select|insert|update|delete|replace|truncate|drop|alter|create)
    \b
    [\s\*]+
    .{0,200}?                        # some columns / expressions
    \b
    (from|into|table|database)
    \b
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

# === XSS Patterns ===
# Common XSS markers: tags, handlers, JS URLs, etc. [web:32][web:38]
XSS_PATTERNS = [
    r"<\s*script\b",                     # <script
    r"<\s*img\b[^>]*\bon\w+\s*=",        # <img ... onload= / onclick= ...
    r"<\s*iframe\b",                     # <iframe
    r"<\s*svg\b[^>]*\bon\w+\s*=",        # <svg onload=...
    r"javascript\s*:",                   # javascript: URI
    r"data\s*:\s*text/html",             # data:text/html,
    r"on\w+\s*=",                        # any inline event handler: onclick=
    r"document\s*\.",                    # document.cookie, document.location
    r"window\s*\.",                      # window.location
    r"alert\s*\(",                       # alert(
    r"prompt\s*\(",                      # prompt(
    r"confirm\s*\(",                     # confirm(
]

XSS_REGEXES = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in XSS_PATTERNS]

# === Match Packet Against Rules ===
def load_rules(filename: str):
    with open(filename, "rb") as f:
        rules = pickle.load(f)
    return rules

def classify_packet(pkt: dict, rules: dict):
    """
    Fixed to handle Snort‑style rules with booleans and raw content.
    """

    def match_field(rule_val, pkt_val):
        if rule_val in ("any", "$EXTERNAL_NET", "$HOME_NET"):
            return True
        return str(rule_val) == str(pkt_val)

    def packet_matches_rule(pkt_inner: dict, rule: dict) -> bool:
        proto = pkt_inner.get("protocol", "").lower()
        if "http" not in proto:
            return False

        if rule.get("protocol", "").lower() not in {"tcp", "http", "udp"}:
            return False

        # 5‑tuple
        if not match_field(rule["src_ip"], pkt_inner["src_ip"]):
            return False
        if not match_field(rule["dst_ip"], pkt_inner["dst_ip"]):
            return False
        if not match_field(rule["src_port"], pkt_inner["src_port"]):
            return False
        if not match_field(rule["dst_port"], pkt_inner["dst_port"]):
            return False

        if rule.get("direction") and rule["direction"] != pkt_inner.get("direction", "->"):
            return False

        opts = rule.get("options", {})

        # HTTP method - FIXED: skip if boolean, safe string conversion
        http_method = opts.get("http_method")
        if http_method:
            methods = http_method if isinstance(http_method, list) else [http_method]
            methods_clean = []
            for m in methods:
                if isinstance(m, str):
                    methods_clean.append(m.strip('"').upper())
                elif isinstance(m, bool):  # skip True/False flags
                    continue
            if methods_clean and pkt_inner.get("method", "").upper() not in methods_clean:
                return False

        # URI patterns - include content fallback
        uri_opts = []
        for key in ("http_uri", "uricontent"):
            if key in opts:
                val = opts[key]
                if isinstance(val, list):
                    uri_opts.extend(val)
                else:
                    uri_opts.append(val)

        if not uri_opts and "content" in opts:
            content_val = opts["content"]
            if isinstance(content_val, list):
                uri_opts.extend(content_val)
            else:
                uri_opts.append(content_val)

        uri = pkt_inner.get("uri", "")
        for pattern in uri_opts:
            if not isinstance(pattern, str):
                continue
            # Extract first token from Snort content like "/viewsource/template.html?,fast_pattern,nocase"
            token = pattern.split(",", 1)[0].strip().strip('"')
            if token and token not in uri:
                return False

        # HTTP status code - FIXED: safe int conversion
        stat_opt = opts.get("http_stat_code")
        if stat_opt is not None:
            codes = stat_opt if isinstance(stat_opt, list) else [stat_opt]
            codes_clean = set()
            for c in codes:
                if isinstance(c, (int, str)):
                    try:
                        codes_clean.add(int(str(c).strip('"').strip()))
                    except (ValueError, TypeError):
                        pass
            try:
                pkt_status = int(str(pkt_inner.get("status", 0)).strip('"').strip())
            except (ValueError, TypeError):
                return False
            if codes_clean and pkt_status not in codes_clean:
                return False

        return True

    matches = []
    for sid, rule in rules.items():
        if packet_matches_rule(pkt, rule):
            opts = rule.get("options", {})
            msg = opts.get("msg", "Unknown web attack")
            classtype = opts.get("classtype", "unknown")
            if isinstance(msg, str):
                msg = msg.strip('"')
            type_str = f"{msg} ({classtype})"
            matches.append((sid, type_str))

    if not matches:
        return [0, ""]
    return matches


# === Hash check using VirusTotal ===
def check_virustotal_sha256(sha256_hash: str):
    """
    Simple VirusTotal checker with clear verdict.
    Returns: {'verdict': 'MALICIOUS'|'CLEAN'|'UNKNOWN', 'detections': X}
    """
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY,
    }
    
    try:
        r = requests.get(url, headers=headers)
        
        if r.status_code == 404:
            return {'verdict': 'UNKNOWN', 'message': 'file not in database', 'detections': 0}
        
        if r.status_code != 200:
            return {'verdict': 'ERROR', 'message': f'HTTP {r.status_code}', 'detections': 0}
        
        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats["malicious"]
        total = sum(stats.values())
        
        # Simple threshold: >5 detections = MALICIOUS (industry standard)
        if malicious > 5:
            verdict = 'MALICIOUS'
        elif malicious > 0:
            verdict = 'SUSPICIOUS' 
        else:
            verdict = 'CLEAN'
            
        return {
            'verdict': verdict,
            'detections': malicious,
            'total_engines': total,
            'ratio': f"{malicious}/{total}",
            'harmless': stats["harmless"],
            'undetected': stats["undetected"]
        }
        
    except Exception as e:
        return {'verdict': 'ERROR', 'message': str(e), 'detections': 0}

# === Check Form Fields Against Word List ===
def load_wordlist(path):
    wl = set()
    try:
        with open(path, "r") as f:
            wl = {line.strip().lower() for line in f if line.strip()}
    except:
        pass
    return wl

def extract_creds(form_raw):
    """WORKS 100% with your data."""
    u_match = re.search(r'name=\\\\x22username\\\\x22\\\\x0D\\\\x0A\\\\x0D\\\\x0A([^\\\\x0D\\\\x0A]+)', form_raw)
    p_match = re.search(r'name=\\\\x22password\\\\x22\\\\x0D\\\\x0A\\\\x0D\\\\x0A([^\\\\x0D\\\\x0A]+)', form_raw)
    
    return u_match.group(1) if u_match else None, p_match.group(1) if p_match else None

def check_creds(username, password, wordlist):
    username_weak = username and username.lower() in wordlist
    password_weak = password and password.lower() in wordlist
    result = {
            "username": username,
            "password": password, 
            "username_hit": username_weak,
            "password_hit": password_weak,
            "risky": username_weak or password_weak
        }
    
    return result

def check_sql_injection(field_value:str):
    """"
    Return True if the string contains obvious SQL injection patterns.
    Very simple heuristic, not a full WAF. [web:34][web:38]
    """
    if not field_value:
        return False
    
    # Quick reject: very short, alnum only → usually safe
    if len(field_value) < 3 and field_value.isalnum():
        return False
    
    #Search for Injection
    for rx in SQLI_REGEXES:
        if rx.search(field_value):
            return True
    
    #Search for SQL Statements
    if bool(SQL_STATEMENT_REGEX.search(field_value)):
        return True
        
    return False
    
def check_xss(field_value:str):
    """
    Heuristic XSS detector for a single field value.
    Flags obvious payloads like:
      <script>alert(1)</script>
      <img src=x onerror=alert(1)>
      javascript:alert(1)
    """
    if not field_value:
        return False
    
    # Quick reject: short, alnum only → usually safe
    if len(field_value) < 4 and field_value.isalnum():
        return False
    
    for rx in XSS_REGEXES:
        if rx.search(field_value):
            return True
    return False


def match(log):
    """
    Main detection engine.
    Accepts a structured log dictionary.
    Returns structured detection results.
    """
    log = json.loads(log)
    
    # Check if it's a POST request
    is_post = log.get("method") == "POST"
    
    if is_post:
        # Full result structure for POST requests
        result = {
            "timestamp": log.get("timestamp"),
            "network_matches": [],
            "virustotal_file_check": {},
            "credential_check": {},
            "sql_injection": False,
            "xss": False
        }
    else:
        # Minimal result structure for GET requests
        result = {
            "timestamp": log.get("timestamp"),
            "network_matches": [],
        }

    # === Rule-based Network Matching (always do this for all requests) ===
    try:
        network_matches = classify_packet(log, load_rules(PICKLE_FILE))
        result["network_matches"] = network_matches
    except Exception as e:
        result["network_matches"] = {"error": str(e)}

    # Only perform deep analysis for POST requests
    if is_post:
        # === VirusTotal SHA256 Check ===
        sha256_hash = log.get("SHA256")
        if sha256_hash:
            vt_result = check_virustotal_sha256(sha256_hash)
            result["virustotal_file_check"] = vt_result

        # === Weak Credential Check ===
        username = log.get("username")
        password = log.get("password")

        if username or password:
            cred_result = check_creds(username, password, WORDLIST_PATH)
            result["credential_check"] = cred_result

        # === SQL Injection Check ===
        if username:
            result["sql_injection"] = check_sql_injection(username)

        # === XSS Check ===
        if username:
            result["xss"] = check_xss(username)

        # Determine result status for POST requests
        # Safely check if credential_check has "risky" key
        cred_risky = False
        if result["credential_check"]:
            cred_risky = result["credential_check"].get("risky", False)
        
        # Safely check virustotal verdict
        vt_suspicious = False
        vt_unknown = False
        if result["virustotal_file_check"]:
            verdict = result["virustotal_file_check"].get("verdict", "")
            message = result["virustotal_file_check"].get("message", "")
            vt_suspicious = verdict in ["SUSPICIOUS", "MALICIOUS"]
            vt_unknown = verdict == "UNKNOWN" or "file not in database" in message

        if result["xss"] or result["sql_injection"] or cred_risky or vt_suspicious:
            return result, None
        elif vt_unknown:
            return result, "unknown"
        else:
            return False
    else:
        # For GET requests, just return the network matches result
        # You can define what constitutes a "hit" for GET requests here
        # For now, let's assume any network match is considered suspicious
        if (result["network_matches"] and len(result["network_matches"]) > 0) and (result["network_matches"][0] and result["network_matches"][1]):
            return result, None
        else:
            return False