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
PICKLE_FILE = "rules.pkl"
WORDLIST_PATH = "wordlist.txt"
BOUNDARY = "----WebKitFormBoundaryYBhhLWdibeuMQdJn"
CONTENT_TYPE = f"multipart/form-data; boundary={BOUNDARY}"
load_dotenv()
VT_API_KEY = os.getenv("API_KEY") 

# === Match Packet Against Rules ===
def load_rules(filename: str):
    with open(filename, "rb") as f:
        rules = pickle.load(f)
    return rules

def classify_packet(pkt: dict, rules: dict):
    """
    Modified to accept YOUR example packet format:
    {
      "timestamp", "action", "protocol": "HTTP/1.1", 
      "src_ip", "src_port", "direction", "dst_ip", "dst_port", 
      "method", "uri", "status"
    }
    Returns list of (sid, type_str) or [0, ""] if no match
    """

    def match_field(rule_val, pkt_val):
        if rule_val == "any":
            return True
        return str(rule_val) == str(pkt_val)

    def packet_matches_rule(pkt_inner: dict, rule: dict) -> bool:
        # Handle your protocol format (HTTP/1.1 -> treat as HTTP)
        proto = pkt_inner.get("protocol", "").lower()
        if "http" not in proto:
            return False

        # Match rule protocol (tcp/http/etc)
        if rule["protocol"].lower() not in {"tcp", "http", "udp"}:
            return False

        # Use YOUR field names: src_ip, dst_ip, src_port, dst_port
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

        # HTTP method
        http_method = opts.get("http_method")
        if http_method:
            methods = http_method if isinstance(http_method, list) else [http_method]
            methods_clean = [m.strip('"').upper() for m in methods]
            if pkt_inner.get("method", "").upper() not in methods_clean:
                return False

        # URI patterns (http_uri / uricontent as substring)
        uri_opts = []
        for key in ("http_uri", "uricontent"):
            if key in opts:
                val = opts[key]
                if isinstance(val, list):
                    uri_opts.extend(val)
                else:
                    uri_opts.append(val)

        uri = pkt_inner.get("uri", "")
        for pattern in uri_opts:
            pat = pattern.strip('"')
            if pat not in uri:
                return False

        # HTTP status code
        stat_opt = opts.get("http_stat_code")
        if stat_opt is not None:
            codes = stat_opt if isinstance(stat_opt, list) else [stat_opt]
            codes_clean = {int(str(c).strip('"')) for c in codes}
            try:
                pkt_status = int(str(pkt_inner.get("status", 0)).strip('"'))
            except (TypeError, ValueError):
                return False
            if pkt_status not in codes_clean:
                return False

        return True

    # Main matching logic
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

    # Return [0, ""] if no matches
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

# def extract_creds(form_raw):
#     """WORKS 100% with your data."""
#     u_match = re.search(r'name=\\\\x22username\\\\x22\\\\x0D\\\\x0A\\\\x0D\\\\x0A([^\\\\x0D\\\\x0A]+)', form_raw)
#     p_match = re.search(r'name=\\\\x22password\\\\x22\\\\x0D\\\\x0A\\\\x0D\\\\x0A([^\\\\x0D\\\\x0A]+)', form_raw)
    
#     return u_match.group(1) if u_match else None, p_match.group(1) if p_match else None

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

# def main():

#     option = input("Test Function:")

#     match option:
#         case "1":
#             rules = load_rules(PICKLE_FILE)
#             packet = {"timestamp": "03/Feb/2026:23:00:04 +0800", "action": "log", "protocol": "HTTP/1.1", "src_ip": "192.168.246.1", "src_port": "58970", "direction": "->", "dst_ip": "192.168.246.139", "dst_port": "80", "method": "POST", "uri": "/upload", "status": "200"}
#             matches = classify_packet(packet, rules)
#             print(matches)

#         case "2":
#             hash_to_check = "c5c974b3315602ffaab9066aeaac3a55510db469b483cb85f6c591e948d16cfe"
#             result = check_virustotal_sha256(hash_to_check)
#             print(result)

#         case "3":
#             ENTRY = {
#                 "timestamp": "03/Feb/2026:23:00:04 +0800",
#                 "Form": "------WebKitFormBoundaryYBhhLWdibeuMQdJn\\x0D\\x0AContent-Disposition: form-data; name=\\x22username\\x22\\x0D\\x0A\\x0D\\x0Aadmin\\x0D\\x0A------WebKitFormBoundaryYBhhLWdibeuMQdJn\\x0D\\x0AContent-Disposition: form-data; name=\\x22password\\x22\\x0D\\x0A\\x0D\\x0AVImo8-@d\\x0D\\x0A------WebKitFormBoundaryYBhhLWdibeuMQdJn\\x0D\\x0AContent-Disposition: form-data; name=\\x22uploaded_file\\x22; filename=\\x2267.txt\\x22\\x0D\\x0AContent-Type: text/plain\\x0D\\x0A\\x0D\\x0A67\\x0D\\x0A\\x5C67\\x0D\\x0ASamuel\\x0D\\x0Abenson\\x0D\\x0Ateck seng\\x0D\\x0A\\x0D\\x0A67\\x5Cn\\x5C67\\x5Cn\\x0D\\x0A------WebKitFormBoundaryYBhhLWdibeuMQdJn--\\x0D\\x0A"}
#             wordlist = load_wordlist(WORDLIST_PATH)
#             username, password = extract_creds(repr(ENTRY.get("Form", "")))
#             result = check_creds(username, password, wordlist)
#             timestamp = {"timestamp": ENTRY.get("timestamp")}
#             final_result = timestamp | result
#             print(final_result)

def match(packet, form):
    """
    Main function called from app.py
    packet_raw: raw log line (string)
    sha256_hash: file hash string
    """

    results = {}

    # Load rules
    rules = load_rules(PICKLE_FILE)

    # Rule classification
    rule_matches = classify_packet(packet, rules)
    results["rule_matches"] = rule_matches

    # Rainbow table check
    username = form.get("username")
    password = form.get("password")
    wordlist = load_wordlist(WORDLIST_PATH)
    cred_result = check_creds(username, password, wordlist)
    results["credential_analysis"] = cred_result

    # VirusTotal check
    sha256_hash = form.get("SHA256")
    if sha256_hash:
        vt_result = check_virustotal_sha256(sha256_hash)
        results["virustotal"] = vt_result
    
    return results
    
if __name__ == "__main__":
    print("Run via app.py instead.")
