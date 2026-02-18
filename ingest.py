# ingest.py
import os
import pickle

RULES_FILE = "rules.txt"
PICKLE_FILE = "rules.pkl"

# Ports commonly used for HTTP/HTTPS; extend if needed
HTTP_PORTS = {80, 443, 8080, 8000, 8443}

# HTTP sticky-buffer / options keywords (Snort 2/3 style) [web:52]
HTTP_KEYWORDS = {
    "http_uri",
    "http_raw_uri",
    "http_header",
    "http_raw_header",
    "http_method",
    "http_client_body",
    "http_server_body",
    "http_cookie",
    "http_stat_code",
    "http_stat_msg",
    "http_user_agent",
    "http_host",
    "http_raw_host",
    "http(referer)",
    "service",           # used as service:http in some rules [web:70]
    # feel free to add more http_* options you want to treat as web
}


def parse_rule(line: str) -> dict | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    try:
        header, options_part = line.split("(", 1)
        options_part = options_part.rsplit(")", 1)[0]
    except ValueError:
        return None

    header_tokens = header.split()
    if len(header_tokens) < 7:
        return None

    action = header_tokens[0]
    proto = header_tokens[1]
    src_ip = header_tokens[2]
    src_port = header_tokens[3]
    direction = header_tokens[4]
    dst_ip = header_tokens[5]
    dst_port = header_tokens[6]

    rule_dict = {
        "action": action,
        "protocol": proto,
        "src_ip": src_ip,
        "src_port": src_port,
        "direction": direction,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "options": {},
        "raw": line,  # optional: keep original line
    }

    for opt in options_part.split(";"):
        opt = opt.strip()
        if not opt:
            continue

        if ":" in opt:
            key, value = opt.split(":", 1)
            key = key.strip()
            value = value.strip()
        else:
            key = opt
            value = True

        if key in rule_dict["options"]:
            existing = rule_dict["options"][key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                rule_dict["options"][key] = [existing, value]
        else:
            rule_dict["options"][key] = value

    return rule_dict


def is_web_app_attack_rule(rule: dict) -> bool:
    """
    ONLY accept rules specifically for WEB APPLICATION ATTACKS.
    Protocols: http/tcp/udp + HTTP ports + attack indicators.
    """
    proto = (rule.get("protocol") or "").lower()
    
    # 1. Must be http/tcp/udp protocol
    if proto not in {"http", "tcp", "udp"}:
        return False
    
    # 2. Destination port must be HTTP-related
    dst_port = rule.get("dst_port")
    try:
        dst_port_int = int(str(dst_port))
        if dst_port_int not in HTTP_PORTS:
            return False
    except (TypeError, ValueError):
        return False
    
    opts = rule.get("options", {}) or {}
    
    # 3. Must have web application ATTACK indicators:
    web_attack_indicators = {
        # HTTP-specific options (required)
        "http_uri", "http_raw_uri", "http_method", "http_header", 
        "http_client_body", "http_cookie", "http_stat_code",
        # Attack patterns (content, pcre, etc.)
        "content", "uricontent", "pcre",
    }
    
    # Check for attack indicators OR web attack classtypes
    has_attack_opts = any(k in web_attack_indicators for k in opts.keys())
    
    classtype = opts.get("classtype", "")
    has_attack_classtype = any(term in str(classtype).lower() for term in 
        ["web", "xss", "sql", "injection", "lfi", "rfi", "cmd", "php", "shell", "attempt"])
    
    # 4. Service must be HTTP-related
    service_val = opts.get("service")
    has_http_service = service_val and isinstance(service_val, str) and "http" in service_val.lower()
    
    return (has_attack_opts or has_attack_classtype or has_http_service)



def load_existing_rules(pickle_file: str) -> dict:
    if not os.path.exists(pickle_file):
        return {}
    with open(pickle_file, "rb") as f:
        return pickle.load(f)


def save_rules(rules: dict, pickle_file: str) -> None:
    with open(pickle_file, "wb") as f:
        pickle.dump(rules, f)


def ingest_rules(rules_file: str, pickle_file: str) -> None:
    existing_rules = load_existing_rules(pickle_file)
    existing_sids = set(existing_rules.keys())

    added = 0
    with open(rules_file, "r") as f:
        for idx, line in enumerate(f, start=1):
            parsed = parse_rule(line)
            if not parsed:
                continue

            # ONLY keep WEB APPLICATION ATTACK rules
            if not is_web_app_attack_rule(parsed):  # <-- Changed this line
                continue

            sid = parsed["options"].get("sid", idx)
            try:
                sid = int(sid)
            except (TypeError, ValueError):
                pass

            if sid in existing_sids:
                continue

            existing_rules[sid] = parsed
            existing_sids.add(sid)
            added += 1

    save_rules(existing_rules, pickle_file)
    print(f"[WEB APP ATTACKS] Added {added} new rules. Total: {len(existing_rules)}")



def main():
    ingest_rules(RULES_FILE, PICKLE_FILE)


if __name__ == "__main__":
    main()
