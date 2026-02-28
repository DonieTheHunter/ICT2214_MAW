# cases.py

import sqlite3
import json

conn = sqlite3.connect("cases.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_hash TEXT UNIQUE,
    event_timestamp TEXT,
    action TEXT,
    protocol TEXT,
    user_agent TEXT,
    referrer TEXT,
    host TEXT,
    Content_Type TEXT,
    src_ip TEXT,
    src_port TEXT,
    direction TEXT,
    dst_ip TEXT,
    dst_port TEXT,
    method TEXT,
    uri TEXT,
    http_status TEXT,
    username TEXT,
    password_hash TEXT,
    filename TEXT,
    file_sha256 TEXT,
    status INTEGER DEFAULT 1,
    datetime DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()
conn.close()

def insert_case(log, log_hash):
    conn = sqlite3.connect("cases.db")
    cursor = conn.cursor()
    log = json.loads(log)
    cursor.execute("""
        INSERT INTO cases (
            log_hash, event_timestamp, action, protocol, 
            user_agent, referrer, host, content_type,
            src_ip, src_port, direction,
            dst_ip, dst_port,
            method, uri, http_status,
            username, password_hash,
            filename, file_sha256
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        log_hash,
        log.get("timestamp"),
        log.get("action"),
        log.get("protocol"),
        log.get("user_agent"),
        log.get("referrer"),
        log.get("host"),
        log.get("content_type"),
        log.get("src_ip"),
        log.get("src_port"),
        log.get("direction"),
        log.get("dst_ip"),
        log.get("dst_port"),
        log.get("method"),
        log.get("uri"),
        log.get("status"),
        log.get("username"),
        log.get("password"),
        log.get("filename"),
        log.get("SHA256")
    ))

    conn.commit()
    conn.close()

def get_cases():
    conn = sqlite3.connect("cases.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cases")
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_open_cases():
    conn = sqlite3.connect("cases.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cases WHERE status = 1")
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_case_by_hash(log_hash):
    conn = sqlite3.connect("cases.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, status FROM cases WHERE log_hash = ?", (log_hash,))
    row = cursor.fetchone()
    conn.close()
    return row

def is_case_open(log_hash):
    row = get_case_by_hash(log_hash)
    if row is None:
        return False, None
    case_id, status = row
    return status == 1, case_id


def update_case_status(status, case_id):
    conn = sqlite3.connect("cases.db")
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE cases
        SET status = ?
        WHERE id = ?
    """, (status, case_id))
    conn.commit()
    conn.close()