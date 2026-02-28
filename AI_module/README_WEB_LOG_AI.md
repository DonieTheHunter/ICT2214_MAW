# Web Log AI Processing + Optional OpenAI LLM Verdict

Your reverse proxy log is **JSON-lines**. Uploads may appear as two lines:

1) **packet line**: `timestamp/method/uri/status/ips/ports...`
2) **form line**: `username/password/filename/SHA256...` (no `method/uri`)

The ML model expects **one record per event**, so we merge those lines before scoring.

This folder contains:
- ✅ Local ML scoring (your `rf_web_ids_model.pkl`)
- ✅ Short `suspicion` label (upload/sql/xss/etc.)
- ✅ Optional OpenAI LLM verdict (malicious / benign / uncertain) with short evidence

---

## 1) Folder layout (Windows)

Put these files in the **same folder** (example: `C:\Web Sec Project\ai_ids\`):

- `features.py`
- `inference.py`
- `rf_web_ids_model.pkl`   ← your trained bundle
- `log_ai.py`
- `merge_web_log.py`
- `run_web_log_ai.py`
- `run_log_ai.py`
- `llm_judge.py`
- `requirements.txt`

---

## 2) Install deps

```bat
cd "C:\Web Sec Project\ai_ids"
pip install -r requirements.txt
```

---

## 3) Test on your reverse-proxy log file (no LLM)

### Option A: Score directly (recommended)

```bat
cd "C:\Web Sec Project\ai_ids"
python run_web_log_ai.py "C:\path\to\reverse-proxy-access.log" --pretty --min-tier LOW
```

- `--min-tier LOW` prints all (LOW/MED/HIGH)
- default prints only MED/HIGH

### Option B: Convert to merged JSONL first

```bat
cd "C:\Web Sec Project\ai_ids"
python merge_web_log.py "C:\path\to\reverse-proxy-access.log" merged.jsonl
python run_log_ai.py merged.jsonl --pretty --min-tier LOW
```

---

## 4) Enable OpenAI LLM verdict (optional)

### 4.1 Set your API key (Windows)

In cmd:

```bat
setx OPENAI_API_KEY "YOUR_KEY_HERE"
```

Close that cmd window and open a **new** one (setx applies to new terminals).

### 4.2 Run with LLM enabled

```bat
cd "C:\Web Sec Project\ai_ids"
python run_web_log_ai.py "C:\path\to\reverse-proxy-access.log" --llm --pretty --min-tier LOW
```

LLM cost-control knobs:
- NOTE: file upload-ish records (filename/SHA256 or /upload) will call the LLM even if your tier is LOW, because the LLM can reason about filenames better than a numeric feature model.

- Only call LLM for HIGH:
  ```bat
  python run_web_log_ai.py "C:\path\to\reverse-proxy-access.log" --llm --llm-min-tier HIGH
  ```
- Choose a model:
  ```bat
  python run_web_log_ai.py "C:\path\to\reverse-proxy-access.log" --llm --llm-model gpt-5-mini
  ```

### 4.3 What the LLM returns

When enabled, output JSON will include:
- `llm.available` (true/false)
- `llm.result.verdict` = `malicious | benign | uncertain`
- `llm.result.attack_type` = file_upload_malware / sql_injection / xss / etc.
- `llm.result.evidence` = short list of why
- `final_verdict` / `is_malicious` = combined final decision

### 4.4 Privacy + safety notes (already handled)

`llm_judge.py` REDACTS by default:
- password never sent (only `password_present` + length + “looks like sha256”)
- username is hashed
- IP last octet is masked
- request body (if present) is truncated

It also uses a small cache:
- `llm_cache.sqlite3`
So duplicate events don’t keep burning tokens.

---

## 5) Live tail mode

```bat
python run_web_log_ai.py "C:\path\to\reverse-proxy-access.log" --follow
```

You can combine with `--llm` if you like living dangerously (and paying money).

---

## Output example (one-line)

You’ll see lines like:

`[MED] p=0.632 22/Feb/2026:... 192.168... POST /upload | Upload-ish request; File indicator: ... || LLM=malicious(0.81) file_upload_malware`
