# Web IDS + OpenAI LLM + Optional File Content Review

This package does **three** things:

1) **ML score** each web event using your trained RandomForest (`rf_web_ids_model.pkl`)  
2) **(Optional)** open and inspect the referenced uploaded file locally (if you have it)  
3) **(Optional)** call the **OpenAI API** to produce a *structured verdict*:
   - malicious / benign / uncertain
   - confidence
   - attack type (sql_injection, file_upload_malware, etc.)
   - recommended action (allow / review / block)

## What “file reading” means here
Your log record usually contains only **filename + SHA256**, not raw bytes.
The AI can only “read file contents” if your server **saved the upload on disk** and you provide either:
- a full file path in the log record (field like `file_path`), OR
- an upload directory via `--upload-dir` so the script can open `<upload-dir>\<filename>`

The code **does not execute** files. It only reads bytes and extracts:
- size + hash + file type (magic bytes)
- entropy (rough “packed/encrypted?” clue)
- small sample of printable strings
- zip member names + a few string samples from small members

## Setup (Windows)

### 1) Put these files in:
`C:\Web Sec Project\ai_ids\`

### 2) Put your trained model in the same folder:
`rf_web_ids_model.pkl`

### 3) Install dependencies
```bat
cd "C:\Web Sec Project\ai_ids"
pip install -r requirements.txt
```

### 4) Set OpenAI API key (recommended as environment var OPENAI_API_KEY)
```bat
setx OPENAI_API_KEY "sk-...."
```
Close terminal and open a new one.

## Test ML-only (no OpenAI calls)
```bat
python run_web_log_ai.py "reverse-proxy-access.sample.log" --pretty --min-tier LOW
```

## Test with LLM enabled
```bat
python run_web_log_ai.py "reverse-proxy-access.sample.log" --llm --pretty --min-tier LOW --llm-cache
```

## Enable file inspection
If your uploads are saved here:
`C:\Web Sec Project\uploads\`

And the files exist there with the same filename as logged:
```bat
python run_web_log_ai.py "reverse-proxy-access.log" --llm --pretty --min-tier LOW --upload-dir "C:\Web Sec Project\uploads"
```

If your log includes an explicit path field:
```json
{"filename":"AryanRAT_March2010.zip","file_path":"C:\\Web Sec Project\\uploads\\AryanRAT_March2010.zip"}
```
(then you don't need --upload-dir)

## Retrain (only if you have the labeled CSV)
Fast:
```bat
python train_model_fast.py
```
Full tuning:
```bat
python trained_model.py
```

## What I added / fixed
- Removed the bogus empty JSON body `{}` when there are no payload fields (reduces false MED noise).
- File inspection module (`file_inspector.py`) with safe limits.
- LLM module uses Responses API and **does not** send temperature (fixes your 400 error).
- Optional SQLite caching of LLM decisions.
