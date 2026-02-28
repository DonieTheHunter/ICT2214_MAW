AI Log Scoring (MED/HIGH) - Minimal Setup

Put these files next to:
  - inference.py
  - features.py
  - rf_web_ids_model.pkl

Quick test:
  cd C:\Web Sec Project\ai_ids
  python run_log_ai.py example_log.jsonl --pretty

Tail a live log:
  python run_log_ai.py C:\path\to\your_server_log.jsonl --follow

Output:
  [MED] p=0.632 20/Feb/2026:... 192.168... POST /upload | Upload-ish request; File indicator: ...
