# rules_store.py
import pickle
import os
from ingest import ingest_rules  # or copy ingest_rules into this file

def load_rules(pickle_file: str) -> dict:
    if not os.path.exists(pickle_file):
        return {}
    with open(pickle_file, "rb") as f:
        return pickle.load(f)

def build_or_load_rules(rules_txt="rules.txt", rules_pkl="rules.pkl") -> dict:
    # Build if missing (or you can always rebuild on startup if you prefer)
    if not os.path.exists(rules_pkl):
        ingest_rules(rules_txt, rules_pkl)
    return load_rules(rules_pkl)
