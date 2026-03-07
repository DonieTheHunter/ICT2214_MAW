# read_rules.py
import pickle
import sys

PICKLE_FILE = "rules.pkl"

def load_rules(filename: str):
    with open(filename, "rb") as f:
        rules = pickle.load(f)
    return rules

def main():
    rules = load_rules(PICKLE_FILE)
    sid_rule = int(input("SID: "))
    print(f"Loaded {len(rules)} rules")
    # Example: iterate and print first few
    for i, (sid, rule) in enumerate(rules.items()):
        if (sid == sid_rule):
            print(sid, "->", rule)

if __name__ == "__main__":
    main()
