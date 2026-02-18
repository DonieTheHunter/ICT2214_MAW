# read_rules.py
import pickle

PICKLE_FILE = "rules.pkl"

def load_rules(filename: str):
    with open(filename, "rb") as f:
        rules = pickle.load(f)
    return rules

def main():
    rules = load_rules(PICKLE_FILE)
    print(f"Loaded {len(rules)} rules")
    # Example: iterate and print first few
    for i, (sid, rule) in enumerate(rules.items()):
        print(sid, "->", rule)
        if i >= 4:  # stop after 5 rules
            break

if __name__ == "__main__":
    main()
