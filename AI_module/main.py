# ============================================
# main.py
# Simple interactive tester for your model.
# ============================================
from inference import score_request, get_policy

MAX_PASTE_LINES = 2000

pol = get_policy()

print("\n============================================")
print("INTERACTIVE MODE: Paste an HTTP request to score it.")
print(" - End input with a single line containing: END")
print(" - Type: quit   to exit")
print("============================================\n")
print(f"Model: {pol['model_path']}")
print(f"Cutoffs: MED={pol['thr_med']*100:.0f}  HIGH={pol['thr_high']*100:.0f}\n")

while True:
    first = input("Paste HTTP request now (or type 'quit'): ").strip()
    if first.lower() == "quit":
        break

    lines = [first]
    for _ in range(MAX_PASTE_LINES):
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)

    raw_http = "\n".join(lines).strip()
    if not raw_http:
        print("[!] Empty input. Try again.\n")
        continue

    out = score_request(raw_http)

    print("\n----- RESULT -----")
    print(f"Tier: {out['tier']}  |  Action: {out['action']}")
    print(f"Attack Probability: {out['prob_attack']:.4f}  |  Benign Probability: {out['prob_benign']:.4f}")
    print(f"Risk Score: {out['risk_score']:.2f} / 100")

    p = out["parsed"]
    print("\nParsed:")
    print(f"  Method: {p['method']}")
    print(f"  URL:    {p['url']}")
    if p["host"]:
        print(f"  Host:   {p['host']}")
    if p["user_agent"]:
        ua = p["user_agent"]
        print(f"  UA:     {ua[:80]}{'...' if len(ua) > 80 else ''}")

    print("\nSignals (quick view):")
    for k, v in out["signals"].items():
        print(f"  {k}: {v}")

    print("\nTip: If it's MED, feed raw_http + these signals into your LLM for reasoning.\n")
