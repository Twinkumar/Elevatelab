import argparse
import itertools
import math
import os
from datetime import datetime

try:
    from zxcvbn import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False


def entropy(password: str) -> float:
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in '!@#$%^&*()_+-=[]{}|;:\'\",.<>/?' for c in password): charset += 32
    if charset == 0:
        return 0
    return round(math.log2(charset ** len(password)), 2)

def analyze_password(password: str):
    print("\n--- Password Analysis ---")
    if ZXCVBN_AVAILABLE:
        res = zxcvbn(password)
        print(f"zxcvbn score: {res['score']} / 4")
        print(f"Estimated crack time (offline fast hash): {res['crack_times_display']['offline_fast_hashing_1e10_per_second']}")
        print(f"Feedback: {res['feedback']['suggestions']}")
    else:
        print("zxcvbn not installed; using entropy only.")
    e = entropy(password)
    print(f"Entropy: {e} bits")
    if e < 28:
        print("Strength: Very Weak")
    elif e < 36:
        print("Strength: Weak")
    elif e < 60:
        print("Strength: Reasonable")
    elif e < 128:
        print("Strength: Strong")
    else:
        print("Strength: Very Strong")

LEET_MAP = {
    'a': ['a','@','4'],
    'e': ['e','3'],
    'i': ['i','1','!'],
    'o': ['o','0'],
    's': ['s','$','5'],
    't': ['t','7']
}

def leetspeak_variants(word):
    variants = ['']
    for c in word:
        choices = LEET_MAP.get(c.lower(), [c])
        variants = [p + ch for p in variants for ch in choices]
    return set(variants)

def word_variants(base_words, years=None, leet=False, append_years=False, separators=None):
    if separators is None:
        separators = ['', '_', '-', '.', '@']

    variants = set()
    for w in base_words:
        local = {w, w.lower(), w.title(), w.upper()}
        if leet:
            local |= set().union(*(leetspeak_variants(v) for v in local))
        variants |= local

    results = set()
    for combo_len in range(1, min(3, len(variants))+1):
        for combo in itertools.permutations(list(variants), combo_len):
            for sep in separators:
                combined = sep.join(combo)
                results.add(combined)

    if append_years and years:
        for r in list(results):
            for y in years:
                results.add(f"{r}{y}")
                results.add(f"{y}{r}")

    return results

def generate_wordlist(args):
    base = []
    for val in [args.name, args.pet, args.birth, args.keyword]:
        if val:
            base.append(str(val))

    if not base:
        print("No inputs provided for wordlist generation.")
        return

    years = []
    if args.years:
        try:
            start, end = map(int, args.years.split('-'))
            years = list(range(start, end+1))
        except Exception:
            print("Invalid year range; expected format: 1990-2025")

    print(f"Generating variants... base={base}")
    wl = word_variants(base, years=years if args.append_years else None,
                       leet=args.leet, append_years=args.append_years)

    if args.max_size and len(wl) > args.max_size:
        wl = set(list(wl)[:args.max_size])

    out_path = args.out or 'wordlist.txt'
    with open(out_path, 'w', encoding='utf-8') as f:
        for w in sorted(wl):
            f.write(w + '\n')

    print(f"Generated {len(wl)} words → {out_path}")


def main():
    parser = argparse.ArgumentParser(description='Password Strength Analyzer & Wordlist Generator')
    sub = parser.add_subparsers(dest='cmd', required=True)

    p1 = sub.add_parser('analyze', help='Analyze password strength')
    p1.add_argument('--password', required=True, help='Password to analyze')

    p2 = sub.add_parser('generate', help='Generate custom wordlist')
    p2.add_argument('--name', help='Name input')
    p2.add_argument('--pet', help='Pet name input')
    p2.add_argument('--birth', help='Birth year/date input')
    p2.add_argument('--keyword', help='Keyword or hobby input')
    p2.add_argument('--years', help='Year range (e.g. 1990-2025)')
    p2.add_argument('--leet', action='store_true', help='Apply leetspeak variants')
    p2.add_argument('--append-years', action='store_true', help='Append/prepend years')
    p2.add_argument('--max-size', type=int, default=5000, help='Limit output size')
    p2.add_argument('--out', help='Output filename (.txt)')

    args = parser.parse_args()

    if args.cmd == 'analyze':
        analyze_password(args.password)
    elif args.cmd == 'generate':
        generate_wordlist(args)

if __name__ == '__main__':
    main()
