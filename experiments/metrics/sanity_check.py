#!/usr/bin/env python3
"""Automated PASS/FAIL sanity check for a running vLLM /v1/completions
endpoint, written BEFORE Phase 9-quater's VM exists and BEFORE any config is
tested against real hardware -- thresholds below are pre-registered and must
NOT be adjusted after seeing results for a given configuration (see
EXPERIMENTS_LOG.md Phase 9-quater). Root problem this addresses: Phase 9-ter's
served model produced degenerate output ("[]([]([]...", "!!!!!!!!",
"httphttphttp...") and this was caught only by eyeballing responses -- this
script makes that judgment automatic and reproducible instead.

Two independent checks, both required for an overall PASS:
1. Anti-degeneration (must hold for ALL prompts): zlib compression ratio of
   the raw completion text. This is a robust generalization of "fraction of
   the most-repeated n-gram" that doesn't depend on picking a repeat-period
   length up front -- compression exploits ANY repeated substring regardless
   of length, so it catches a single token repeated with no whitespace
   ("[]([]([]...") just as well as a multi-word period repeated with spaces
   ("foo bar baz foo bar baz..."), which fixed-window n-gram/word-frequency
   checks were verified (locally, before any VM) to miss in some cases.
   Word-level distinct-ratio/top-word-fraction are still computed and logged
   as supplementary diagnostics but do not gate the verdict.
2. Content correctness (must hold for >= 4 of 5 prompts): each prompt has a
   trivially checkable expected substring. A coherent model should get nearly
   all of these right; a degenerate one gets essentially none.

Usage: sanity_check.py <service-url> [<output-json-path>]
Exit code 0 = PASS, 1 = FAIL, 2 = request/connection error.
"""
import json
import sys
import urllib.request
import zlib
from collections import Counter

# Pre-registered thresholds -- fixed before any real run, not tuned after
# seeing results. COMPRESSION_RATIO_MIN chosen with a wide margin after
# local (zero-cost) testing: synthetic degenerate samples (repeated single
# token, repeated multi-word period, repeated bangs) all compressed to
# 0.10-0.18; coherent English samples compressed to 0.81+. 0.35 sits well
# clear of both clusters.
COMPRESSION_RATIO_MIN = 0.35
CONTENT_PASS_MIN = 4  # out of 5 prompts

PROMPTS = [
    {
        "id": "arithmetic",
        "prompt": "What is 2+2? Answer with just the number.",
        "check": lambda text: "4" in text,
    },
    {
        "id": "counting",
        "prompt": "Count from 1 to 5, separated by commas.",
        "check": lambda text: all(
            text.find(str(n)) != -1 and text.find(str(n)) < text.find(str(n + 1))
            for n in range(1, 5)
        ) if all(str(n) in text for n in range(1, 6)) else False,
    },
    {
        "id": "sky_color",
        "prompt": "What color is the sky on a clear day? Answer in one word.",
        "check": lambda text: "blue" in text.lower(),
    },
    {
        "id": "sequence",
        "prompt": "Complete this sequence: 2, 4, 6, 8,",
        "check": lambda text: "10" in text,
    },
    {
        "id": "capital",
        "prompt": "What is the capital of France? Answer in one word.",
        "check": lambda text: "paris" in text.lower(),
    },
]


def anti_degeneration_metrics(text):
    raw = text.encode()
    if len(raw) == 0:
        # Empty completion is a real failure (model produced nothing).
        return {"compression_ratio": 0.0, "distinct_word_ratio": 0.0,
                "top_word_fraction": 1.0, "pass": False}
    if len(raw) < 20:
        # Too short for zlib's compression ratio to be meaningful in either
        # direction (found empirically: legitimate one-word answers like
        # "Paris." score a spuriously low ratio purely from zlib's fixed
        # header/table overhead on tiny inputs, which would wrongly FAIL a
        # perfectly healthy concise answer). A short, non-empty, non-repeating
        # completion cannot exhibit pathological repetition in the first
        # place -- there isn't room for a repeat pattern to emerge -- so
        # pass this check by construction and let the content check carry
        # correctness for short answers.
        compression_ratio = 1.0
    else:
        compression_ratio = len(zlib.compress(raw, level=9)) / len(raw)
    passed = compression_ratio > COMPRESSION_RATIO_MIN

    words = text.split()
    distinct_ratio = len(set(words)) / len(words) if words else 0.0
    top_fraction = Counter(words).most_common(1)[0][1] / len(words) if words else 1.0

    return {
        "compression_ratio": round(compression_ratio, 4),
        "distinct_word_ratio": round(distinct_ratio, 4),
        "top_word_fraction": round(top_fraction, 4),
        "pass": passed,
    }


def call_completion(url, prompt, timeout=60):
    body = json.dumps({
        "model": "llm-inference-real",
        "prompt": prompt,
        "max_tokens": 40,
        "temperature": 0,
        "seed": 42,
    }).encode()
    req = urllib.request.Request(
        f"{url}/v1/completions", data=body, headers={"Content-Type": "application/json"}
    )
    resp = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
    return resp["choices"][0]["text"]


def main():
    if len(sys.argv) < 2:
        print("usage: sanity_check.py <service-url> [<output-json-path>]", file=sys.stderr)
        sys.exit(2)
    url = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else None

    results = []
    content_pass_count = 0
    all_anti_degeneration_pass = True

    for spec in PROMPTS:
        try:
            text = call_completion(url, spec["prompt"])
        except Exception as e:
            print(f"REQUEST ERROR for prompt '{spec['id']}': {e}", file=sys.stderr)
            sys.exit(2)
        ad = anti_degeneration_metrics(text)
        content_ok = bool(spec["check"](text))
        if content_ok:
            content_pass_count += 1
        if not ad["pass"]:
            all_anti_degeneration_pass = False
        results.append({
            "id": spec["id"],
            "prompt": spec["prompt"],
            "completion": text,
            "anti_degeneration": ad,
            "content_check_pass": content_ok,
        })
        print(f"[{spec['id']}] content_pass={content_ok} "
              f"compression_ratio={ad['compression_ratio']} (min {COMPRESSION_RATIO_MIN}) "
              f"distinct_ratio={ad['distinct_word_ratio']} top_frac={ad['top_word_fraction']} "
              f"raw={text[:80]!r}")

    overall_pass = all_anti_degeneration_pass and content_pass_count >= CONTENT_PASS_MIN
    summary = {
        "service_url": url,
        "thresholds": {
            "compression_ratio_min": COMPRESSION_RATIO_MIN,
            "content_pass_min": CONTENT_PASS_MIN,
        },
        "content_pass_count": content_pass_count,
        "content_pass_total": len(PROMPTS),
        "all_anti_degeneration_pass": all_anti_degeneration_pass,
        "overall_pass": overall_pass,
        "results": results,
    }

    print(f"\n=== VERDICT: {'PASS' if overall_pass else 'FAIL'} "
          f"(content {content_pass_count}/{len(PROMPTS)}, "
          f"anti-degeneration all-pass={all_anti_degeneration_pass}) ===")

    if out_path:
        with open(out_path, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"Full result written to {out_path}")

    sys.exit(0 if overall_pass else 1)


if __name__ == "__main__":
    main()
