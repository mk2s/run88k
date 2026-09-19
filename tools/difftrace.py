#!/usr/bin/env python3
"""Differential-trace driver: compare run88k's per-instruction trace against the
nono LUNA-88k oracle to find the first divergence.

run88k emits a JSONL trace (see src/difftrace.zig). This tool does not talk to
nono directly (nono is driven via MCP by the agent); instead it:

  * `emit <trace> <index>`  -> prints the nono run_test_case inputs for one
        instruction (code word, preset registers) so the agent can call the
        oracle, then compares by feeding the oracle result back via `check`.
  * `check <trace> <index> <after_json>` -> given the oracle's `after` register
        map (JSON), diffs the general registers r0..r31 against run88k's `post`
        and reports any mismatch.
  * `count <trace>` -> number of traced instructions.
  * `list <trace> <lo> <hi>` -> human-readable disasm-ish dump of a range.

Registers are compared for r0..r31 only (PC/pipeline are not meaningfully
single-step-replayable for delayed branches; a wrong *computed value* is the
signal we want).
"""
import json
import sys


def load(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def cmd_count(path):
    print(len(load(path)))


def cmd_emit(path, idx):
    rows = load(path)
    r = rows[idx]
    # Preset every nonzero pre-register (r1..r31); r0 is always 0.
    regs = {}
    for i in range(1, 32):
        v = r["pre"][i]
        if v != 0:
            regs[f"r{i}"] = v
    out = {
        "index": idx,
        "pc": r["pc"],
        "op": r["op"],
        "code_words": [r["op"]],
        "registers": regs,
    }
    if "maddr" in r:
        out["maddr"] = r["maddr"]
        out["mpre"] = r["mpre"]
        out["mpost"] = r["mpost"]
    print(json.dumps(out))


def cmd_check(path, idx, after_json):
    rows = load(path)
    r = rows[idx]
    after = json.loads(after_json)

    def norm(v):
        if isinstance(v, str):
            return int(v, 16) if v.startswith("0x") else int(v)
        return v & 0xFFFFFFFF

    mism = []
    for i in range(1, 32):
        want = r["post"][i] & 0xFFFFFFFF
        key = f"r{i}"
        if key in after:
            got = norm(after[key]) & 0xFFFFFFFF
            if got != want:
                mism.append((key, want, got))
    if mism:
        print(f"DIVERGENCE at index {idx} pc={r['pc']:#x} op={r['op']:#010x}")
        for k, want, got in mism:
            print(f"  {k}: run88k={want:#x} nono={got:#x}")
    else:
        print(f"OK index {idx} pc={r['pc']:#x} op={r['op']:#010x}")


def cmd_list(path, lo, hi):
    rows = load(path)
    for i in range(lo, min(hi, len(rows))):
        r = rows[i]
        changed = []
        for j in range(32):
            if r["pre"][j] != r["post"][j]:
                changed.append(f"r{j}:{r['pre'][j]:#x}->{r['post'][j]:#x}")
        cf = ""
        if r.get("cf") != r.get("cf2"):
            cf = f" cf:{r['cf']}->{r['cf2']}"
        mem = ""
        if "maddr" in r:
            mem = f" mem[{r['maddr']:#x}]:{r['mpre']:#x}->{r['mpost']:#x}"
        print(f"[{i}] pc={r['pc']:#x} op={r['op']:#010x} {' '.join(changed)}{cf}{mem}")


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "count":
        cmd_count(sys.argv[2])
    elif cmd == "emit":
        cmd_emit(sys.argv[2], int(sys.argv[3]))
    elif cmd == "check":
        cmd_check(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    elif cmd == "list":
        cmd_list(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    else:
        print("unknown command", cmd, file=sys.stderr)
        sys.exit(1)
